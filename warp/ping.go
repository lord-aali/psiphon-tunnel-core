package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

const handshakeTimeout = 2 * time.Second

// Handshake sends a WireGuard handshake initiation to addr and waits for a
// valid response. Empty presharedKey is treated as 32 zero bytes.
func Handshake(ctx context.Context, addr, privateKey, peerPublicKey, presharedKey string) error {
	staticKeyPair, err := staticKeypair(privateKey)
	if err != nil {
		return err
	}
	peerPub, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil {
		return err
	}
	var psk []byte
	if presharedKey == "" {
		psk = make([]byte, 32)
	} else {
		psk, err = base64.StdEncoding.DecodeString(presharedKey)
		if err != nil {
			return err
		}
	}
	ephemeral, err := ephemeralKeypair()
	if err != nil {
		return err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         staticKeyPair,
		PeerStatic:            peerPub,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          psk,
		PresharedKeyPlacement: 2,
		EphemeralKeypair:      ephemeral,
		Random:                rand.Reader,
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	tai64n := make([]byte, 0, 12)
	tai64n = binary.BigEndian.AppendUint64(tai64n, uint64(int64(4611686018427387914)+now.Unix()))
	tai64n = binary.BigEndian.AppendUint32(tai64n, uint32(now.Nanosecond()))
	msg, _, _, err := hs.WriteMessage(nil, tai64n)
	if err != nil {
		return err
	}

	packet := new(bytes.Buffer)
	_, _ = packet.Write([]byte{0x01, 0x00, 0x00, 0x00})
	var senderIndex [4]byte
	binary.LittleEndian.PutUint32(senderIndex[:], 28)
	_, _ = packet.Write(senderIndex[:])
	_, _ = packet.Write(msg)

	macKey := blake2s.Sum256(append([]byte("mac1----"), peerPub...))
	hasher, err := blake2s.New128(macKey[:])
	if err != nil {
		return err
	}
	_, _ = hasher.Write(packet.Bytes())
	_, _ = packet.Write(hasher.Sum(nil)[:16])
	_, _ = packet.Write(make([]byte, 16))

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(handshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(packet.Bytes()); err != nil {
		return err
	}

	response := make([]byte, 92)
	n, err := conn.Read(response)
	if err != nil {
		return err
	}
	if n < 60 || response[0] != 2 {
		return errors.New("invalid warp handshake response")
	}
	ourIndex := binary.LittleEndian.Uint32(response[8:12])
	if ourIndex != 28 {
		return errors.New("invalid warp handshake sender index")
	}
	payload, _, _, err := hs.ReadMessage(nil, response[12:60])
	if err != nil {
		return err
	}
	if len(payload) != 0 {
		return fmt.Errorf("unexpected warp handshake payload")
	}
	return nil
}

func staticKeypair(privateKeyBase64 string) (noise.DHKey, error) {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return noise.DHKey{}, err
	}
	var pubkey, privkey [32]byte
	copy(privkey[:], privateKey)
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return noise.DHKey{Private: privateKey, Public: pubkey[:]}, nil
}

func ephemeralKeypair() (noise.DHKey, error) {
	ephemeralPrivateKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivateKey); err != nil {
		return noise.DHKey{}, err
	}
	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: ephemeralPrivateKey, Public: ephemeralPublicKey}, nil
}
