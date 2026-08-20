package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

func generateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return marshalledPrivKey, marshalledPubKey, nil
}

func generateCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}
