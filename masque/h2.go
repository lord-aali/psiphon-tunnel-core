package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const connectURI = "https://cloudflareaccess.com"

// context ID 0 as a 1-byte QUIC varint.
var contextIDZero = []byte{0x00}

type ipConn struct {
	stream *h2DatagramStream
}

func (c *ipConn) Close() error { return c.stream.Close() }

func (c *ipConn) ReadPacket(b []byte) (int, error) {
	data, err := c.stream.ReceiveDatagram()
	if err != nil {
		return 0, err
	}
	if len(data) < 1 {
		return 0, errors.New("empty masque datagram")
	}
	pkt := data[1:]
	return copy(b, pkt), nil
}

func (c *ipConn) WritePacket(b []byte) (icmp []byte, err error) {
	frame := make([]byte, 0, len(contextIDZero)+len(b))
	frame = append(frame, contextIDZero...)
	frame = append(frame, b...)
	if err := c.stream.SendDatagram(frame); err != nil {
		return nil, err
	}
	return nil, nil
}

func connectH2(ctx context.Context, cfg *Config, socksAddr string) (*ipConn, *http.Response, error) {
	tlsConfig, err := ClientTLSConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	return doConnectH2(ctx, tlsConfig, cfg.H2Endpoint(), socksAddr)
}

// ClientTLSConfig builds the MASQUE HTTP/2 client certificate + SNI config.
func ClientTLSConfig(cfg *Config) (*tls.Config, error) {
	privDER, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	privKey, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	certDER, err := generateCert(privKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: certDER,
			PrivateKey:  privKey,
		}},
		ServerName:         cfg.H2SNI(),
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	}, nil
}

// ProbeH2 tries a MASQUE CONNECT-IP handshake against endpoint (host:port).
// A 2xx status means the IP speaks MASQUE HTTP/2.
func ProbeH2(ctx context.Context, tlsConfig *tls.Config, endpoint string) (time.Duration, int, error) {
	start := time.Now()
	conn, rsp, err := doConnectH2(ctx, tlsConfig, endpoint, "")
	rtt := time.Since(start)
	status := 0
	if rsp != nil {
		status = rsp.StatusCode
	}
	if conn != nil {
		_ = conn.Close()
	}
	return rtt, status, err
}

func doConnectH2(ctx context.Context, tlsConfig *tls.Config, endpoint, socksAddr string) (*ipConn, *http.Response, error) {
	client, err := newHTTP2Client(tlsConfig, endpoint, socksAddr)
	if err != nil {
		return nil, nil, err
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, connectURI, pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, err
	}
	req.Host = "cloudflareaccess.com:443"
	req.ContentLength = -1
	req.Header = http.Header{}
	req.Header.Set("User-Agent", "")
	req.Header.Set("cf-connect-proto", "cf-connect-ip")
	req.Header.Set("pq-enabled", "false")

	rsp, err := client.Do(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		client.CloseIdleConnections()
		return nil, nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = pr.Close()
		_ = pw.Close()
		_ = rsp.Body.Close()
		client.CloseIdleConnections()
		return nil, rsp, fmt.Errorf("masque server responded %d", rsp.StatusCode)
	}

	stream := &h2DatagramStream{
		requestBody:  pw,
		responseBody: rsp.Body,
		recvBuf:      make([]byte, 0, 4096),
	}
	return &ipConn{stream: stream}, rsp, nil
}

func newHTTP2Client(tlsConfig *tls.Config, endpoint, socksAddr string) (*http.Client, error) {
	parsed, err := url.Parse(connectURI)
	if err != nil {
		return nil, err
	}
	originAuthority := parsed.Hostname() + ":443"

	transport := &http2.Transport{
		// Always use our TLS config (client cert + skip-verify). Ignore the
		// config passed by http2.Transport — it resets InsecureSkipVerify.
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			if addr == originAuthority || addr == parsed.Host {
				addr = endpoint
			}
			return dialTLSThroughSOCKS(ctx, socksAddr, network, addr, tlsConfig)
		},
	}
	return &http.Client{Transport: transport}, nil
}

func dialTLSThroughSOCKS(ctx context.Context, socksAddr, network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	var raw net.Conn
	var err error
	if socksAddr == "" {
		d := &net.Dialer{}
		raw, err = d.DialContext(ctx, network, addr)
	} else {
		dialer, e := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if e != nil {
			return nil, e
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			raw, err = cd.DialContext(ctx, network, addr)
		} else {
			raw, err = dialer.Dial(network, addr)
		}
	}
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

type h2DatagramStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	readMu       sync.Mutex
	writeMu      sync.Mutex
	recvBuf      []byte
}

func (s *h2DatagramStream) ReceiveDatagram() ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		capsuleType, payload, consumed, ok, err := parseCapsule(s.recvBuf)
		if err != nil {
			return nil, err
		}
		if ok {
			if capsuleType != 0 {
				s.recvBuf = s.recvBuf[consumed:]
				continue
			}
			out := make([]byte, 0, len(contextIDZero)+len(payload))
			out = append(out, contextIDZero...)
			out = append(out, payload...)
			s.recvBuf = s.recvBuf[consumed:]
			return out, nil
		}
		buf := make([]byte, 4096)
		n, readErr := s.responseBody.Read(buf)
		if n > 0 {
			s.recvBuf = append(s.recvBuf, buf[:n]...)
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func (s *h2DatagramStream) SendDatagram(data []byte) error {
	if len(data) < 1 {
		return errors.New("empty datagram")
	}
	payload := data[1:]
	frame := make([]byte, 0, 8+len(payload))
	frame = appendVarint(frame, 0)
	frame = appendVarint(frame, uint64(len(payload)))
	frame = append(frame, payload...)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.requestBody.Write(frame)
	return err
}

func (s *h2DatagramStream) Close() error {
	_ = s.requestBody.Close()
	return s.responseBody.Close()
}

func parseCapsule(buf []byte) (capsuleType uint64, payload []byte, consumed int, ok bool, err error) {
	capsuleType, typeLen, ok := parseVarint(buf)
	if !ok {
		return 0, nil, 0, false, nil
	}
	payloadLen, payloadLenLen, ok := parseVarint(buf[typeLen:])
	if !ok {
		return 0, nil, 0, false, nil
	}
	headerLen := typeLen + payloadLenLen
	totalLen := headerLen + int(payloadLen)
	if totalLen < headerLen {
		return 0, nil, 0, false, errors.New("malformed capsule length")
	}
	if len(buf) < totalLen {
		return 0, nil, 0, false, nil
	}
	return capsuleType, buf[headerLen:totalLen], totalLen, true, nil
}

func parseVarint(buf []byte) (v uint64, n int, ok bool) {
	if len(buf) == 0 {
		return 0, 0, false
	}
	prefix := buf[0] >> 6
	n = 1 << prefix
	if len(buf) < n {
		return 0, 0, false
	}
	v = uint64(buf[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(buf[i])
	}
	return v, n, true
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
