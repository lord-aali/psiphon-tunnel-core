package wiresocks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// Socks5UDPForwarder relays local UDP datagrams through a SOCKS5 UDP ASSOCIATE
// session to a fixed remote destination (used to send WireGuard through a proxy).
type Socks5UDPForwarder struct {
	destAddr     *net.UDPAddr
	proxyUDPAddr *net.UDPAddr
	udpConn      *net.UDPConn
	listener     *net.UDPConn
	controlConn  net.Conn
	clientAddr   *net.UDPAddr
	clientMu     sync.Mutex
	closeOnce    sync.Once
}

// NewVtunUDPForwarder relays local UDP through a wiresocks virtual TUN.
func NewVtunUDPForwarder(localBind, dest string, vtun *VirtualTun, mtu int, ctx context.Context) error {
	localAddr, err := net.ResolveUDPAddr("udp", localBind)
	if err != nil {
		return err
	}

	destAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return err
	}

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return err
	}

	rconn, err := vtun.Tnet.DialUDP(nil, destAddr)
	if err != nil {
		_ = listener.Close()
		return err
	}

	var clientAddr *net.UDPAddr
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buffer := make([]byte, mtu)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, cAddr, err := listener.ReadFrom(buffer)
				if err != nil {
					continue
				}
				clientAddr = cAddr.(*net.UDPAddr)
				_, _ = rconn.WriteTo(buffer[:n], destAddr)
			}
		}
	}()
	go func() {
		defer wg.Done()
		buffer := make([]byte, mtu)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, _, err := rconn.ReadFrom(buffer)
				if err != nil {
					continue
				}
				if clientAddr != nil {
					_, _ = listener.WriteTo(buffer[:n], clientAddr)
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		_ = listener.Close()
		_ = rconn.Close()
	}()
	return nil
}

// NewSocks5UDPForwarder listens on localBind and forwards UDP to dest via socks5Server.
// The SOCKS5 control connection is kept open for the lifetime of the association.
func NewSocks5UDPForwarder(localBind, socks5Server, dest string) (*Socks5UDPForwarder, error) {
	localAddr, err := net.ResolveUDPAddr("udp", localBind)
	if err != nil {
		return nil, err
	}

	destAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return nil, err
	}
	if destAddr.IP.To4() == nil {
		return nil, fmt.Errorf("socks5 udp forwarder currently supports IPv4 destinations only: %s", dest)
	}

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, err
	}

	tcpConn, err := net.Dial("tcp", socks5Server)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	if err := socks5Handshake(tcpConn); err != nil {
		_ = tcpConn.Close()
		_ = listener.Close()
		return nil, err
	}

	proxyUDPAddr, err := requestUDPAssociate(tcpConn, socks5Server)
	if err != nil {
		_ = tcpConn.Close()
		_ = listener.Close()
		return nil, err
	}

	udpConn, err := net.DialUDP("udp", nil, proxyUDPAddr)
	if err != nil {
		_ = tcpConn.Close()
		_ = listener.Close()
		return nil, err
	}

	return &Socks5UDPForwarder{
		destAddr:     destAddr,
		proxyUDPAddr: proxyUDPAddr,
		udpConn:      udpConn,
		listener:     listener,
		controlConn:  tcpConn,
	}, nil
}

// LocalAddr returns the local UDP address WireGuard should use as its peer endpoint.
func (f *Socks5UDPForwarder) LocalAddr() string {
	return f.listener.LocalAddr().String()
}

// Start begins forwarding; it stops when ctx is cancelled.
func (f *Socks5UDPForwarder) Start(ctx context.Context) {
	go f.listenAndServe(ctx)
	go f.receiveFromProxy(ctx)
	go func() {
		<-ctx.Done()
		f.Close()
	}()
}

// Close releases forwarder resources.
func (f *Socks5UDPForwarder) Close() {
	f.closeOnce.Do(func() {
		if f.listener != nil {
			_ = f.listener.Close()
		}
		if f.udpConn != nil {
			_ = f.udpConn.Close()
		}
		if f.controlConn != nil {
			_ = f.controlConn.Close()
		}
	})
}

func socks5Handshake(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("invalid SOCKS5 authentication response")
	}
	return nil
}

func (f *Socks5UDPForwarder) listenAndServe(ctx context.Context) {
	buffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = f.listener.SetReadDeadline(deadlineFromContext(ctx))
		n, clientAddr, err := f.listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		f.clientMu.Lock()
		f.clientAddr = clientAddr
		f.clientMu.Unlock()

		f.forwardPacketToRemote(buffer[:n])
	}
}

func (f *Socks5UDPForwarder) forwardPacketToRemote(data []byte) {
	packet := make([]byte, 10+len(data))
	packet[0] = 0x00
	packet[1] = 0x00
	packet[2] = 0x00
	packet[3] = 0x01
	copy(packet[4:8], f.destAddr.IP.To4())
	binary.BigEndian.PutUint16(packet[8:10], uint16(f.destAddr.Port))
	copy(packet[10:], data)

	_, err := f.udpConn.Write(packet)
	if err != nil {
		fmt.Printf("Error forwarding packet to remote: %v\n", err)
	}
}

func (f *Socks5UDPForwarder) receiveFromProxy(ctx context.Context) {
	buffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = f.udpConn.SetReadDeadline(deadlineFromContext(ctx))
		n, err := f.udpConn.Read(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if n < 10 {
			continue
		}

		f.clientMu.Lock()
		clientAddr := f.clientAddr
		f.clientMu.Unlock()
		if clientAddr != nil {
			_, _ = f.listener.WriteToUDP(buffer[10:n], clientAddr)
		}
	}
}

func requestUDPAssociate(conn net.Conn, socks5Server string) (*net.UDPAddr, error) {
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("UDP ASSOCIATE request failed (rep=0x%02x)", resp[1])
	}

	var bindIP net.IP
	switch resp[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		bindIP = net.IP(ip)
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		host := make([]byte, length[0])
		if _, err := io.ReadFull(conn, host); err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(string(host))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve UDP associate host %q: %w", string(host), err)
		}
		bindIP = ips[0].To4()
		if bindIP == nil {
			bindIP = ips[0]
		}
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		bindIP = net.IP(ip)
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type 0x%02x", resp[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return nil, err
	}
	bindPort := binary.BigEndian.Uint16(portBuf[:])

	if bindIP.IsUnspecified() {
		host, _, err := net.SplitHostPort(socks5Server)
		if err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve socks host %q: %w", host, err)
		}
		bindIP = ips[0]
	}

	return &net.UDPAddr{IP: bindIP, Port: int(bindPort)}, nil
}
