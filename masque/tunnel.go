package masque

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/bepass-org/psiphon/tun"
	"github.com/bepass-org/psiphon/tun/netstack"
	"github.com/bepass-org/psiphon/wiresocks"
)

const mtu = 1280

// StartSocks starts MASQUE over HTTP/2 and exposes a SOCKS proxy on bindAddress.
// When socksUpstream is non-empty (host:port), the MASQUE TCP dial goes through that SOCKS5 proxy.
func StartSocks(ctx context.Context, cfg *Config, bindAddress, socksUpstream string) error {
	localAddrs := make([]netip.Addr, 0, 2)
	if cfg.IPv4 != "" {
		v4, err := netip.ParseAddr(cfg.IPv4)
		if err != nil {
			return fmt.Errorf("parse masque ipv4: %w", err)
		}
		localAddrs = append(localAddrs, v4)
	}
	if cfg.IPv6 != "" {
		v6, err := netip.ParseAddr(cfg.IPv6)
		if err != nil {
			return fmt.Errorf("parse masque ipv6: %w", err)
		}
		localAddrs = append(localAddrs, v6)
	}
	if len(localAddrs) == 0 {
		return errors.New("masque config has no tunnel addresses")
	}

	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return fmt.Errorf("create masque tun: %w", err)
	}

	go maintainTunnel(ctx, cfg, socksUpstream, tunDev)

	vt := &wiresocks.VirtualTun{
		Tnet:      tnet,
		SystemDNS: false,
		Verbose:   false,
		Logger:    wiresocks.DefaultLogger{},
		Dev:       nil,
		Ctx:       ctx,
	}
	vt.StartProxy(bindAddress)
	return nil
}

func maintainTunnel(ctx context.Context, cfg *Config, socksUpstream string, tunDev tun.Device) {
	for {
		select {
		case <-ctx.Done():
			_ = tunDev.Close()
			return
		default:
		}

		log.Printf("Establishing MASQUE HTTP/2 tunnel to %s (SNI %s) ...", cfg.H2Endpoint(), cfg.H2SNI())
		ipConn, rsp, err := connectH2(ctx, cfg, socksUpstream)
		if err != nil {
			log.Printf("MASQUE connect failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if rsp != nil && (rsp.StatusCode < 200 || rsp.StatusCode > 299) {
			log.Printf("MASQUE connect status: %s", rsp.Status)
			_ = ipConn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		log.Println("Connected to MASQUE server (HTTP/2)")
		log.Println("Connected successfully.")

		errCh := make(chan error, 2)

		go func() {
			packetBufs := [][]byte{make([]byte, mtu)}
			sizes := []int{0}
			for {
				select {
				case <-ctx.Done():
					errCh <- context.Canceled
					return
				default:
				}
				sizes[0] = 0
				n, err := tunDev.Read(packetBufs, sizes, 0)
				if err != nil {
					errCh <- fmt.Errorf("tun read: %w", err)
					return
				}
				if n < 1 || sizes[0] == 0 {
					continue
				}
				if _, err := ipConn.WritePacket(packetBufs[0][:sizes[0]]); err != nil {
					errCh <- fmt.Errorf("masque write: %w", err)
					return
				}
			}
		}()

		go func() {
			buf := make([]byte, mtu)
			for {
				select {
				case <-ctx.Done():
					errCh <- context.Canceled
					return
				default:
				}
				n, err := ipConn.ReadPacket(buf)
				if err != nil {
					errCh <- fmt.Errorf("masque read: %w", err)
					return
				}
				if _, err := tunDev.Write([][]byte{buf[:n]}, 0); err != nil {
					errCh <- fmt.Errorf("tun write: %w", err)
					return
				}
			}
		}()

		err = <-errCh
		log.Printf("MASQUE tunnel lost: %v; reconnecting...", err)
		_ = ipConn.Close()
		select {
		case <-ctx.Done():
			_ = tunDev.Close()
			return
		case <-time.After(time.Second):
		}
	}
}
