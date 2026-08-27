package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/bepass-org/psiphon/masque"
	"github.com/bepass-org/psiphon/psiphon"
	"github.com/bepass-org/psiphon/warp"
	"github.com/bepass-org/psiphon/wiresocks"
)

const (
	MasqueDefaultSNI      = masque.DefaultH2SNI
	MasqueDefaultEndpoint = masque.DefaultH2Endpoint
)

// RunMode selects how tunnels are stacked.
type RunMode int

const (
	// ModePsiphonOnly exposes Psiphon SOCKS on -b (default).
	ModePsiphonOnly RunMode = iota
	// ModeWarpOnly exposes WireGuard WARP SOCKS on -b; Psiphon is not started.
	ModeWarpOnly
	// ModeMasqueOnly exposes MASQUE (HTTP/2) SOCKS on -b; Psiphon is not started.
	ModeMasqueOnly
	// ModeMasquePsiphon exposes MASQUE SOCKS on -b; MASQUE dials through Psiphon.
	ModeMasquePsiphon
	// ModePsiphonMasque exposes Psiphon SOCKS on -b; Psiphon dials through MASQUE.
	ModePsiphonMasque
	// ModePsiphonWarp exposes Psiphon SOCKS on -b; Psiphon dials through WARP.
	ModePsiphonWarp
)

func RunPsiphon(bindAddress string, proxyAddr string, country string, workingDirectory string, config string, ctx context.Context) error {
	err := psiphon.RunPsiphon(proxyAddr, bindAddress, country, workingDirectory, config, ctx)
	if err != nil {
		log.Printf("unable to run psiphon %v\n", err)
		return fmt.Errorf("unable to run psiphon %v\n", err)
	}
	log.Println("Connected successfully.")
	return nil
}

// Run starts the selected tunnel mode.
func Run(bindAddress string, proxyAddr string, country string, workingDirectory string, config string, mode RunMode, masqueSNI, masqueEndpoint, warpEndpoint string, ctx context.Context) error {
	switch mode {
	case ModeWarpOnly:
		return runWarpOnly(bindAddress, proxyAddr, workingDirectory, warpEndpoint, ctx)
	case ModeMasqueOnly:
		return runMasqueOnly(bindAddress, proxyAddr, workingDirectory, masqueSNI, masqueEndpoint, ctx)
	case ModeMasquePsiphon:
		return runMasquePsiphon(bindAddress, proxyAddr, country, workingDirectory, config, masqueSNI, masqueEndpoint, ctx)
	case ModePsiphonMasque:
		return runPsiphonMasque(bindAddress, proxyAddr, country, workingDirectory, config, masqueSNI, masqueEndpoint, ctx)
	case ModePsiphonWarp:
		return runPsiphonWarp(bindAddress, proxyAddr, country, workingDirectory, config, warpEndpoint, ctx)
	default:
		return RunPsiphon(bindAddress, proxyAddr, country, workingDirectory, config, ctx)
	}
}

func runWarpOnly(bindAddress, proxyAddr, workingDirectory, warpEndpoint string, ctx context.Context) error {
	log.Println("Starting Cloudflare WARP (WireGuard) ...")
	if _, err := startWarp(bindAddress, workingDirectory, proxyAddr, warpEndpoint, ctx); err != nil {
		return err
	}
	log.Printf("WARP SOCKS ready on %s", bindAddress)
	log.Printf("Connected successfully.")
	return nil
}

func runMasqueOnly(bindAddress, proxyAddr, workingDirectory, masqueSNI, masqueEndpoint string, ctx context.Context) error {
	log.Println("Starting Cloudflare MASQUE (HTTP/2) ...")
	upstream := ""
	if proxyAddr != "null" && proxyAddr != "" {
		host, err := socks5HostPort(proxyAddr)
		if err != nil {
			return err
		}
		upstream = host
		log.Printf("MASQUE TCP dial via %s", upstream)
	}
	if err := startMasque(bindAddress, workingDirectory, upstream, masqueSNI, masqueEndpoint, ctx); err != nil {
		return err
	}
	log.Printf("MASQUE SOCKS ready on %s", bindAddress)
	return nil
}

func runMasquePsiphon(bindAddress, proxyAddr, country, workingDirectory, config, masqueSNI, masqueEndpoint string, ctx context.Context) error {
	psiphonBind, err := findFreePort("tcp")
	if err != nil {
		return fmt.Errorf("unable to allocate internal Psiphon SOCKS port: %w", err)
	}

	log.Printf("Starting Psiphon (country=%s) on %s ...", country, psiphonBind)
	if err := RunPsiphon(psiphonBind, proxyAddr, country, workingDirectory, config, ctx); err != nil {
		return err
	}

	log.Println("Starting Cloudflare MASQUE (HTTP/2) over Psiphon ...")
	if err := startMasque(bindAddress, workingDirectory, psiphonBind, masqueSNI, masqueEndpoint, ctx); err != nil {
		return fmt.Errorf("unable to start masque over psiphon: %w", err)
	}
	log.Printf("MASQUE SOCKS ready on %s", bindAddress)
	return nil
}

func runPsiphonMasque(bindAddress, proxyAddr, country, workingDirectory, config, masqueSNI, masqueEndpoint string, ctx context.Context) error {
	masqueBind, err := findFreePort("tcp")
	if err != nil {
		return fmt.Errorf("unable to allocate internal MASQUE SOCKS port: %w", err)
	}

	log.Println("Starting Cloudflare MASQUE (HTTP/2) ...")
	upstream := ""
	if proxyAddr != "null" && proxyAddr != "" {
		host, err := socks5HostPort(proxyAddr)
		if err != nil {
			return err
		}
		upstream = host
		log.Printf("MASQUE TCP dial via %s", upstream)
	}
	if err := startMasque(masqueBind, workingDirectory, upstream, masqueSNI, masqueEndpoint, ctx); err != nil {
		return err
	}
	log.Printf("MASQUE SOCKS ready on %s", masqueBind)

	log.Printf("Starting Psiphon over MASQUE (country=%s) ...", country)
	if err := RunPsiphon(bindAddress, "socks5://"+masqueBind, country, workingDirectory, config, ctx); err != nil {
		return fmt.Errorf("unable to start psiphon over masque: %w", err)
	}
	log.Printf("Psiphon SOCKS ready on %s", bindAddress)
	return nil
}

func runPsiphonWarp(bindAddress, proxyAddr, country, workingDirectory, config, warpEndpoint string, ctx context.Context) error {
	warpBind, err := findFreePort("tcp")
	if err != nil {
		return fmt.Errorf("unable to allocate internal WARP SOCKS port: %w", err)
	}

	log.Println("Starting Cloudflare WARP (WireGuard) ...")
	if _, err := startWarp(warpBind, workingDirectory, proxyAddr, warpEndpoint, ctx); err != nil {
		return err
	}
	log.Printf("WARP SOCKS ready on %s", warpBind)

	log.Printf("Starting Psiphon over WARP (country=%s) ...", country)
	if err := RunPsiphon(bindAddress, "socks5://"+warpBind, country, workingDirectory, config, ctx); err != nil {
		return fmt.Errorf("unable to start psiphon over warp: %w", err)
	}
	log.Printf("Psiphon SOCKS ready on %s", bindAddress)
	return nil
}

func startMasque(bindAddress, workingDirectory, socksUpstream, masqueSNI, masqueEndpoint string, ctx context.Context) error {
	masqueDir := filepath.Join(workingDirectory, "data", "masque")
	cfg, err := masque.EnsureIdentity(masqueDir)
	if err != nil {
		return err
	}
	if err := cfg.ApplyOverrides(masqueEndpoint, masqueSNI); err != nil {
		return err
	}
	return masque.StartSocks(ctx, cfg, bindAddress, socksUpstream)
}

func startWarp(bindAddress, workingDirectory, proxyAddr, warpEndpoint string, ctx context.Context) (string, error) {
	warpDir := filepath.Join(workingDirectory, "data", "warp")
	if err := os.MkdirAll(warpDir, 0755); err != nil {
		return "", fmt.Errorf("create warp directory: %w", err)
	}

	warp.UpdatePath(warpDir)
	if !warp.CheckProfileExists("notset") {
		log.Println("Creating WARP identity (first run) ...")
		if err := warp.LoadOrCreateIdentity(""); err != nil {
			return "", fmt.Errorf("create warp identity: %w", err)
		}
	}

	profilePath := filepath.Join(warpDir, "wgcf-profile.ini")
	endpointOverride := "notset"
	if warpEndpoint != "" {
		if _, _, err := net.SplitHostPort(warpEndpoint); err != nil {
			return "", fmt.Errorf("warp-endpoint must be host:port: %w", err)
		}
		endpointOverride = warpEndpoint
		log.Printf("WARP endpoint override %s", warpEndpoint)
	}

	if proxyAddr != "null" && proxyAddr != "" {
		socksHost, err := socks5HostPort(proxyAddr)
		if err != nil {
			return "", err
		}

		baseConf, err := wiresocks.ParseConfig(profilePath, endpointOverride)
		if err != nil {
			return "", fmt.Errorf("parse warp profile: %w", err)
		}
		if len(baseConf.Device.Peers) == 0 || baseConf.Device.Peers[0].Endpoint == nil {
			return "", fmt.Errorf("warp profile has no peer endpoint")
		}
		remoteEndpoint := *baseConf.Device.Peers[0].Endpoint

		localUDP, err := findFreePort("udp")
		if err != nil {
			return "", fmt.Errorf("allocate local udp for warp forwarder: %w", err)
		}

		forwarder, err := wiresocks.NewSocks5UDPForwarder(localUDP, socksHost, remoteEndpoint)
		if err != nil {
			return "", fmt.Errorf("start socks5 udp forwarder (SOCKS5 must support UDP ASSOCIATE): %w", err)
		}
		forwarder.Start(ctx)
		endpointOverride = forwarder.LocalAddr()
		log.Printf("WireGuard endpoint %s via SOCKS5 %s (local %s)", remoteEndpoint, socksHost, endpointOverride)
	}

	conf, err := wiresocks.ParseConfig(profilePath, endpointOverride)
	if err != nil {
		return "", fmt.Errorf("parse warp profile: %w", err)
	}

	vtun, err := wiresocks.StartWireguard(conf.Device, false, ctx)
	if err != nil {
		return "", fmt.Errorf("start wireguard: %w", err)
	}
	vtun.StartProxy(bindAddress)
	return bindAddress, nil
}

func socks5HostPort(proxyURL string) (string, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid proxy url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "socks5" && scheme != "socks5h" {
		return "", fmt.Errorf("upstream proxy must be socks5:// (got %s)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("proxy url missing host: %s", proxyURL)
	}
	if !strings.Contains(u.Host, ":") {
		return net.JoinHostPort(u.Host, "1080"), nil
	}
	return u.Host, nil
}

// ListAvailableCountries returns sorted egress country codes from the local datastore.
func ListAvailableCountries(workingDirectory string, config string) ([]string, error) {
	return psiphon.ListAvailableCountries(workingDirectory, config)
}

func findFreePort(network string) (string, error) {
	if network == "udp" {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).String(), nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}
