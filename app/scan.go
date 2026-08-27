package app

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bepass-org/psiphon/masque"
	"github.com/bepass-org/psiphon/warp"
	"gopkg.in/ini.v1"
)

const (
	scanMasquePort    = 443
	scanMasqueWorkers = 16
	scanMasqueTimeout = 4 * time.Second
	scanMasqueCSV     = "scan-masque.csv"

	scanWarpWorkers = 32
	scanWarpTimeout = 2 * time.Second
	scanWarpCSV     = "scan-warp.csv"

	ipv6SequentialPerCIDR = 256
	ipv6RandomPerCIDR     = 256
)

type scanHit struct {
	ip   netip.Addr
	port int
	rtt  time.Duration
}

type ipProbeFunc func(ctx context.Context, ip netip.Addr) (port int, rtt time.Duration, err error)

// RunMasqueScan probes MASQUE HTTP/2 ranges with a real CONNECT-IP handshake.
func RunMasqueScan(workingDirectory, masqueSNI string, ctx context.Context) error {
	masqueDir := filepath.Join(workingDirectory, "data", "masque")
	cfg, err := masque.EnsureIdentity(masqueDir)
	if err != nil {
		return err
	}
	if err := cfg.ApplyOverrides("", masqueSNI); err != nil {
		return err
	}
	tlsCfg, err := masque.ClientTLSConfig(cfg)
	if err != nil {
		return err
	}

	probe := func(ctx context.Context, ip netip.Addr) (int, time.Duration, error) {
		endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(scanMasquePort))
		probeCtx, cancel := context.WithTimeout(ctx, scanMasqueTimeout)
		defer cancel()
		rtt, status, err := masque.ProbeH2(probeCtx, tlsCfg, endpoint)
		if err != nil {
			return 0, 0, err
		}
		if status < 200 || status > 299 {
			return 0, 0, fmt.Errorf("masque status %d", status)
		}
		return scanMasquePort, rtt, nil
	}

	return runIPScan(ctx, scanOpts{
		label:   fmt.Sprintf("MASQUE HTTP/2 (SNI %s)", cfg.H2SNI()),
		cidrs:   masque.DefaultH2CIDRs,
		csvName: filepath.Join(workingDirectory, scanMasqueCSV),
		workers: scanMasqueWorkers,
		probe:   probe,
	})
}

// RunWarpScan probes WARP WireGuard ranges with a handshake on UDP 2408.
func RunWarpScan(workingDirectory string, ctx context.Context) error {
	warpDir := filepath.Join(workingDirectory, "data", "warp")
	if err := os.MkdirAll(warpDir, 0755); err != nil {
		return fmt.Errorf("create warp directory: %w", err)
	}
	warp.UpdatePath(warpDir)
	if !warp.CheckProfileExists("notset") {
		fmt.Fprintln(os.Stderr, "Creating WARP identity (first run) ...")
		if err := warp.LoadOrCreateIdentity(""); err != nil {
			return fmt.Errorf("create warp identity: %w", err)
		}
	}

	profilePath := filepath.Join(warpDir, "wgcf-profile.ini")
	iniCfg, err := ini.Load(profilePath)
	if err != nil {
		return fmt.Errorf("read warp profile: %w", err)
	}
	privateKey := iniCfg.Section("Interface").Key("PrivateKey").String()
	peerPublicKey := iniCfg.Section("Peer").Key("PublicKey").String()
	if privateKey == "" || peerPublicKey == "" {
		return fmt.Errorf("warp profile missing keys")
	}

	probe := func(ctx context.Context, ip netip.Addr) (int, time.Duration, error) {
		endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(warp.DefaultPort))
		probeCtx, cancel := context.WithTimeout(ctx, scanWarpTimeout)
		defer cancel()
		start := time.Now()
		err := warp.Handshake(probeCtx, endpoint, privateKey, peerPublicKey, "")
		if err != nil {
			return 0, 0, err
		}
		return warp.DefaultPort, time.Since(start), nil
	}

	return runIPScan(ctx, scanOpts{
		label:   "WARP WireGuard",
		cidrs:   warp.DefaultCIDRs,
		csvName: filepath.Join(workingDirectory, scanWarpCSV),
		workers: scanWarpWorkers,
		probe:   probe,
	})
}

type scanOpts struct {
	label   string
	cidrs   []string
	csvName string
	workers int
	probe   ipProbeFunc
}

func runIPScan(ctx context.Context, opts scanOpts) error {
	useIPv6 := ipv6Available()
	ips, err := expandCIDRs(opts.cidrs, true, useIPv6)
	if err != nil {
		return err
	}
	total := len(ips)
	if total == 0 {
		return fmt.Errorf("scan list is empty")
	}
	if !useIPv6 {
		fmt.Fprintln(os.Stderr, "IPv6 is not available; scanning IPv4 only")
	}

	f, err := os.Create(opts.csvName)
	if err != nil {
		return fmt.Errorf("create %s: %w", opts.csvName, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"ip", "port", "rtt_ms"}); err != nil {
		return err
	}
	w.Flush()

	fmt.Fprintf(os.Stderr, "Scanning %d %s IPs (Ctrl+C to stop). Results: %s\n",
		total, opts.label, opts.csvName)

	jobs := make(chan netip.Addr)
	hits := make(chan scanHit, opts.workers)
	var scanned atomic.Int64
	var cleanCount atomic.Int64

	var workers sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					continue
				}
				port, rtt, err := opts.probe(ctx, ip)
				scanned.Add(1)
				if err == nil {
					hits <- scanHit{ip: ip, port: port, rtt: rtt}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()

	go func() {
		workers.Wait()
		close(hits)
	}()

	var csvMu sync.Mutex
	printStatus := func() {
		fmt.Fprintf(os.Stderr, "\rScanned %d/%d  clean %d", scanned.Load(), total, cleanCount.Load())
	}

	statusTick := time.NewTicker(200 * time.Millisecond)
	defer statusTick.Stop()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-statusTick.C:
				printStatus()
			case <-done:
				return
			}
		}
	}()

	for hit := range hits {
		cleanCount.Add(1)
		ipStr := hit.ip.String()
		rttMs := int(hit.rtt.Milliseconds())
		if rttMs < 1 {
			rttMs = 1
		}

		fmt.Fprintf(os.Stderr, "\r")
		fmt.Printf("%s\n", net.JoinHostPort(ipStr, strconv.Itoa(hit.port)))
		printStatus()

		csvMu.Lock()
		_ = w.Write([]string{ipStr, strconv.Itoa(hit.port), strconv.Itoa(rttMs)})
		w.Flush()
		csvMu.Unlock()
	}
	close(done)

	printStatus()
	fmt.Fprintln(os.Stderr)
	noun := "IP(s)"
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "Scan stopped. %d clean %s saved to %s\n", cleanCount.Load(), noun, opts.csvName)
		return nil
	}
	fmt.Fprintf(os.Stderr, "Scan finished. %d clean %s saved to %s\n", cleanCount.Load(), noun, opts.csvName)
	return nil
}

func expandCIDRs(cidrs []string, useIPv4, useIPv6 bool) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{})
	var ips []netip.Addr
	add := func(addr netip.Addr) {
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		ips = append(ips, addr)
	}

	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %s: %w", raw, err)
		}
		prefix = prefix.Masked()
		is4 := prefix.Addr().Is4()
		if (is4 && !useIPv4) || (!is4 && !useIPv6) {
			continue
		}
		if is4 {
			for _, addr := range enumeratePrefix(prefix, 0) {
				add(addr)
			}
			continue
		}
		for _, addr := range enumeratePrefix(prefix, ipv6SequentialPerCIDR) {
			add(addr)
		}
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits <= 8 {
			continue
		}
		added := 0
		for i := 0; i < ipv6RandomPerCIDR*8 && added < ipv6RandomPerCIDR; i++ {
			addr, err := randomAddrInPrefix(prefix)
			if err != nil {
				return nil, err
			}
			before := len(ips)
			add(addr)
			if len(ips) > before {
				added++
			}
		}
	}
	return ips, nil
}

func enumeratePrefix(prefix netip.Prefix, limit int) []netip.Addr {
	var ips []netip.Addr
	addr := prefix.Addr()
	for {
		if !prefix.Contains(addr) {
			break
		}
		ips = append(ips, addr)
		if limit > 0 && len(ips) >= limit {
			break
		}
		next := addr.Next()
		if !next.IsValid() {
			break
		}
		addr = next
	}
	return ips
}

func randomAddrInPrefix(prefix netip.Prefix) (netip.Addr, error) {
	base := prefix.Masked().Addr()
	if !base.Is6() {
		return netip.Addr{}, fmt.Errorf("randomAddrInPrefix requires IPv6")
	}
	a := base.As16()
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return netip.Addr{}, err
	}
	for bit := prefix.Bits(); bit < 128; bit++ {
		byteIdx := bit / 8
		shift := uint(7 - (bit % 8))
		mask := byte(1 << shift)
		a[byteIdx] = (a[byteIdx] &^ mask) | (rnd[byteIdx] & mask)
	}
	return netip.AddrFrom16(a), nil
}

func ipv6Available() bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp6", "[2001:4860:4860::8888]:80")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
