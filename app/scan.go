package app

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
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
	scanMasqueCSV = "scan-masque.csv"
	scanWarpCSV   = "scan-warp.csv"

	// Thorough IPv4 sweep (Aether full_subnet): every host in each /24.
	// Balanced-style random sampling skipped .116 in 162.159.198.0/24.
	scanMasqueWorkers   = 16
	scanMasqueTimeout   = 12 * time.Second
	scanMasqueH3Timeout = 15 * time.Second
	scanMasqueSampleV6  = 140

	scanWarpWorkers   = 8
	scanWarpTimeout   = 7 * time.Second
	scanWarpSampleV6  = 120
	scanWarpPortWaves = 3
)

type scanHit struct {
	ip   netip.Addr
	port int
	rtt  time.Duration
}

type scanTarget struct {
	ip   netip.Addr
	port int
}

type endpointProbeFunc func(ctx context.Context, ip netip.Addr, port int) (time.Duration, error)

// RunMasqueScan probes MASQUE ranges with CONNECT-IP plus a data-plane DNS check,
// using Aether's CIDRs, seeds, ports, and interleaved sampling.
func RunMasqueScan(workingDirectory, masqueSNI string, useH3 bool, ctx context.Context) error {
	masqueDir := filepath.Join(workingDirectory, "data", "masque")
	cfg, err := masque.EnsureIdentity(masqueDir)
	if err != nil {
		return err
	}
	if err := cfg.ApplyOverrides("", masqueSNI); err != nil {
		return err
	}

	useIPv6 := ipv6Available()
	targets, err := buildMasqueTargets(true, useIPv6)
	if err != nil {
		return err
	}

	label := fmt.Sprintf("MASQUE HTTP/2 data-plane (SNI %s)", cfg.H2SNI())
	timeout := scanMasqueTimeout
	workers := scanMasqueWorkers
	if useH3 {
		label = fmt.Sprintf("MASQUE HTTP/3 data-plane (SNI %s)", cfg.H2SNI())
		timeout = scanMasqueH3Timeout
		workers = 8
	}
	if !useIPv6 {
		fmt.Fprintln(os.Stderr, "IPv6 is not available; scanning IPv4 only")
	}

	tlsCfg, err := masque.ClientTLSConfig(cfg)
	if err != nil {
		return err
	}

	probe := func(ctx context.Context, ip netip.Addr, port int) (time.Duration, error) {
		endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var (
			rtt    time.Duration
			status int
			err    error
		)
		if useH3 {
			rtt, status, err = masque.ProbeH3(probeCtx, cfg, endpoint, "")
		} else {
			rtt, status, err = masque.ProbeH2(probeCtx, cfg, tlsCfg, endpoint, "", masque.FragmentConfig{})
		}
		if err != nil {
			return 0, err
		}
		if status < 200 || status > 299 {
			return 0, fmt.Errorf("masque status %d", status)
		}
		return rtt, nil
	}

	return runEndpointScan(ctx, scanEndpointOpts{
		label:   label,
		targets: targets,
		csvName: filepath.Join(workingDirectory, scanMasqueCSV),
		workers: workers,
		probe:   probe,
	})
}

type masqueHit struct {
	endpoint string
	useH3    bool
	fragment masque.FragmentConfig
}

// scanFirstMasqueEndpoint probes targets until one CONNECT-IP + data-plane
// check succeeds. HTTP/3 is tried first, then HTTP/2 without fragment, then
// HTTP/2 with TLS fragment.
func scanFirstMasqueEndpoint(ctx context.Context, cfg *masque.Config, tlsCfg *tls.Config, socksAddr string, fragment masque.FragmentConfig, skip map[string]struct{}) (string, bool, masque.FragmentConfig, error) {
	useIPv6 := ipv6Available()
	targets, err := buildMasqueSmartTargets(true, useIPv6)
	if err != nil {
		return "", false, masque.FragmentConfig{}, err
	}
	if skip == nil {
		skip = map[string]struct{}{}
	}
	filtered := make([]scanTarget, 0, len(targets))
	for _, t := range targets {
		ep := net.JoinHostPort(t.ip.String(), strconv.Itoa(t.port))
		if _, ok := skip[ep]; ok {
			continue
		}
		filtered = append(filtered, t)
	}
	if len(filtered) == 0 {
		return "", false, masque.FragmentConfig{}, fmt.Errorf("masque smart: no endpoints left to scan")
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan scanTarget)
	hits := make(chan masqueHit, 1)
	var scanned atomic.Int64
	total := len(filtered)

	var workers sync.WaitGroup
	workerN := 8
	if workerN > total {
		workerN = total
	}
	for i := 0; i < workerN; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range jobs {
				if scanCtx.Err() != nil {
					return
				}
				endpoint := net.JoinHostPort(t.ip.String(), strconv.Itoa(t.port))
				scanned.Add(1)

				h3Ctx, h3Cancel := context.WithTimeout(scanCtx, scanMasqueH3Timeout)
				_, status, err := masque.ProbeH3(h3Ctx, cfg, endpoint, socksAddr)
				h3Cancel()
				if err == nil && status >= 200 && status <= 299 {
					select {
					case hits <- masqueHit{endpoint: endpoint, useH3: true}:
						cancel()
					default:
					}
					return
				}
				if scanCtx.Err() != nil {
					return
				}

				if frag, ok := probeH2AutoFragment(scanCtx, cfg, tlsCfg, endpoint, socksAddr, "scan", fragment); ok {
					select {
					case hits <- masqueHit{endpoint: endpoint, fragment: frag}:
						cancel()
					default:
					}
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range filtered {
			select {
			case <-scanCtx.Done():
				return
			case jobs <- t:
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()

	log.Printf("MASQUE smart: scanning %d endpoints for the first working address ...", total)
	statusTick := time.NewTicker(2 * time.Second)
	defer statusTick.Stop()

	for {
		select {
		case hit := <-hits:
			return finishMasqueHit(hit)
		case <-statusTick.C:
			log.Printf("MASQUE smart: scanned %d/%d", scanned.Load(), total)
		case <-done:
			select {
			case hit := <-hits:
				return finishMasqueHit(hit)
			default:
				if ctx.Err() != nil {
					return "", false, masque.FragmentConfig{}, ctx.Err()
				}
				return "", false, masque.FragmentConfig{}, fmt.Errorf("masque smart: no working endpoint found")
			}
		case <-ctx.Done():
			return "", false, masque.FragmentConfig{}, ctx.Err()
		}
	}
}

func finishMasqueHit(hit masqueHit) (string, bool, masque.FragmentConfig, error) {
	if hit.useH3 {
		log.Printf("MASQUE smart: found HTTP/3 %s", hit.endpoint)
		return hit.endpoint, true, masque.FragmentConfig{}, nil
	}
	if hit.fragment.Enabled {
		log.Printf("MASQUE smart: found HTTP/2 %s with TLS fragment", hit.endpoint)
	} else {
		log.Printf("MASQUE smart: found HTTP/2 %s without TLS fragment", hit.endpoint)
	}
	return hit.endpoint, false, hit.fragment, nil
}

// RunWarpScan probes WARP WireGuard ranges with a real handshake, using Aether's
// prefixes, seeds, and rotated UDP port waves.
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

	useIPv6 := ipv6Available()
	targets, err := buildWarpTargets(true, useIPv6)
	if err != nil {
		return err
	}
	if !useIPv6 {
		fmt.Fprintln(os.Stderr, "IPv6 is not available; scanning IPv4 only")
	}

	probe := func(ctx context.Context, ip netip.Addr, port int) (time.Duration, error) {
		endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		probeCtx, cancel := context.WithTimeout(ctx, scanWarpTimeout)
		defer cancel()
		start := time.Now()
		if err := warp.Handshake(probeCtx, endpoint, privateKey, peerPublicKey, ""); err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}

	return runEndpointScan(ctx, scanEndpointOpts{
		label:   "WARP WireGuard handshake",
		targets: targets,
		csvName: filepath.Join(workingDirectory, scanWarpCSV),
		workers: scanWarpWorkers,
		probe:   probe,
	})
}

type scanEndpointOpts struct {
	label   string
	targets []scanTarget
	csvName string
	workers int
	probe   endpointProbeFunc
}

func runEndpointScan(ctx context.Context, opts scanEndpointOpts) error {
	total := len(opts.targets)
	if total == 0 {
		return fmt.Errorf("scan list is empty")
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

	fmt.Fprintf(os.Stderr, "Scanning %d %s endpoints (Ctrl+C to stop). Results: %s\n",
		total, opts.label, opts.csvName)

	jobs := make(chan scanTarget)
	hits := make(chan scanHit, opts.workers)
	var scanned atomic.Int64
	var cleanCount atomic.Int64

	var workers sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					continue
				}
				rtt, err := opts.probe(ctx, t.ip, t.port)
				scanned.Add(1)
				if err == nil {
					hits <- scanHit{ip: t.ip, port: t.port, rtt: rtt}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range opts.targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
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
	noun := "endpoint(s)"
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "Scan stopped. %d clean %s saved to %s\n", cleanCount.Load(), noun, opts.csvName)
		return nil
	}
	fmt.Fprintf(os.Stderr, "Scan finished. %d clean %s saved to %s\n", cleanCount.Load(), noun, opts.csvName)
	return nil
}

func buildMasqueTargets(useIPv4, useIPv6 bool) ([]scanTarget, error) {
	return assembleMasqueTargets(useIPv4, useIPv6, false)
}

func buildMasqueSmartTargets(useIPv4, useIPv6 bool) ([]scanTarget, error) {
	return assembleMasqueTargets(useIPv4, useIPv6, true)
}

func assembleMasqueTargets(useIPv4, useIPv6, preferFirstCIDR bool) ([]scanTarget, error) {
	ports := masque.ScanPorts
	primary := ports[0]
	var out []scanTarget
	seen := make(map[scanTarget]struct{})
	push := func(ip netip.Addr, port int) {
		t := scanTarget{ip: ip, port: port}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}

	var seeds4, seeds6 []netip.Addr
	if useIPv4 {
		if preferFirstCIDR {
			prefHosts, err := enumerateCIDRv4(masque.PreferredScanCIDRv4)
			if err != nil {
				return nil, err
			}
			for _, ip := range prefHosts {
				push(ip, primary)
			}
		}
		for _, s := range masque.ScanSeedsV4 {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			seeds4 = append(seeds4, ip)
			push(ip, primary)
		}
		groups := make([][]netip.Addr, 0, len(masque.ScanCIDRsV4))
		for _, cidr := range masque.ScanCIDRsV4 {
			if preferFirstCIDR && cidr == masque.PreferredScanCIDRv4 {
				continue
			}
			hosts, err := enumerateCIDRv4(cidr)
			if err != nil {
				return nil, err
			}
			groups = append(groups, hosts)
		}
		interleavePush(groups, func(ip netip.Addr) { push(ip, primary) })
	}

	if useIPv6 {
		for _, s := range masque.ScanSeedsV6 {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			seeds6 = append(seeds6, ip)
			push(ip, primary)
		}
		groups := make([][]netip.Addr, 0, len(masque.ScanCIDRsV6))
		for _, cidr := range masque.ScanCIDRsV6 {
			hosts, err := sampleCIDRv6(cidr, scanMasqueSampleV6, masque.ScanCIDRsV4)
			if err != nil {
				return nil, err
			}
			groups = append(groups, hosts)
		}
		interleavePush(groups, func(ip netip.Addr) { push(ip, primary) })
	}

	if useIPv4 {
		for _, ip := range seeds4 {
			for _, port := range ports[1:] {
				push(ip, port)
			}
		}
	}
	if useIPv6 {
		for _, ip := range seeds6 {
			for _, port := range ports[1:] {
				push(ip, port)
			}
		}
	}
	return out, nil
}

func buildWarpTargets(useIPv4, useIPv6 bool) ([]scanTarget, error) {
	ports := warp.ScanPorts
	if len(ports) == 0 {
		ports = []int{warp.DefaultPort}
	}

	var anchors, pool []netip.Addr
	if useIPv4 {
		for _, s := range warp.ScanSeedsV4 {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			anchors = append(anchors, ip)
		}
		groups := make([][]netip.Addr, 0, len(warp.ScanCIDRsV4))
		for _, cidr := range warp.ScanCIDRsV4 {
			hosts, err := enumerateCIDRv4(cidr)
			if err != nil {
				return nil, err
			}
			groups = append(groups, hosts)
		}
		interleavePush(groups, func(ip netip.Addr) { pool = append(pool, ip) })
	}
	if useIPv6 {
		for _, s := range warp.ScanSeedsV6 {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			anchors = append(anchors, ip)
		}
		groups := make([][]netip.Addr, 0, len(warp.ScanCIDRsV6))
		for _, cidr := range warp.ScanCIDRsV6 {
			hosts, err := sampleCIDRv6(cidr, scanWarpSampleV6, warp.ScanCIDRsV4)
			if err != nil {
				return nil, err
			}
			groups = append(groups, hosts)
		}
		interleavePush(groups, func(ip netip.Addr) { pool = append(pool, ip) })
	}

	seenIP := make(map[netip.Addr]struct{})
	ips := make([]netip.Addr, 0, len(anchors)+len(pool))
	for _, ip := range append(anchors, pool...) {
		if _, ok := seenIP[ip]; ok {
			continue
		}
		seenIP[ip] = struct{}{}
		ips = append(ips, ip)
	}

	var out []scanTarget
	seen := make(map[scanTarget]struct{})
	push := func(ip netip.Addr, port int) {
		t := scanTarget{ip: ip, port: port}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for wave := 0; wave < scanWarpPortWaves; wave++ {
		for idx, ip := range ips {
			push(ip, ports[(idx+wave)%len(ports)])
		}
	}
	return out, nil
}

func interleavePush(groups [][]netip.Addr, emit func(netip.Addr)) {
	maxLen := 0
	for _, g := range groups {
		if len(g) > maxLen {
			maxLen = len(g)
		}
	}
	for i := 0; i < maxLen; i++ {
		for _, g := range groups {
			if i < len(g) {
				emit(g[i])
			}
		}
	}
}

func enumerateCIDRv4(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %s: %w", cidr, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("not ipv4 cidr: %s", cidr)
	}
	addr4 := prefix.Addr().As4()
	base := binary.BigEndian.Uint32(addr4[:])
	hostBits := 32 - prefix.Bits()
	if hostBits <= 0 {
		return []netip.Addr{prefix.Addr()}, nil
	}
	if hostBits > 12 {
		return sampleCIDRv4(cidr, 140)
	}
	size := uint32(1) << hostBits
	if size <= 2 {
		return []netip.Addr{prefix.Addr()}, nil
	}
	out := make([]netip.Addr, 0, size-2)
	for off := uint32(1); off < size-1; off++ {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+off)
		out = append(out, netip.AddrFrom4(a))
	}
	return out, nil
}

func sampleCIDRv4(cidr string, n int) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %s: %w", cidr, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("not ipv4 cidr: %s", cidr)
	}
	addr4 := prefix.Addr().As4()
	base := binary.BigEndian.Uint32(addr4[:])
	hostBits := 32 - prefix.Bits()
	if hostBits <= 0 {
		return []netip.Addr{prefix.Addr()}, nil
	}
	size := uint32(1) << hostBits
	if size <= 2 {
		return []netip.Addr{prefix.Addr()}, nil
	}
	usable := size - 2
	want := uint32(n)
	if want > usable {
		want = usable
	}
	chosen := make(map[uint32]struct{}, want)
	out := make([]netip.Addr, 0, want)
	for uint32(len(out)) < want {
		off := 1 + uint32(rand.Intn(int(usable)))
		if _, ok := chosen[off]; ok {
			continue
		}
		chosen[off] = struct{}{}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+off)
		out = append(out, netip.AddrFrom4(a))
	}
	return out, nil
}

func sampleCIDRv6(cidr string, n int, v4CIDRs []string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %s: %w", cidr, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() {
		return nil, fmt.Errorf("not ipv6 cidr: %s", cidr)
	}
	if 128-prefix.Bits() == 0 {
		return []netip.Addr{prefix.Addr()}, nil
	}

	var v4nets []netip.Prefix
	for _, raw := range v4CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4nets = append(v4nets, p.Masked())
		}
	}

	base := prefix.Addr().As16()
	out := make([]netip.Addr, 0, n)
	for i := 0; i < n; i++ {
		var embedded uint32
		if len(v4nets) == 0 {
			embedded = rand.Uint32()
		} else {
			p := v4nets[rand.Intn(len(v4nets))]
			hostBits := 32 - p.Bits()
			a4 := p.Addr().As4()
			b := binary.BigEndian.Uint32(a4[:])
			if hostBits <= 0 {
				embedded = b
			} else {
				mask := uint32((uint64(1) << hostBits) - 1)
				embedded = b | (rand.Uint32() & mask)
			}
		}
		var full [16]byte
		copy(full[:], base[:])
		full[12] = byte(embedded >> 24)
		full[13] = byte(embedded >> 16)
		full[14] = byte(embedded >> 8)
		full[15] = byte(embedded)
		out = append(out, netip.AddrFrom16(full))
	}
	return out, nil
}

func ipv6Available() bool {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
	if err != nil {
		return false
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.ParseIP("2606:4700:d0::a29f:c001"), Port: 443}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = c.WriteTo([]byte{0}, dst)
	return err == nil
}
