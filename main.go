package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bepass-org/psiphon/app"
	"github.com/bepass-org/psiphon/masque"
)

func usage() {
	log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
	log.Println("Usage: psiphon [-b addr:port] [-c country] [-p proxy] [-wo|-mo|-mp|-pm|-pw] [-masque-h3] [-masque-smart] [-masque-fragment] [-masque-sni sni] [-masque-endpoint ip:port] [-warp-endpoint ip:port] [-scan-masque|-scan-warp] [-list]")
	flag.PrintDefaults()
}

func showAppVersion() {
	log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
	log.Println("Project link: https://github.com/lord-aali/psiphon-tunnel-core")
	log.Println("version: 1.0.2-alpha")
	os.Exit(0)
}

func main() {
	var (
		bindAddress      = flag.String("b", "127.0.0.1:10808", "socks bind address")
		proxy            = flag.String("p", "null", "Upstream SOCKS5 proxy url [format: socks5://127.0.0.1:1080].")
		workingDirectory = flag.String("d", "./", "Working directory")
		country          = flag.String("c", "US", "Country code (e.g., US, DE, JP). Use -list to see available values.")
		config           = flag.String("config", "null", "Psiphon config file. (if present input parameters except 'd' may be overridden.)")
		listCountries    = flag.Bool("list", false, "List available egress countries from the local data store")
		warpOnly         = flag.Bool("wo", false, "Enable Cloudflare WARP (WireGuard) only")
		masqueOnly       = flag.Bool("mo", false, "Enable Cloudflare MASQUE only")
		masquePsiphon    = flag.Bool("mp", false, "Enable Cloudflare MASQUE over Psiphon")
		psiphonMasque    = flag.Bool("pm", false, "Enable Psiphon over Cloudflare MASQUE")
		psiphonWarp      = flag.Bool("pw", false, "Enable Psiphon over Cloudflare WARP (WireGuard)")
		masqueH3         = flag.Bool("masque-h3", false, "Use MASQUE HTTP/3 (QUIC) instead of HTTP/2 (default endpoint "+app.MasqueDefaultH3Endpoint+")")
		masqueSmart      = flag.Bool("masque-smart", false, "Prefer MASQUE HTTP/3, fall back to HTTP/2 (TLS fragment only if SNI is blocked), and auto-scan an endpoint if needed")
		masqueFragment   = flag.Bool("masque-fragment", false, "Fragment MASQUE HTTP/2 TLS ClientHello (TCP only)")
		masqueFragSize   = flag.String("masque-fragment-size", "16-32", "MASQUE HTTP/2 fragment size range in bytes")
		masqueFragDelay  = flag.String("masque-fragment-delay", "2-10", "MASQUE HTTP/2 fragment delay range in milliseconds")
		masqueSNI        = flag.String("masque-sni", "", "Override MASQUE TLS SNI (default: "+app.MasqueDefaultSNI+")")
		masqueEndpoint   = flag.String("masque-endpoint", "", "Override MASQUE endpoint as host:port (IPv6 as [addr]:port; default H2: "+app.MasqueDefaultEndpoint+", H3: "+app.MasqueDefaultH3Endpoint+")")
		warpEndpoint     = flag.String("warp-endpoint", "", "Override WARP WireGuard endpoint as host:port (IPv6 as [addr]:port; default: profile endpoint)")
		scanMasque       = flag.Bool("scan-masque", false, "Aether-style MASQUE scan (seeds, sampled CIDRs, ports, data-plane); add -masque-h3 for HTTP/3; write scan-masque.csv")
		scanWarp         = flag.Bool("scan-warp", false, "Aether-style WARP scan (seeds, sampled CIDRs, rotated UDP ports, handshake); write scan-warp.csv")
		showVersion      = flag.Bool("version", false, "Show version")
	)

	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		showAppVersion()
	}

	enabled := 0
	if *warpOnly {
		enabled++
	}
	if *masqueOnly {
		enabled++
	}
	if *masquePsiphon {
		enabled++
	}
	if *psiphonMasque {
		enabled++
	}
	if *psiphonWarp {
		enabled++
	}
	if enabled > 1 {
		log.Fatal("flags -wo, -mo, -mp, -pm, and -pw are mutually exclusive")
	}
	if *scanMasque && *scanWarp {
		log.Fatal("flags -scan-masque and -scan-warp are mutually exclusive")
	}

	if *listCountries {
		countries, err := app.ListAvailableCountries(*workingDirectory, *config)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(app.FormatCountryList(countries))
		return
	}

	if *scanMasque || *scanWarp {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-sigchan
			cancel()
		}()
		log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
		var err error
		if *scanMasque {
			err = app.RunMasqueScan(*workingDirectory, *masqueSNI, *masqueH3, ctx)
		} else {
			err = app.RunWarpScan(*workingDirectory, ctx)
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	mode := app.ModePsiphonOnly
	switch {
	case *warpOnly:
		mode = app.ModeWarpOnly
	case *masqueOnly:
		mode = app.ModeMasqueOnly
	case *masquePsiphon:
		mode = app.ModeMasquePsiphon
	case *psiphonMasque:
		mode = app.ModePsiphonMasque
	case *psiphonWarp:
		mode = app.ModePsiphonWarp
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	fragment, err := masque.ParseFragmentConfig(*masqueFragment, *masqueFragSize, *masqueFragDelay)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
		err := app.Run(*bindAddress, *proxy, *country, *workingDirectory, *config, mode, *masqueSNI, *masqueEndpoint, *warpEndpoint, *masqueH3, *masqueSmart, fragment, ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-sigchan
	cancel()
}
