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
)

func usage() {
	log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
	log.Println("Usage: psiphon [-b addr:port] [-c country] [-p proxy] [-wo|-mo|-mp] [-list]")
	flag.PrintDefaults()
}

func showAppVersion() {
	log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
	log.Println("Project link: https://github.com/lord-aali/psiphon-tunnel-core")
	log.Println("version: 1.0.0-alpha")
	os.Exit(0)
}

func main() {
	var (
		bindAddress      = flag.String("b", "127.0.0.1:10808", "socks bind address")
		proxy            = flag.String("p", "null", "Upstream SOCKS5 proxy url [format: socks5://127.0.0.1:1080].")
		workingDirectory = flag.String("d", "./", "Working directory")
		country          = flag.String("c", "AT", "Country code (e.g., US, DE, JP). Use -list to see available values.")
		config           = flag.String("config", "null", "Psiphon config file. (if present input parameters except 'd' may be overridden.)")
		listCountries    = flag.Bool("list", false, "List available egress countries from the local data store")
		warpOnly         = flag.Bool("wo", false, "Enable Cloudflare WARP (WireGuard) only")
		masqueOnly       = flag.Bool("mo", false, "Enable Cloudflare MASQUE (HTTP/2) only")
		masquePsiphon    = flag.Bool("mp", false, "Enable Cloudflare MASQUE (HTTP/2) over Psiphon")
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
	if enabled > 1 {
		log.Fatal("flags -wo, -mo, and -mp are mutually exclusive")
	}

	if *listCountries {
		countries, err := app.ListAvailableCountries(*workingDirectory, *config)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(app.FormatCountryList(countries))
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
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
		err := app.Run(*bindAddress, *proxy, *country, *workingDirectory, *config, mode, ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-sigchan
	cancel()
}
