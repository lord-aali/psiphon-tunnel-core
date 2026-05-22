package main

import (
	"context"
	"flag"
	"github.com/bepass-org/psiphon/app"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func usage() {
	log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
	log.Println("Usage: psiphon [-b addr:port] [-p proxy]")
	flag.PrintDefaults()
}

func main() {
	var (
		bindAddress      = flag.String("b", "127.0.0.1:10808", "socks bind address")
		proxy            = flag.String("p", "null", "Upstream proxy url [format: socks5://127.0.0.1:1080].")
		workingDirectory = flag.String("d", "./", "Working directory")
		country          = flag.String("c", "AT", "Country code (valid values: [AT BE BG BR CA CH CZ DE DK EE ES FI FR GB HR HU IE IN IT JP LV NL NO PL PT RO RS SE SG SK UA US])")
		config           = flag.String("config", "null", "Psiphon config file. (if present all the following parameters except 'd' will be ignored.)")
	)

	flag.Usage = usage
	flag.Parse()

	sigchan := make(chan os.Signal)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		log.Println("Unofficial version of Psiphon, made by Ali Rahimi.")
		err := app.RunPsiphon(*bindAddress, *proxy, *country, *workingDirectory, *config, ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-sigchan
	cancel()
}
