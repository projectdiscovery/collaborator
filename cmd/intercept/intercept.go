package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/collaborator/biid"
	"github.com/projectdiscovery/gologger"
)

// Options to handle intercept
type Options struct {
	InterceptBIIDTimeout int
}

func main() {
	var options Options
	flag.IntVar(&options.InterceptBIIDTimeout, "intercept-biid-timeout", 600, "Automatic BIID intercept Timeout")

	// Setup close handler
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			os.Exit(0)
		}()
	}()

	if os.Getuid() != 0 {
		gologger.Fatal().Msgf("Intercept needs to run as root to access raw sockets")
	}
	gologger.Print().Msgf("Attempting to intercept BIID")
	// attempt to retrieve biid
	interceptedBiid, err := biid.Intercept(time.Duration(options.InterceptBIIDTimeout) * time.Second)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
	if interceptedBiid == "" {
		gologger.Fatal().Msgf("BIID not found")
	}
	gologger.Print().Msgf("BIID found: %s", interceptedBiid)
}
