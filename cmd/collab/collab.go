package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/collaborator/internal/runner"
	"github.com/projectdiscovery/collaborator/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

var (
	cfgFile string
	options = &types.Options{}
)

func main() {
	readConfig()

	runner.ParseOptions(options)

	collabRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup close handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			collabRunner.Close()
			os.Exit(0)
		}()
	}()

	err = collabRunner.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run collab: %s\n", err)
	}
}

func readConfig() {
	set := goflags.NewFlagSet()
	set.Marshal = true
	set.SetDescription(`Collaborator is a tool to fetch and print the interactions from burp collaborator`)
	set.StringVar(&cfgFile, "config", "", "Collaborator configuration file")
	set.StringVar(&options.BIID, "biid", "", "burp collaborator unique id")
	set.BoolVar(&options.Silent, "silent", false, "Don't print the banner")
	set.BoolVar(&options.Version, "version", false, "Show version of collaborator")
	set.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	set.IntVar(&options.Interval, "interval", 2, "Polling interval in seconds")
	set.StringVar(&options.HTTPMessage, "message-http", types.DefaultHTTPMessage, "HTTP Message")
	set.StringVar(&options.DNSMessage, "message-dns", types.DefaultDNSMessage, "DNS Message")
	set.StringVar(&options.SMTPMessage, "message-smtp", types.DefaultSMTPMessage, "SMTP Message")
	set.StringVar(&options.CLIMessage, "message-cli", types.DefaultCLIMessage, "CLI Message")

	_ = set.Parse()

	if cfgFile != "" {
		if err := set.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
}
