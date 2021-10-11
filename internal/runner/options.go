package runner

import (
	"errors"
	"os"

	"github.com/projectdiscovery/collaborator/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// ParseOptions parses the command line flags provided by a user
func ParseOptions(options *types.Options) {

	// Read the inputs and configure the logging
	configureOutput(options)

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	if err := validateOptions(options); err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}
}

// configureOutput configures the output on the screen
func configureOutput(options *types.Options) {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

// validateOptions validates the configuration options passed
func validateOptions(options *types.Options) error {
	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}
	return nil
}
