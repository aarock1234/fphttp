// Command observe records fphttp requests observed by tls.but.sh.
// It preserves the diagnostic payload without asserting browser equivalence.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aarock1234/fphttp/browser"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	options, err := parseOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}
	if options.catalog {
		return writeOutput(options.outputPath, browser.Catalog())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()

	report, observationErr := collectObservations(ctx, options)
	if observationErr != nil {
		report.Error = observationErr.Error()
	}
	if err := writeOutput(options.outputPath, report); err != nil {
		return errors.Join(observationErr, err)
	}

	return observationErr
}
