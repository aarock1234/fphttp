// Command observe records the requests an fphttp profile sends, as the
// tls.but.sh diagnostic endpoints see them. It preserves each diagnostic
// payload without asserting that it matches a real browser.
//
// The profile comes from NewProfile, so -browser, -platform, and -version
// accept what NewProfile accepts. A version newer than the newest supported
// release is observed with the newest release and recorded as a warning.
// With -catalog, observe writes the supported release catalog instead of
// sending requests.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
)

func main() {
	if err := run(); err != nil {
		slog.Error("observe failed", slog.Any("error", err))
		os.Exit(1)
	}
}

// run parses the flags, then writes either the catalog or a report of the
// observed requests. A report is written even when an observation fails, so
// it records what was seen up to the failure.
func run() error {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if opts.catalog {
		return writeOutput(opts.outputPath, catalogEntries())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	report, observationErr := collectObservations(ctx, opts)
	if observationErr != nil {
		report.Error = observationErr.Error()
	}

	if err := writeOutput(opts.outputPath, report); err != nil {
		return errors.Join(observationErr, err)
	}

	return observationErr
}
