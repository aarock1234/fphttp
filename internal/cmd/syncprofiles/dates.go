package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// longDateLayout is the "October 8, 2026" form used by Microsoft and Apple
// release notes.
const longDateLayout = "January 2, 2006"

// window is the range of publication times included in the generated table:
// from midnight UTC on the since date up to, but excluding, midnight UTC
// after the through date.
type window struct {
	since time.Time
	until time.Time
}

// parseWindow parses the -since and -through dates.
func parseWindow(since, through string) (window, error) {
	first, err := time.Parse(time.DateOnly, since)
	if err != nil {
		return window{}, fmt.Errorf("parse -since: %w", err)
	}

	last, err := time.Parse(time.DateOnly, through)
	if err != nil {
		return window{}, fmt.Errorf("parse -through: %w", err)
	}

	if first.After(last) {
		return window{}, errors.New("-since must not be after -through")
	}

	return window{
		since: first,
		until: last.AddDate(0, 0, 1),
	}, nil
}

// includes reports whether a release published at released falls in w.
func (w window) includes(released time.Time) bool {
	return !released.Before(w.since) && released.Before(w.until)
}

// parseLongDate parses a date such as "October 8, 2026", tolerating extra
// whitespace between its words.
func parseLongDate(text string) (time.Time, error) {
	return time.Parse(longDateLayout, strings.Join(strings.Fields(text), " "))
}

// warnUnreadableDate logs a release that a feed lists with a date this tool
// cannot parse. The caller skips the release, so a date format change shows
// up in the log instead of silently shrinking the generated table.
func warnUnreadableDate(feed, version string, err error) {
	slog.Warn("skipping release with an unreadable date",
		slog.String("feed", feed),
		slog.String("version", version),
		slog.Any("error", err),
	)
}
