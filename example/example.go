package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	http "github.com/aarock1234/fphttp/v2"
)

type fingerprint struct {
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	AkamaiHash    string `json:"akamai_hash"`
	PeetPrintHash string `json:"peetprint_hash"`
}

func main() {
	if err := run(); err != nil {
		slog.Error("request failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	profile, err := http.NewProfile(http.BrowserChrome, http.PlatformWindows, http.Latest)
	if err != nil {
		return fmt.Errorf("create profile: %w", err)
	}

	client := http.NewClient(profile)
	client.Timeout = 15 * time.Second
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://tls.peet.ws/api/clean", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var f fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return fmt.Errorf("decode fingerprint: %w", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(f); err != nil {
		return fmt.Errorf("write fingerprint: %w", err)
	}

	return nil
}
