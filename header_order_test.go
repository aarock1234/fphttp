package http

import (
	"bytes"
	"testing"
)

func TestHeader_WriteSubsetOrdered(t *testing.T) {
	t.Run("headers are written in specified order", func(t *testing.T) {
		h := Header{
			"Accept":     {"text/html"},
			"Host":       {"example.com"},
			"User-Agent": {"Go-Test"},
		}
		order := []string{"User-Agent", "Host", "Accept"}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, nil, order, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "User-Agent: Go-Test\r\nHost: example.com\r\nAccept: text/html\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("unordered headers appended in sorted order", func(t *testing.T) {
		h := Header{
			"Zebra":      {"z"},
			"Accept":     {"text/html"},
			"Host":       {"example.com"},
			"User-Agent": {"Go-Test"},
		}
		order := []string{"Host"}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, nil, order, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "Host: example.com\r\n" +
			"Accept: text/html\r\n" +
			"User-Agent: Go-Test\r\n" +
			"Zebra: z\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("order keys not in header are skipped", func(t *testing.T) {
		h := Header{
			"Host": {"example.com"},
		}
		order := []string{"X-Missing", "Host", "X-Also-Missing"}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, nil, order, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "Host: example.com\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("excluded headers skipped even if in order", func(t *testing.T) {
		h := Header{
			"Host":       {"example.com"},
			"User-Agent": {"Go-Test"},
			"Accept":     {"text/html"},
		}
		order := []string{"Host", "User-Agent", "Accept"}
		exclude := map[string]bool{
			"User-Agent": true,
		}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, exclude, order, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "Host: example.com\r\nAccept: text/html\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("empty order falls back to sorted order", func(t *testing.T) {
		h := Header{
			"Zebra":  {"z"},
			"Accept": {"text/html"},
			"Host":   {"example.com"},
		}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, nil, nil, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "Accept: text/html\r\n" +
			"Host: example.com\r\n" +
			"Zebra: z\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("multiple values for a single key are all written", func(t *testing.T) {
		h := Header{
			"Accept": {"text/html", "application/json", "text/plain"},
			"Host":   {"example.com"},
		}
		order := []string{"Accept", "Host"}

		var buf bytes.Buffer
		err := h.writeSubsetOrdered(&buf, nil, order, nil)
		if err != nil {
			t.Fatalf("writeSubsetOrdered() error = %v", err)
		}

		want := "Accept: text/html\r\n" +
			"Accept: application/json\r\n" +
			"Accept: text/plain\r\n" +
			"Host: example.com\r\n"
		if got := buf.String(); got != want {
			t.Errorf("writeSubsetOrdered() =\n%q\nwant:\n%q", got, want)
		}
	})
}
