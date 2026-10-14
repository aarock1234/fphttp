package main

import (
	"bytes"
	"fmt"
	"go/format"
	"text/template"
	"time"

	_ "embed" // embeds the generated file template
)

//go:embed builds.go.tmpl
var buildsTemplateText string

// buildsTemplate renders builds_gen.go from a list of buildRow values.
var buildsTemplate = template.Must(template.New("builds").Parse(buildsTemplateText))

// buildRow is one row of the generated builds table, with every field in
// its Go source form.
type buildRow struct {
	Browser  string
	Platform string
	Version  string
	Engine   string
	Released string
}

// renderBuilds returns the gofmt-formatted source of builds_gen.go listing
// builds in the given order.
func renderBuilds(builds []release) ([]byte, error) {
	rows := make([]buildRow, 0, len(builds))
	for _, build := range builds {
		rows = append(rows, buildRow{
			Browser:  build.browser.String(),
			Platform: build.platform.String(),
			Version:  build.version,
			Engine:   build.engine,
			Released: build.released.UTC().Format(time.DateOnly),
		})
	}

	var source bytes.Buffer
	if err := buildsTemplate.Execute(&source, rows); err != nil {
		return nil, fmt.Errorf("render builds: %w", err)
	}

	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format builds: %w", err)
	}

	return formatted, nil
}
