package browser

import (
	_ "embed"
	"encoding/json"
	"fmt"

	http "github.com/aarock1234/fphttp/v2"
)

//go:embed data/brave.json
var braveData []byte

type braveDefinition struct {
	Version       string             `json:"version"`
	EngineVersion string             `json:"engine_version"`
	Platform      http.Platform      `json:"platform"`
	Chromium      chromiumDefinition `json:"chromium"`
	Sources       []Source           `json:"sources"`
}

var braveDefinitions = loadBraveDefinitions()

func loadBraveDefinitions() map[string]braveDefinition {
	var definitions []braveDefinition
	if err := json.Unmarshal(braveData, &definitions); err != nil {
		panic(fmt.Sprintf("browser: invalid Brave definitions: %v", err))
	}
	indexed := make(map[string]braveDefinition, len(definitions))
	for _, definition := range definitions {
		indexed[string(definition.Platform)+"/"+definition.Version] = definition
	}

	return indexed
}

func chromiumDefinitionForDescriptor(descriptor Descriptor) (chromiumDefinition, bool) {
	switch descriptor.Browser {
	case http.BrowserChrome:
		definition, found := chromiumDefinitions[string(descriptor.Platform)+"/"+descriptor.Version]

		return definition, found
	case http.BrowserEdge:
		if descriptor.Variant == "chromium-source-assumption" {
			return chromiumFamily(descriptor.Platform, descriptor.EngineVersion)
		}
	case http.BrowserBrave:
		definition, found := braveDefinitions[string(descriptor.Platform)+"/"+descriptor.Version]
		if found {
			return definition.Chromium, true
		}
	}

	return chromiumDefinition{}, false
}
