package main

import (
	"encoding/json"
	"fmt"

	http "github.com/aarock1234/fphttp"
)

type fingerprint struct {
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	AkamaiHash    string `json:"akamai_hash"`
	PeetPrintHash string `json:"peetprint_hash"`
}

func main() {
	client := &http.Client{
		Transport: &http.Transport{
			Fingerprint: http.Chrome(),
		},
	}

	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/clean", nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var f fingerprint
	if err = json.NewDecoder(resp.Body).Decode(&f); err != nil {
		panic(err)
	}

	b, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
