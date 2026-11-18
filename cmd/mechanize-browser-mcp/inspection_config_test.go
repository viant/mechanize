package main

import (
	"strings"
	"testing"
)

func TestInspectionConfigRequiresRestrictedOrigins(t *testing.T) {
	for _, input := range []string{`{"inspectionOnly":true}`, `{"inspectionOnly":true,"allowAllWeb":false}`, `{"inspectionOnly":true,"allowAllWeb":true,"allowedOrigins":["https://site.example"]}`} {
		if _, err := decodeConfig(strings.NewReader(input)); err == nil {
			t.Fatal("unrestricted inspection accepted")
		}
	}
	c, err := decodeConfig(strings.NewReader(`{"inspectionOnly":true,"allowAllWeb":false,"allowedOrigins":["https://site.example"]}`))
	if err != nil || !c.AllowMutation {
		t.Fatal("navigation must remain available", err)
	}
}

func TestNetworkRuleValidation(t *testing.T) {
	for _, rule := range []string{
		`{"origin":"https://metrics.example/path","path":"/collect","parameters":{}}`,
		`{"origin":"https://metrics.example","path":"/collect?secret=x","parameters":{}}`,
		`{"origin":"https://metrics.example","path":"/collect","parameters":{"order":"raw"}}`,
	} {
		if _, err := decodeConfig(strings.NewReader(`{"networkRules":[` + rule + `]}`)); err == nil {
			t.Fatal("invalid network rule accepted")
		}
	}
	_, err := decodeConfig(strings.NewReader(`{"networkRules":[{"origin":"https://metrics.example","path":"/collect","parameters":{"amount":"value","order":"presence"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
}
