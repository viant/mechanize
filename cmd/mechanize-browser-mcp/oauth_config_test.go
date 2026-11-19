package main

import (
	"context"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestOAuthOnlyConfiguration(t *testing.T) {
	for _, input := range []string{`{}`, `{"identityPolicy":{"requiredScopes":["browser:use"]}}`, `{"identityPolicy":{"clients":{"client":"Client"}}}`} {
		c, err := decodeConfig(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.newVerifier(context.Background()); err == nil {
			t.Fatal("OAuth policy not required")
		}
	}
	if _, err := decodeConfig(strings.NewReader(`{"bearerTokenFile":"/old-service-secret"}`)); err == nil {
		t.Fatal("legacy service secret configuration accepted")
	}
	c := config{IdentityPolicy: auth.Policy{Clients: map[string]string{"client": "Client"}, RequiredScopes: []string{" "}}}
	if _, err := c.newVerifier(context.Background()); err == nil {
		t.Fatal("blank scope accepted")
	}
}
