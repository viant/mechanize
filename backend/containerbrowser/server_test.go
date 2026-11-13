package containerbrowser

import (
	"github.com/viant/mechanize/script"
	"testing"
)

func TestContainerCompileUsesCanonicalPolicy(t *testing.T) {
	h := &Host{Policy: script.Policy{AllowedSurfaces: map[string]bool{"https://example.test": true}, AllowMutation: true, Capabilities: BrowserCapabilities()}}
	for _, source := range []string{
		`web.tab(origin: "https://example.test").openOrigin()`,
		`web.tab(origin: "https://example.test").getById("query").fill("hello")`,
		`let value = web.tab(origin: "https://example.test").getById("query").read("value")`,
	} {
		if _, err := h.compile(&Source{Source: source}); err != nil {
			t.Fatalf("valid browser DSL: %v", err)
		}
	}
	for _, source := range []string{
		`app("com.example.app").getById("query").click()`,
		`web.tab(origin: "https://other.test").openOrigin()`,
		`web.tab(origin: "https://example.test").frame(name: "inner").getById("query").click()`,
	} {
		if _, err := h.compile(&Source{Source: source}); err == nil {
			t.Fatalf("unsupported scope accepted: %s", source)
		}
	}
	h.Policy.AllowMutation = false
	if _, err := h.compile(&Source{Source: `web.tab(origin: "https://example.test").getById("query").click()`}); err == nil {
		t.Fatal("mutation policy bypassed")
	}
}
