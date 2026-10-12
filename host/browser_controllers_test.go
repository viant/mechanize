package host

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"testing"
)

func TestNativeControllersRequiresHumanAndClosedRequest(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "console-user", []string{"desktop:control", "consent:admin"})
	p.ClientID = "console"
	ctx := auth.WithPrincipal(context.Background(), p)
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}}
	if _, err := h.nativeBrowserControllers(ctx, p, json.RawMessage(`{"nativeHuman":true}`)); err == nil {
		t.Fatal("caller claimed human authority")
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"profileChannel":"p","browserInstance":"b","action":"status","nativeHuman":true}`, `{"profileChannel":"p","browserInstance":"b","action":"configure","policy":{"enabled":true,"origins":["https://example.test/path"],"secret":"x"}}`, `{"profileChannel":"p","browserInstance":"b","action":"execute","javascript":"alert(1)"}`, `{} {}`} {
		if _, err := h.nativeBrowserControllers(human, p, json.RawMessage(raw)); err == nil {
			t.Fatal("untrusted request accepted")
		}
	}
}
