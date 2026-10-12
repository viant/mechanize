package host

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestNativeSetupMetadataRequiresHumanAndClosedSelectors(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "setup-console", []string{"desktop:control", "consent:admin"})
	p.ClientID = "console"
	ctx := auth.WithPrincipal(context.Background(), p)
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}}
	if _, err := h.nativeBrowserSetupMetadata(ctx, p, json.RawMessage(`{"profileChannel":"p","browserInstance":"b"}`)); err == nil {
		t.Fatal("non-native caller admitted")
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"profileChannel":"p","browserInstance":"b","loadedDirectory":"/guessed"}`, `{"profileChannel":"p","browserInstance":"b","storageSHA256":"caller-digest"}`, `{"profileChannel":"p","browserInstance":"b","nativeHuman":true}`} {
		if _, err = h.nativeBrowserSetupMetadata(human, p, json.RawMessage(raw)); err == nil {
			t.Fatal("caller evidence accepted")
		}
	}
}
