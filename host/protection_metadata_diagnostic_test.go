package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func TestProtectionMetadataFailureIsNotReportedAsVaultKeyFailure(t *testing.T) {
	p, err := auth.NewPrincipal("fixture:issuer", "", "public-observer", []string{"desktop:observe", "desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "fixture-native-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	metadataParent := filepath.Join(t.TempDir(), "unavailable-metadata-parent")
	if err := os.WriteFile(metadataParent, []byte("synthetic storage fault"), 0600); err != nil {
		t.Fatal(err)
	}
	builder, err := durable.New(durable.Options{SourceRoot: filepath.Join(t.TempDir(), "missing-source"), StorageRoot: filepath.Join(metadataParent, "storage"), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("metadata failure dispatched input")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(context.Background())
	h := &Host{durable: builder}
	for _, mutation := range []bool{false, true} {
		lease, e := h.AuthorizeOperation(ctx, p, model.Surface{Kind: "web", Origin: "https://public.invalid", TabID: "opaque-tab"}, mutation, consent.Observe)
		if lease != nil {
			t.Fatal("unreadable protections created an exposure lease")
		}
		var diagnostic *model.MechanizeError
		if !errors.As(e, &diagnostic) || diagnostic.Code != "protectionMetadataUnavailable" || diagnostic.Stage != "admission" || diagnostic.DispatchState != "notDispatched" || diagnostic.EffectState != "none" {
			t.Fatal("pre-input metadata failure lost typed diagnostic")
		}
		if errors.Is(e, vault.ErrUnavailable) || strings.Contains(e.Error(), "vault key") {
			t.Fatal("metadata failure falsely reported a key problem")
		}
		if !strings.Contains(diagnostic.Message, "bind/") {
			t.Fatal("closed metadata phase lost")
		}
	}
}
