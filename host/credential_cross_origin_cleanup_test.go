package host

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	gateway "github.com/viant/mechanize/mcp"
)

func TestNewOriginRetiresOnlySameClientAbsentCredentialSource(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		for _, absent := range []bool{false, true} {
			name := "present"
			if absent {
				name = "absent"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				credentialHostFixtureFlow(t, mode, credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
					if _, err := h.CredentialApply(ctx, p, ref); err != nil && mode != "unknown" {
						t.Fatal(err)
					}
					before, attempts := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
					fills, submits, vaultReads := f.fills, f.submits, reads.Load()
					checks := 0
					f.scopeAbsent = func(c context.Context, source chrome.CredentialProtectionScope) error {
						checks++
						actor, err := auth.FromContext(c)
						if err != nil || actor.ClientID != p.ClientID || source.Origin != input.Surface.Origin || source.PreparationID != ref.PreparationID {
							t.Fatal("source or actor changed")
						}
						if !absent {
							return errPrivateCredential
						}
						return nil
					}
					bound := auth.WithConsentBinding(ctx, f.session.consent)
					err := h.credentials.retireAbsentCredentialSources(bound, p, "https://unrelated.invalid")
					after, rows := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
					if absent {
						if err != nil || after.ProtectionState != "closed" || checks < 2 {
							t.Fatal("proved absent source retained", err)
						}
					} else if !errors.Is(err, errOtherCredentialScopeHeld) || after != before {
						t.Fatal("live source barrier changed", err)
					}
					if len(rows) != len(attempts) {
						t.Fatal("input history changed")
					}
					for i, row := range rows {
						original := attempts[i]
						row.ProtectionState, row.Revision, row.UpdatedAt = original.ProtectionState, original.Revision, original.UpdatedAt
						if row != original {
							t.Fatal("original dispatch knowledge changed")
						}
					}
					if f.fills != fills || f.submits != submits || reads.Load() != vaultReads {
						t.Fatal("cleanup accessed credentials or repeated input")
					}
				}})
			})
		}
	}
}
