package chrome

import (
	"context"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestPrivateCredentialRetirementProofAndNoReplay(t *testing.T) {
	for _, state := range []string{"dispatched", "notDispatched", "unknown"} {
		t.Run(state, func(t *testing.T) {
			g, p, ctx, count := controlFixtureVersion(t, 2, func() string { return state })
			cb := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
			ctx = auth.WithConsentBinding(ctx, cb)
			a, e := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
			if e != nil {
				t.Fatal(e)
			}
			c := g.controlChannel(a)
			fill, attempt := strings.Repeat("a", 64), strings.Repeat("b", 64)
			g.broker.mu.Lock()
			c.privateFlow = &credentialFlow{authority: a, binding: cb, fillAttempt: fill, submitAttempt: strings.Repeat("c", 64), submitState: "notDispatched"}
			c.privateCredentialAttempts = map[string]bool{fill: true}
			g.broker.mu.Unlock()
			allow := func(context.Context) error { return nil }
			proof, result, err := g.RetireVaultCredential(ctx, p, a, fill, attempt, allow)
			if result.DispatchState != state || count.Load() != 1 || (err != nil) != (state == "unknown") {
				t.Fatalf("retirement result: %s %v", result.DispatchState, err)
			}
			valid := g.VerifyCredentialRetirement(ctx, p, a, proof) == nil
			if valid != (state == "dispatched") {
				t.Fatal("unproved retirement accepted")
			}
			if g.VerifyCredentialRetirement(ctx, p, a, CredentialRetirementProof{}) == nil {
				t.Fatal("empty proof accepted")
			}
			if g.VerifyCredentialRetirement(auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "foreign", GrantID: "grant", Purpose: "private"}), p, a, proof) == nil {
				t.Fatal("foreign consent accepted")
			}
			if _, _, err = g.RetireVaultCredential(ctx, p, a, fill, strings.Repeat("d", 64), allow); err == nil || count.Load() != 1 {
				t.Fatal("retirement replayed")
			}
			if _, err = g.SubmitVaultCredential(ctx, p, a, fill, strings.Repeat("e", 64), allow); err == nil || count.Load() != 1 {
				t.Fatal("submit after retirement admitted")
			}
		})
	}
}

func TestPrivateCredentialRetirementRejectsInputUncertainty(t *testing.T) {
	for _, mode := range []string{"submitConfirmed", "submitUnknown", "unresolved", "poisoned", "foreignFill", "guard"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, count := controlFixtureVersion(t, 2)
			cb := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
			ctx = auth.WithConsentBinding(ctx, cb)
			a, e := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
			if e != nil {
				t.Fatal(e)
			}
			c := g.controlChannel(a)
			fill := strings.Repeat("a", 64)
			f := &credentialFlow{authority: a, binding: cb, fillAttempt: fill}
			if mode == "submitConfirmed" {
				f.submitConfirmed = true
			}
			if mode == "submitUnknown" {
				f.submitAttempt = strings.Repeat("c", 64)
				f.submitState = "unknown"
			}
			if mode == "poisoned" {
				f.poisoned = true
			}
			if mode == "foreignFill" {
				f.fillAttempt = strings.Repeat("f", 64)
			}
			g.broker.mu.Lock()
			c.privateFlow = f
			c.privateCredentialAttempts = map[string]bool{fill: true}
			if mode == "unresolved" {
				c.unknown["other"] = true
			}
			g.broker.mu.Unlock()
			guard := func(context.Context) error {
				if mode == "guard" {
					return auth.ErrUnauthorized
				}
				return nil
			}
			proof, result, err := g.RetireVaultCredential(ctx, p, a, fill, strings.Repeat("b", 64), guard)
			if err == nil || result.DispatchState != "notDispatched" || count.Load() != 0 || g.VerifyCredentialRetirement(ctx, p, a, proof) == nil {
				t.Fatal("unsafe retirement admitted")
			}
		})
	}
}
