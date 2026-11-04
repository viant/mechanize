package chrome

import (
	"context"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestConfirmedCredentialAdvanceSurvivesEmptyPriorInventory(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
	ctx = auth.WithConsentBinding(ctx, binding)
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	fill, submit := strings.Repeat("a", 64), strings.Repeat("b", 64)
	g.broker.mu.Lock()
	c.privateFlow = &credentialFlow{authority: a, fillAttempt: fill, binding: binding}
	c.privateCredentialAttempts = map[string]bool{fill: true}
	c.protectionSources = map[string]CredentialProtectionScope{"source": {Identity: a.Document.Identity, Origin: a.Document.Origin}}
	g.broker.mu.Unlock()
	allow := func(context.Context) error { return nil }
	result, err := g.SubmitVaultCredential(ctx, p, a, fill, submit, allow)
	if err != nil || result.DispatchState != "dispatched" {
		t.Fatal("fixture submit failed", err)
	}
	g.broker.mu.Lock()
	// A prior incomplete inventory can erase the public list. The next complete
	// inventory omits the quarantined document; its private lineage still exists.
	c.documents = nil
	retainProtectedInventoryLocked(c, nil)
	c.inventoryComplete = true
	g.broker.mu.Unlock()
	next, err := g.AdvanceVaultCredential(ctx, p, a, submit, allow)
	if err != nil || next.Stage != "password" {
		t.Fatal("confirmed private lineage lost during inventory refresh", err)
	}
	if count.Load() != 1 {
		t.Fatal("inventory recovery replayed credential input")
	}
	if g.VerifyControl(ctx, p, a) == nil {
		t.Fatal("old authority survived transition")
	}
}

func TestInventoryCannotInventPrivateContinuation(t *testing.T) {
	for _, mode := range []string{"confirmed", "unknown", "unconfirmed", "poisoned", "retired", "retiring", "badAttempt", "noProtection", "foreignOrigin", "foreignTab", "foreignDocument", "foreignFrame", "foreignChannel"} {
		t.Run(mode, func(t *testing.T) {
			d := Document{Identity: Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 7, FrameID: 0, DocumentID: "source", Generation: 2}, Origin: "https://fixture.test"}
			f := &credentialFlow{authority: ControlAuthority{Document: d}, submitConfirmed: true, submitState: "dispatched", submitAttempt: strings.Repeat("a", 64)}
			source := CredentialProtectionScope{Identity: d.Identity, Origin: d.Origin}
			switch mode {
			case "unknown":
				f.submitState = "unknown"
			case "unconfirmed":
				f.submitConfirmed = false
			case "poisoned":
				f.poisoned = true
			case "retired":
				f.retired = true
			case "retiring":
				f.retireAttempt = "retirement"
			case "badAttempt":
				f.submitAttempt = "missing"
			case "foreignOrigin":
				source.Origin = "https://other.test"
			case "foreignTab":
				source.Identity.TabID++
			case "foreignDocument":
				source.Identity.DocumentID = "other"
			case "foreignFrame":
				source.Identity.FrameID++
			case "foreignChannel":
				source.Identity.ProfileChannel = "other"
			}
			c := &channel{privateFlow: f, protectionSources: map[string]CredentialProtectionScope{"source": source}}
			if mode == "noProtection" {
				c.protectionSources = nil
			}
			retainProtectedInventoryLocked(c, nil)
			if mode == "confirmed" {
				if len(c.documents) != 1 || c.documents[0] != d {
					t.Fatal("original source not retained exactly")
				}
				retainProtectedInventoryLocked(c, c.documents)
				if len(c.documents) != 1 {
					t.Fatal("source duplicated on repeated inventory")
				}
			} else if len(c.documents) != 0 {
				t.Fatal("unqualified source resurrected")
			}
		})
	}
}
