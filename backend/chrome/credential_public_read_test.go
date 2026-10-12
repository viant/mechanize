package chrome

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

func publicReadFixture(t *testing.T) (*readFixture, *channel, context.Context) {
	f := newReadFixture(t)
	b := f.g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	c.credentialPublicReadVersion = 1
	c.protectionScopeVersion = 1
	c.documents = nil
	// Retained inactive private evidence must survive classification/read; it is
	// neither a source-absence proof nor a new credential delivery.
	c.privacy = &credentialPrivacyState{}
	b.mu.Unlock()
	ctx := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: "grant", SessionID: "session", Purpose: "public read"})
	return f, c, ctx
}
func TestCredentialPublicReadExactContextAndNoInputAuthority(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	target := readTarget().Surface
	if _, err := f.g.Observe(ctx, f.p, target); err == nil {
		t.Fatal("protected source was publicly selectable")
	}
	verified, err := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.g.Observe(verified, f.p, target); err != nil {
		t.Fatal("classified observation", err)
	}
	pin, err := f.g.PinReadDocument(verified, f.p, target)
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := f.g.ReadPinned(verified, f.p, pin, readTarget(), "value", nil)
	if err != nil || value.String != "independent-result" {
		t.Fatal("classified read", err)
	}
	b := f.g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	permit := verified.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
	if len(c.documents) != 0 || c.privacy == nil || c.privacy.active || f.mutations.Load() != 0 {
		t.Fatal("classification changed source/global authority")
	}
	for _, action := range []string{"executor.acquire", "executor.retire", "element.fill", "element.press", "browser.navigate", "browser.activate", "receipt.query"} {
		if publicReadPermitLocked(verified, c, Command{Action: action, Identity: permit.document.Identity}, false) != nil {
			t.Fatal("read proof accepted action", action)
		}
	}
	if publicReadPermitLocked(verified, c, Command{Action: "read", Identity: permit.document.Identity}, true) != nil {
		t.Fatal("mutation accepted")
	}
}
func TestCredentialPublicReadRejectsMalformedOrPrivateClassification(t *testing.T) {
	for _, mode := range []string{"private", "wrongDocument", "zeroGeneration", "foreignProfile", "missingProof", "wrongHash", "notPublic"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := publicReadFixture(t)
			f.publicReadMode.Store(mode)
			if _, err := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface); err == nil {
				t.Fatal("invalid proof accepted")
			}
			f.g.broker.mu.Lock()
			defer f.g.broker.mu.Unlock()
			if c.privacy == nil || len(c.documents) != 0 || f.mutations.Load() != 0 {
				t.Fatal("invalid proof changed authority")
			}
		})
	}
}
func TestCredentialPublicReadInvalidatesExactProvenance(t *testing.T) {
	for _, mode := range []string{"actor", "client", "consent", "expired", "channel", "process", "unknown", "privateInput", "generation"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := publicReadFixture(t)
			verified, err := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
			if err != nil {
				t.Fatal(err)
			}
			permit := verified.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
			command := Command{Action: "observe", Identity: permit.document.Identity}
			b := f.g.broker
			b.mu.Lock()
			defer b.mu.Unlock()
			switch mode {
			case "actor":
				actor := f.p
				actor.Namespace = "other"
				verified = auth.WithPrincipal(verified, actor)
			case "client":
				actor := f.p
				actor.ClientID = "other"
				verified = auth.WithPrincipal(verified, actor)
			case "consent":
				verified = auth.WithConsentBinding(verified, auth.ConsentBinding{GrantID: "other", SessionID: "session", Purpose: "public read"})
			case "expired":
				permit.expires = time.Now().Add(-time.Second)
			case "channel":
				c.epoch += "changed"
			case "process":
				copy := *c.processEvidence
				copy.ChromeParent.StartToken = "other"
				c.processEvidence = &copy
			case "unknown":
				c.unknown["unknown-input"] = true
			case "privateInput":
				c.privateAdvance = &credentialAdvancePending{}
			case "generation":
				command.Identity.Generation++
			}
			if publicReadPermitLocked(verified, c, command, false) != nil {
				t.Fatal("changed provenance accepted")
			}
		})
	}
}

func TestCredentialPublicReadExpiredReplyKeepsPrivateChannelAndDiscardsValues(t *testing.T) {
	f, c, ctx := publicReadFixture(t)
	verified, err := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
	if err != nil {
		t.Fatal(err)
	}
	permit := verified.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
	permit.expires = time.Now().Add(25 * time.Millisecond)
	f.publicReadDelay.Store(70)
	if observation, err := f.g.Observe(verified, f.p, readTarget().Surface); err == nil || len(observation.Nodes) != 0 {
		t.Fatal("expired classification produced public content")
	}
	f.g.broker.mu.Lock()
	defer f.g.broker.mu.Unlock()
	if c.conn != permit.conn || c.privacy == nil || len(c.documents) != 0 || len(c.unknown) != 0 || f.mutations.Load() != 0 {
		t.Fatal("late read reply damaged retained private state")
	}
}

func TestCredentialPublicReadVersionedMarkerAndOrdinaryControlRemainSeparate(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f, c, ctx := publicReadFixture(t)
			f.g.broker.mu.Lock()
			c.credentialPublicReadVersion = version
			f.g.broker.mu.Unlock()
			verified, err := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
			if version == 3 {
				if err == nil || f.publicReadMarked.Load() != 0 {
					t.Fatal("unsupported peer admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.g.Observe(verified, f.p, readTarget().Surface); err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if version == 2 {
				want = 1
			}
			if f.publicReadMarked.Load() != want {
				t.Fatal("incorrect negotiated marker", f.publicReadMarked.Load())
			}
			permit := verified.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
			f.g.broker.mu.Lock()
			c.privacy = nil
			c.documents = []Document{permit.document}
			f.g.broker.mu.Unlock()
			admission, err := f.g.AdmitControlWithStatus(ctx, f.p, readTarget().Surface)
			if err != nil || admission.Authority.Lease.ID == "" || f.lastValidationMarked.Load() || f.mutations.Load() != 0 {
				t.Fatal("ordinary control inherited public read authority", err)
			}
			before := f.publicReadMarked.Load()
			if _, err = f.g.broker.call(ctx, c, Command{PublicRead: true, Action: "executor.validate", Identity: permit.document.Identity}, false); err == nil {
				t.Fatal("caller marker minted a permit")
			}
			permit.expires = time.Now().Add(-time.Second)
			if _, err = f.g.broker.call(verified, c, Command{Action: "executor.validate", Identity: permit.document.Identity}, false); err == nil {
				t.Fatal("expired permit fell back to ordinary validation")
			}
			if f.publicReadMarked.Load() != before || f.mutations.Load() != 0 {
				t.Fatal("rejected proof dispatched work")
			}
		})
	}
}

func TestCredentialPublicReadContextCannotAdmitControl(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "typedNil"} {
		t.Run(mode, func(t *testing.T) {
			f, c, base := publicReadFixture(t)
			verified, err := f.g.WithVerifiedCredentialPublicRead(base, f.p, readTarget().Surface)
			if err != nil {
				t.Fatal(err)
			}
			permit := verified.Value(credentialPublicReadKey{}).(*credentialPublicReadPermit)
			f.g.broker.mu.Lock()
			c.privacy = nil
			c.documents = []Document{permit.document}
			if mode == "expired" {
				permit.expires = time.Now().Add(-time.Second)
			}
			f.g.broker.mu.Unlock()
			if mode == "typedNil" {
				verified = context.WithValue(base, credentialPublicReadKey{}, (*credentialPublicReadPermit)(nil))
			}
			before := f.acquireCalls.Load()
			admission, err := f.g.AdmitControlWithStatus(verified, f.p, readTarget().Surface)
			if err == nil || admission.Created || admission.Authority.Lease.ID != "" || f.acquireCalls.Load() != before || f.mutations.Load() != 0 {
				t.Fatal("read context admitted control or dispatched work", admission, err)
			}
			failure, ok := err.(*model.MechanizeError)
			if !ok || failure.Code != "publicReadOnly" || failure.DispatchState != "notDispatched" || failure.EffectState != "none" {
				t.Fatal("read-only rejection lost closed dispatch semantics", err)
			}
			// The original operation context remains usable; rejecting a derived read
			// context must neither strip its permit nor contaminate the base authority.
			admission, err = f.g.AdmitControlWithStatus(base, f.p, readTarget().Surface)
			if err != nil || !admission.Confirmed || admission.Authority.Lease.ID == "" || f.acquireCalls.Load() != before+1 || f.mutations.Load() != 0 {
				t.Fatal("base control context did not remain independent", admission, err)
			}
		})
	}
}
