package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKnownPressSourceRetirementRequiresOriginalReceiptAndLease(t *testing.T) {
	for _, kind := range []string{"known", "unknown", "wrongLease", "wrongFingerprint", "otherAction"} {
		t.Run(kind, func(t *testing.T) {
			g, p, ctx, _ := controlFixtureVersion(t, 2)
			a, e := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if e != nil {
				t.Fatal(e)
			}
			b := g.broker
			c := g.controlChannel(a)
			id := strings.Repeat("a", 64)
			original := Command{Action: "element.press", Identity: a.Document.Identity, AttemptID: id, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64)}
			receipt := Reply{AttemptID: id, Identity: original.Identity, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: original.FingerprintSHA256, DispatchState: "dispatched", EffectState: "unverified"}
			switch kind {
			case "unknown":
				receipt.DispatchState = "unknown"
				receipt.EffectState = "unknown"
			case "wrongLease":
				copy := a.Lease
				copy.ID = "other"
				receipt.ControlLease = &copy
			case "wrongFingerprint":
				receipt.FingerprintSHA256 = strings.Repeat("c", 64)
			case "otherAction":
				original.Action = "element.fill"
			}
			b.mu.Lock()
			c.attempts[id] = original
			c.receipts[id] = receipt
			replacement := a.Document
			replacement.DocumentID = "new-document"
			c.documents = []Document{replacement}
			b.mu.Unlock()
			retired, e := g.RetireControl(ctx, p, a)
			if (e == nil && retired) != (kind == "known") {
				t.Fatal("original source retirement result", kind, e)
			}
			b.mu.Lock()
			same := c.receipts[id]
			b.mu.Unlock()
			if same.DispatchState != receipt.DispatchState || same.EffectState != receipt.EffectState || same.FingerprintSHA256 != receipt.FingerprintSHA256 {
				t.Fatal("retirement rewrote original outcome")
			}
		})
	}
}

func TestKnownPressPrivateSourceRetirementKeepsCurrentConsent(t *testing.T) {
	for _, kind := range []string{"current", "revoked", "changedBinding", "cancelled", "foreign", "present", "pending", "otherUnknown"} {
		t.Run(kind, func(t *testing.T) {
			g, p, ctx, source, submit := privacyFixture(t)
			revoked := false
			proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error {
				if revoked {
					return auth.ErrUnauthorized
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			fresh, ok := proof.Authority()
			if !ok {
				t.Fatal("privacy authority unavailable")
			}
			a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: fresh.Document.Origin, TabID: fresh.Document.QualifiedTabID()})
			if err != nil {
				t.Fatal(err)
			}
			c := g.controlChannel(a)
			b := g.broker
			id := strings.Repeat("a", 64)
			command := Command{Action: "element.press", Identity: a.Document.Identity, AttemptID: id, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64)}
			receipt := Reply{AttemptID: id, Identity: command.Identity, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: command.FingerprintSHA256, DispatchState: "dispatched", EffectState: "unverified"}
			b.mu.Lock()
			c.attempts[id] = command
			c.receipts[id] = receipt
			if kind != "present" {
				replacement := a.Document
				replacement.DocumentID = "new-public-document"
				c.documents = []Document{replacement}
			}
			if kind == "pending" {
				c.pending["other-request"] = &pending{}
			}
			if kind == "otherUnknown" {
				c.unknown["other-attempt"] = true
			}
			b.mu.Unlock()
			switch kind {
			case "revoked":
				revoked = true
			case "changedBinding":
				ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "other", GrantID: "private-grant", Purpose: "credential"})
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign":
				p.ClientID = "foreign"
				ctx = auth.WithPrincipal(ctx, p)
			}
			retired, err := g.RetireControl(ctx, p, a)
			if (retired && err == nil) != (kind == "current" || kind == "present") {
				t.Fatal("retirement escaped current private admission", kind, err)
			}
			b.mu.Lock()
			same := c.receipts[id]
			unchangedPrivacy := c.privacy == proof.state && proof.state.active && proof.state.published
			b.mu.Unlock()
			if same.DispatchState != receipt.DispatchState || !unchangedPrivacy {
				t.Fatal("lease cleanup altered business receipt or private redaction")
			}
		})
	}
}

func packagedSourceRetirementReply(command Command) (Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	input, _ := json.Marshal(command)
	child := exec.CommandContext(ctx, "node", filepath.Join("testdata", "control_source_retirement.cjs"))
	child.Stdin = bytes.NewReader(input)
	output, err := child.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return Reply{}, fmt.Errorf("fixture: %s", exit.Stderr)
		}
		return Reply{}, err
	}
	var reply Reply
	err = json.Unmarshal(output, &reply)
	return reply, err
}

// Real Go broker/socket consumes the shipped worker's independent source
// census and immutable Playwright journal ACK. Chrome APIs and signed peers are
// synthetic boundaries; no renderer input or journal write occurs at retirement.
func TestKnownPressSourceRetirementThroughProductionWorker(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "postLoginPrivate"}[private], func(t *testing.T) {
			knownPressProductionWorker(t, private)
		})
	}
}
func knownPressProductionWorker(t *testing.T, private bool) {
	g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { return "knownSourceWorker" })
	a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
	if err != nil {
		t.Fatal(err)
	}
	b := g.broker
	c := g.controlChannel(a)
	if private {
		binding := auth.ConsentBinding{SessionID: "private-session", GrantID: "private-grant", Purpose: "credential"}
		ctx = auth.WithConsentBinding(ctx, binding)
		b.mu.Lock()
		c.privateFlow = &credentialFlow{authority: a, binding: binding, fillAttempt: strings.Repeat("b", 64), submitAttempt: strings.Repeat("c", 64), submitConfirmed: true}
		b.mu.Unlock()
		proof, e := g.QualifyCredentialPrivacy(ctx, p, a, strings.Repeat("c", 64), func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		fresh, ok := proof.Authority()
		if !ok {
			t.Fatal("private capability absent")
		}
		a, e = g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: fresh.Document.Origin, TabID: fresh.Document.QualifiedTabID()})
		if e != nil {
			t.Fatal(e)
		}
	}
	b.mu.Lock()
	b.epoch = "broker1"
	c.epoch = "channel1"
	c.scopeHash = strings.Repeat("a", 64)
	c.grant.Origins = []string{"https://fixture.example.test"}
	a.BrokerEpoch = b.epoch
	a.ChannelEpoch = c.epoch
	a.ScopeHash = c.scopeHash
	a.Document.DocumentID = "d1"
	if private {
		a.Document.DocumentID = "privacy-doc"
	}
	a.Document.Origin = c.grant.Origins[0]
	a.Lease = Lease{ID: "lease-private", Generation: 1}
	if private {
		c.privacy.source.BrokerEpoch = a.BrokerEpoch
		c.privacy.source.ChannelEpoch = a.ChannelEpoch
		c.privacy.source.ScopeHash = a.ScopeHash
		c.privacy.source.Document.Origin = a.Document.Origin
		c.privacy.authority = a
		c.privacy.identity = a.Document.Identity
	}
	command := Command{Action: "element.press", Identity: a.Document.Identity, AttemptID: strings.Repeat("a", 64), BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ControlLease: &a.Lease, FingerprintVersion: 2, Locator: &Locator{Strategy: "id", Value: "save", Exact: true}}
	fp, e := FingerprintMutationV2(command)
	if e != nil {
		b.mu.Unlock()
		t.Fatal(e)
	}
	command.FingerprintSHA256 = fp.SHA256
	command.Locator = nil
	c.attempts[command.AttemptID] = command
	c.receipts[command.AttemptID] = Reply{AttemptID: command.AttemptID, Identity: command.Identity, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: fp.SHA256, DispatchState: "dispatched", EffectState: "unverified"}
	next := a.Document
	next.DocumentID = "retirement-successor"
	c.documents = []Document{next}
	b.mu.Unlock()
	g.controlMu.Lock()
	g.control = &a
	g.controlMu.Unlock()
	retired, err := g.RetireControl(ctx, p, a)
	if err != nil || !retired {
		t.Fatal("production worker retirement ACK not consumed", err)
	}
	b.mu.Lock()
	receipt := c.receipts[command.AttemptID]
	b.mu.Unlock()
	if receipt.DispatchState != "dispatched" || receipt.EffectState != "unverified" || receipt.FingerprintSHA256 != fp.SHA256 {
		t.Fatal("original journal receipt changed")
	}
}
