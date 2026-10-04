package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	write "github.com/viant/mechanize/data/chromeretirementwrite"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

type preparationGuardFixture struct {
	snapshot       chrome.LifecycleReceiptInventory
	quiesced       bool
	calls          []string
	failAt         string
	inventoryCalls int
	journal        *chrome.LifecycleJournalRecord
}

func (g *preparationGuardFixture) Inventory(context.Context, auth.Principal) (chrome.LifecycleReceiptInventory, error) {
	g.calls = append(g.calls, "inventory")
	g.inventoryCalls++
	snapshot := g.snapshot
	if g.failAt == "changed-fence" && g.inventoryCalls > 1 {
		snapshot.ChannelEpoch = "changed"
	}
	return snapshot, nil
}
func (g *preparationGuardFixture) RetireControl(context.Context, auth.Principal) error {
	g.calls = append(g.calls, "retire")
	if g.failAt == "retire" {
		return errors.New("fixture retirement failure")
	}
	return nil
}
func (g *preparationGuardFixture) Quiesce(context.Context, auth.Principal, chrome.Identity) error {
	g.calls = append(g.calls, "quiesce")
	g.quiesced = true
	return nil
}
func (g *preparationGuardFixture) Collect(_ context.Context, _ auth.Principal, i chrome.Identity) (chrome.ReceiptExportManifest, error) {
	g.calls = append(g.calls, "collect")
	if g.failAt == "recording" {
		return chrome.ReceiptExportManifest{Version: 2, Identity: i, Readiness: chrome.ReceiptExportReadiness{RecordingState: "paused", RecordingLastSequence: 1}}, nil
	}
	return chrome.ReceiptExportManifest{Version: 2, Identity: i, Readiness: chrome.ReceiptExportReadiness{Quiesced: g.quiesced, RecordingState: "none"}}, nil
}
func (g *preparationGuardFixture) journalReply() chrome.LifecycleJournalStatus {
	if g.journal == nil {
		return chrome.LifecycleJournalStatus{Inhibited: true, NeedsAttention: true, Reason: "retirementNotFound"}
	}
	raw, _ := json.Marshal(g.journal)
	var record chrome.LifecycleJournalRecord
	_ = json.Unmarshal(raw, &record)
	return chrome.LifecycleJournalStatus{Confirmed: true, Inhibited: true, Record: &record, History: []chrome.LifecycleJournalRecord{}, StoreRevision: record.Revision}
}
func (g *preparationGuardFixture) JournalStatus(context.Context, auth.Principal) (chrome.LifecycleJournalStatus, error) {
	g.calls = append(g.calls, "journal-status")
	return g.journalReply(), nil
}
func (g *preparationGuardFixture) IntendJournal(_ context.Context, _ auth.Principal, id string) (chrome.LifecycleJournalStatus, error) {
	g.calls = append(g.calls, "journal-intended")
	if g.journal != nil && (g.journal.TransitionID != id || g.journal.Phase != "intended") {
		return chrome.LifecycleJournalStatus{}, errors.New("journal phase conflict")
	}
	g.journal = &chrome.LifecycleJournalRecord{Version: 1, Channel: chrome.LifecycleJournalChannel{ProfileChannel: g.snapshot.ProfileChannel, BrowserInstance: g.snapshot.BrowserInstance}, TransitionID: id, OldFence: chrome.LifecycleJournalFence{BrokerEpoch: g.snapshot.BrokerEpoch, ChannelEpoch: g.snapshot.ChannelEpoch, ScopeHash: g.snapshot.ScopeHash}, Phase: "intended", Revision: 1}
	if g.failAt == "journal-intend" {
		return chrome.LifecycleJournalStatus{}, errors.New("lost intended acknowledgement")
	}
	return g.journalReply(), nil
}
func (g *preparationGuardFixture) PrepareJournal(_ context.Context, _ auth.Principal, p chrome.LifecycleJournalPreparation) (chrome.LifecycleJournalStatus, error) {
	g.calls = append(g.calls, "journal-prepared")
	if g.journal == nil || g.journal.TransitionID != p.TransitionID || data.ChromeRetirementDigest(p.Manifest) != p.EnvelopeDigest {
		return chrome.LifecycleJournalStatus{}, errors.New("journal correlation mismatch")
	}
	if g.journal.Phase == "prepared" && (g.journal.EnvelopeDigest != p.EnvelopeDigest || g.journal.HostResolutionDigest != p.HostResolutionDigest) {
		return chrome.LifecycleJournalStatus{}, errors.New("journal proof changed")
	}
	manifest := p.Manifest
	g.journal.Phase = "prepared"
	g.journal.Revision = 2
	g.journal.Manifest = &manifest
	g.journal.EnvelopeDigest = p.EnvelopeDigest
	g.journal.HostResolutionDigest = p.HostResolutionDigest
	if g.failAt == "journal-prepare" {
		return chrome.LifecycleJournalStatus{}, errors.New("lost prepared acknowledgement")
	}
	return g.journalReply(), nil
}
func (g *preparationGuardFixture) Close() {}
func TestRetirementPreparationCommitsGeneratedPreparedState(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	p, _ := auth.FromContext(ctx)
	_, file, _, _ := runtime.Caller(0)
	b, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, errors.New("input forbidden")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	guard := makePreparationGuard(p, a)
	err = b.WithChromeRetirementComponents(ctx, p, func(held context.Context, invoke durable.RetirementComponentInvoker) error {
		id, err := prepareChromeRetirementHeld(held, p, "fixture-prepare", guard, committedComponentInvoker(invoke), func(context.Context, chrome.LifecycleReceiptInventory) (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error) {
			return a.Process, a.Policy, nil
		}, nil)
		if err != nil {
			return err
		}
		if id == "" || !guard.quiesced {
			t.Fatal("preparation incomplete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Assert externally meaningful lifecycle order without coupling to the
	// number of internal fresh-evidence reads performed by generated components.
	operations := []string{}
	for _, call := range guard.calls {
		if call != "inventory" {
			operations = append(operations, call)
		}
	}
	expected := []string{"journal-intended", "retire", "collect", "quiesce", "collect", "journal-prepared"}
	if !reflect.DeepEqual(operations, expected) || len(guard.calls) == 0 || guard.calls[0] != "inventory" || guard.calls[len(guard.calls)-1] != "inventory" {
		t.Fatal("lifecycle order or boundary guard changed", guard.calls)
	}

}

func makePreparationGuard(p auth.Principal, a data.ChromeRetirementAuthority) *preparationGuardFixture {
	return &preparationGuardFixture{snapshot: chrome.LifecycleReceiptInventory{GuardID: "fixture-guard", Owner: p.Namespace, ClientID: p.ClientID, ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance, BrokerEpoch: a.OldBrokerEpoch, ChannelEpoch: a.OldChannelEpoch, ScopeHash: a.OldScopeHash, TrustScope: a.TrustScope, Process: nativepeer.ChromeProcessEvidence{KernelPeerQualified: true, NativeHost: session.ProcessIdentity{PID: a.Process.NativeHostPID, UID: a.Process.NativeHostUID, StartToken: a.Process.NativeHostBirth}, ChromeParent: session.ProcessIdentity{PID: a.Process.ChromePID, UID: a.Process.ChromeUID, StartToken: a.Process.ChromeBirth}}, Roots: []chrome.Identity{{ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance, TabID: 7, DocumentID: "document", Generation: 1}}}}
}

func TestRetirementPreparationFailurePreservesConfirmedProgress(t *testing.T) {
	for _, mode := range []string{"retire", "recording", "changed-fence", "ledger-read", "journal-intend", "journal-prepare"} {
		t.Run(mode, func(t *testing.T) {
			ctx, a := retirementAuthorityFixture(t)
			p, _ := auth.FromContext(ctx)
			_, file, _, _ := runtime.Caller(0)
			b, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				t.Fatal("input dispatch attempted")
				return integration.StepResult{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(ctx)
			guard := makePreparationGuard(p, a)
			guard.failAt = mode
			phases := []string{}
			err = b.WithChromeRetirementComponents(ctx, p, func(held context.Context, invoke durable.RetirementComponentInvoker) error {
				observed := func(callCtx context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
					if r.Target.Component.Name == "WriteChromeRetirement" {
						phases = append(phases, *r.Input.(*write.WriteChromeRetirementInput).WriteChromeRetirement[0].Phase)
					}
					if mode == "ledger-read" && r.Target.Component.Name == "ListChromeAttemptBindings" {
						return nil, errors.New("fixture unavailable ledger")
					}
					return invoke(callCtx, actor, r)
				}
				id, err := prepareChromeRetirementHeld(held, p, "fixture-failure", guard, observed, func(context.Context, chrome.LifecycleReceiptInventory) (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error) {
					return a.Process, a.Policy, nil
				}, nil)
				if err == nil || id != "" {
					t.Fatal("failed preparation reported success")
				}
				var progress *ChromeRetirementPreparationError
				if !errors.As(err, &progress) || progress.TransitionID == "" {
					t.Fatal("recovery identity lost")
				}
				if mode == "journal-prepare" && (progress.LastConfirmedDatabasePhase != "prepared" || progress.LastConfirmedExtensionPhase != "intended" || progress.PendingPhase != "extension.prepared") {
					t.Fatal("partial preparation progress lost", progress)
				}
				if mode == "journal-intend" && (progress.LastConfirmedDatabasePhase != "intended" || progress.LastConfirmedExtensionPhase != "" || progress.PendingPhase != "extension.intended") {
					t.Fatal("partial intention progress lost", progress)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "changed-fence" {
				if len(phases) != 0 {
					t.Fatal("changed fence reached writer", phases)
				}
				return
			}
			if mode == "journal-prepare" {
				if len(phases) != 2 || phases[0] != "intended" || phases[1] != "prepared" {
					t.Fatal("unexpected partial commit", phases)
				}
				return
			}
			if len(phases) != 1 || phases[0] != "intended" {
				t.Fatal("failure wrote a later phase", phases)
			}
		})
	}
}
