package host

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestRetirementResumeGeneratedPhases(t *testing.T) {
	for _, mode := range []string{"intended-missing", "intended-existing", "prepared-intended", "prepared-existing", "prepared-missing", "prepared-foreign", "prepared-changed-receipts"} {
		t.Run(mode, func(t *testing.T) {
			ctx, a := retirementAuthorityFixture(t)
			p, _ := auth.FromContext(ctx)
			_, file, _, _ := runtime.Caller(0)
			builder, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				return integration.StepResult{}, errors.New("input forbidden")
			})
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Close(ctx)
			guard := makePreparationGuard(p, a)
			prepared := len(mode) > 8 && mode[:8] == "prepared"
			if prepared {
				guard.failAt = "journal-prepare"
			} else {
				guard.failAt = "journal-intend"
			}
			provider := func(context.Context, chrome.LifecycleReceiptInventory) (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error) {
				return a.Process, a.Policy, nil
			}
			err = builder.WithChromeRetirementComponents(ctx, p, func(held context.Context, base durable.RetirementComponentInvoker) error {
				invoke := committedComponentInvoker(base)
				if _, err := prepareChromeRetirementHeld(held, p, "resume-request", guard, invoke, provider, nil); err == nil {
					t.Fatal("lost reply unexpectedly confirmed")
				}
				transition := data.ChromeRetirementID(p.Namespace, p.ClientID, guard.snapshot.ProfileChannel, guard.snapshot.BrowserInstance, "resume-request")
				bootstrap := a
				bootstrap.TransitionID = transition
				bootstrap.RequestID = "resume-request"
				bootstrap.Phase = "intended"
				bootstrap.PriorRevision = 0
				bootstrap.Now = bootstrap.CreatedAt
				bootstrap.Manifests = nil
				bootstrap.Proof = data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true}
				bootstrap.GuardProof = guard.snapshot.GuardID
				readCtx, err := data.WithChromeRetirementAuthority(held, bootstrap)
				if err != nil {
					return err
				}
				before, err := loadRetainedChromeRetirement(readCtx, p, bootstrap, invoke)
				if err != nil {
					return err
				}
				switch mode {
				case "intended-missing", "prepared-missing":
					guard.journal = nil
				case "prepared-intended":
					guard.journal.Phase = "intended"
					guard.journal.Revision = 1
					guard.journal.Manifest = nil
					guard.journal.EnvelopeDigest = ""
					guard.journal.HostResolutionDigest = ""
				case "prepared-foreign":
					guard.journal.TransitionID = "foreign"
				case "prepared-changed-receipts":
					guard.quiesced = false
				}
				guard.failAt = ""
				guard.calls = nil
				guard.snapshot.GuardID = "successor-guard"
				writes := 0
				observed := func(callCtx context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
					if r.Target.Component.Name == "WriteChromeRetirement" {
						writes++
					}
					return base(callCtx, actor, r)
				}
				id, resumeErr := prepareChromeRetirementHeld(held, p, "resume-request", guard, observed, provider, nil)
				reject := mode == "prepared-missing" || mode == "prepared-foreign" || mode == "prepared-changed-receipts"
				if reject {
					if resumeErr == nil || id != "" {
						t.Fatal("invalid resume confirmed")
					}
					if writes != 0 {
						t.Fatal("invalid prepared recovery wrote DB")
					}
					return nil
				}
				if resumeErr != nil || id != transition {
					t.Fatalf("resume failed: %s %v", id, resumeErr)
				}
				if prepared {
					if writes != 0 {
						t.Fatal("prepared row rewritten")
					}
					for _, call := range guard.calls {
						if call == "quiesce" || call == "retire" || call == "journal-intended" {
							t.Fatal("prepared recovery replayed action", call)
						}
					}
				} else if writes != 1 {
					t.Fatalf("intended recovery writes=%d", writes)
				}
				after, err := loadRetainedChromeRetirement(readCtx, p, bootstrap, invoke)
				if err != nil {
					return err
				}
				if *after.CreatedAt != *before.CreatedAt || *after.Revision != 2 || len(after.Audit) != 2 || *after.Phase != "prepared" {
					t.Fatal("resume changed retained phase identity")
				}
				afterAudits := map[string]string{}
				for _, audit := range after.Audit {
					afterAudits[*audit.Id] = *audit.PayloadJson
				}
				for _, audit := range before.Audit {
					if afterAudits[*audit.Id] != *audit.PayloadJson {
						t.Fatal("retained audit rewritten")
					}
				}
				if prepared && (*after.UpdatedAt != *before.UpdatedAt || !equalRetainedAudit(before.Audit, after.Audit)) {
					t.Fatal("prepared audit identity changed")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func equalRetainedAudit(a, b []*get.Audit) bool {
	if len(a) != len(b) {
		return false
	}
	byID := map[string]string{}
	for _, v := range a {
		byID[*v.Id] = *v.PayloadJson
	}
	for _, v := range b {
		if byID[*v.Id] != *v.PayloadJson {
			return false
		}
	}
	return true
}

func TestRetirementResumeJournalHistoryValidation(t *testing.T) {
	_, a := retirementAuthorityFixture(t)
	a.Phase = "prepared"
	current := &chrome.LifecycleJournalRecord{Version: 1, Channel: chrome.LifecycleJournalChannel{ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance}, TransitionID: a.TransitionID, OldFence: chrome.LifecycleJournalFence{BrokerEpoch: a.OldBrokerEpoch, ChannelEpoch: a.OldChannelEpoch, ScopeHash: a.OldScopeHash}, Phase: "intended", Revision: 1}
	previous := chrome.LifecycleJournalRecord{Version: 1, Channel: current.Channel, TransitionID: "prior-transition", OldFence: chrome.LifecycleJournalFence{BrokerEpoch: "prior-broker", ChannelEpoch: "prior-channel", ScopeHash: a.OldScopeHash}, Phase: "adopted", Revision: 4, HostResolutionDigest: a.Proof.HostResolutionDigest, AdoptedFence: &current.OldFence}
	envelope := chrome.LifecycleJournalEnvelope{Version: 1, Complete: true, Executors: []data.ChromeRetirementManifest{}}
	previous.Manifest = &envelope
	previous.EnvelopeDigest = data.ChromeRetirementDigest(envelope)
	status := chrome.LifecycleJournalStatus{Confirmed: true, Inhibited: true, Record: current, History: []chrome.LifecycleJournalRecord{previous}, StoreRevision: 5}
	if !retirementResumeJournalCompatible(status, a, true) {
		t.Fatal("valid retained adopted history rejected")
	}
	status.History[0].OldFence.BrokerEpoch = ""
	if retirementResumeJournalCompatible(status, a, true) {
		t.Fatal("malformed historical fence accepted")
	}
	status.History[0] = previous
	status.History[0].TransitionID = current.TransitionID
	if retirementResumeJournalCompatible(status, a, true) {
		t.Fatal("duplicate current transition accepted")
	}
	status.History[0] = previous
	status.StoreRevision = 6
	if retirementResumeJournalCompatible(status, a, true) {
		t.Fatal("extraneous history revision accepted")
	}
}
