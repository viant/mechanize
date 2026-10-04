package host

import (
	"context"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"reflect"
	"sort"
	"time"
)

// ChromeRetirementPreparationError retains progress for explicit recovery. A
// pending phase may have committed; callers must read it back, never replay it
// based solely on this error. The phase fields name only confirmed receipts.
type ChromeRetirementPreparationError struct {
	TransitionID                string
	LastConfirmedDatabasePhase  string
	LastConfirmedExtensionPhase string
	PendingPhase                string
}

func (*ChromeRetirementPreparationError) Error() string {
	return "Chrome retirement preparation is unconfirmed; channel remains inhibited"
}

type retirementReceiptGuard interface {
	Inventory(context.Context, auth.Principal) (chrome.LifecycleReceiptInventory, error)
	JournalStatus(context.Context, auth.Principal) (chrome.LifecycleJournalStatus, error)
	RetireControl(context.Context, auth.Principal) error
	Quiesce(context.Context, auth.Principal, chrome.Identity) error
	Collect(context.Context, auth.Principal, chrome.Identity) (chrome.ReceiptExportManifest, error)
	IntendJournal(context.Context, auth.Principal, string) (chrome.LifecycleJournalStatus, error)
	PrepareJournal(context.Context, auth.Principal, chrome.LifecycleJournalPreparation) (chrome.LifecycleJournalStatus, error)
	Close()
}

// Providers are trusted host enrollment, not client-supplied proof fields.
type retirementEvidenceProvider func(context.Context, chrome.LifecycleReceiptInventory) (data.ChromeRetirementProcessEvidence, data.ChromeRetirementPolicyEvidence, error)
type retirementRecordingRetainer func(context.Context, auth.Principal, retirementReceiptGuard, chrome.Identity) error

func prepareChromeRetirement(ctx context.Context, p auth.Principal, requestID, profile, browser string, b *durable.Builder, g *chrome.Gateway, evidence retirementEvidenceProvider, recordings retirementRecordingRetainer) (string, error) {
	if b == nil || g == nil || evidence == nil {
		return "", errors.New("retirement preparation bindings unavailable")
	}
	var transition string
	err := b.WithChromeRetirementComponents(ctx, p, func(held context.Context, invoke durable.RetirementComponentInvoker) error {
		guard, err := g.BeginLifecycleReceiptExport(held, p, profile, browser)
		if err != nil {
			return err
		}
		defer guard.Close()
		transition, err = prepareChromeRetirementHeld(held, p, requestID, guard, committedComponentInvoker(invoke), evidence, recordings)
		return err
	})
	return transition, err
}

// The only successful terminal state here is prepared and input-inhibited.
// Release/adoption must be separate durable phases; failure never resumes input.
func prepareChromeRetirementHeld(ctx context.Context, p auth.Principal, requestID string, guard retirementReceiptGuard, invoke committedComponentInvoker, evidence retirementEvidenceProvider, recordings retirementRecordingRetainer) (string, error) {
	progress := ChromeRetirementPreparationError{}
	fail := func() (string, error) { copy := progress; return "", &copy }
	if guard == nil || invoke == nil || evidence == nil || !retirementMatchOpaque.MatchString(requestID) {
		return fail()
	}
	snapshot, err := guard.Inventory(ctx, p)
	if err != nil || snapshot.Owner != p.Namespace || snapshot.ClientID != p.ClientID {
		return fail()
	}
	process, policy, err := evidence(ctx, snapshot)
	if err != nil {
		return fail()
	}
	// Provider must preserve the actual peer identities pinned by the guard.
	if process.NativeHostPID != snapshot.Process.NativeHost.PID || process.NativeHostUID != snapshot.Process.NativeHost.UID || process.NativeHostBirth != snapshot.Process.NativeHost.StartToken || process.ChromePID != snapshot.Process.ChromeParent.PID || process.ChromeUID != snapshot.Process.ChromeParent.UID || process.ChromeBirth != snapshot.Process.ChromeParent.StartToken || !snapshot.Process.KernelPeerQualified || policy.TrustScope != snapshot.TrustScope {
		return fail()
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	a := data.ChromeRetirementAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RequestID: requestID, ProfileChannel: snapshot.ProfileChannel, BrowserInstance: snapshot.BrowserInstance, TrustScope: snapshot.TrustScope, OldBrokerEpoch: snapshot.BrokerEpoch, OldChannelEpoch: snapshot.ChannelEpoch, OldScopeHash: snapshot.ScopeHash, Phase: "intended", GuardProof: snapshot.GuardID, CreatedAt: at, Now: at, Process: process, Policy: policy, Proof: data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true}}
	a.TransitionID = data.ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID)
	progress.TransitionID = a.TransitionID
	bound, err := data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		return fail()
	}
	originalInvoke := invoke
	invoke = func(callCtx context.Context, actor auth.Principal, request exec.ComponentRequest) (any, error) {
		value, callErr := originalInvoke(callCtx, actor, request)
		if verifyRetirementResumeInventory(ctx, p, guard, snapshot) != nil {
			return nil, errChromeRetirementRestore
		}
		return value, callErr
	}
	progress.PendingPhase = "database.read"
	retained, readErr := loadRetainedChromeRetirement(bound, p, a, invoke)
	if readErr != nil || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, evidence, process, policy) != nil {
		return fail()
	}
	progress.PendingPhase = ""
	if retained != nil {
		if retained.Phase == nil {
			return fail()
		}
		progress.LastConfirmedDatabasePhase = *retained.Phase
		if *retained.Phase == "prepared" {
			return resumePreparedChromeRetirementHeld(ctx, p, guard, snapshot, evidence, process, policy, a, retained, invoke, &progress)
		}
		if *retained.Phase != "intended" {
			return fail()
		}
		a, err = RestoreChromeRetirementAuthority(p, retained, snapshot, process, policy, "")
		if err != nil {
			return fail()
		}
		bound, err = data.WithChromeRetirementAuthority(ctx, a)
		if err != nil {
			return fail()
		}
		progress.PendingPhase = "extension.status"
		journal, statusErr := guard.JournalStatus(ctx, p)
		if statusErr != nil || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, evidence, process, policy) != nil || !retirementResumeJournalCompatible(journal, a, false) {
			return fail()
		}
		if journal.Confirmed {
			progress.LastConfirmedExtensionPhase = "intended"
		}
		progress.PendingPhase = ""
	}
	progress.PendingPhase = "database." + a.Phase
	if _, err = commitChromeRetirement(bound, invoke); err != nil {
		return fail()
	}
	progress.LastConfirmedDatabasePhase = a.Phase
	progress.PendingPhase = ""
	progress.PendingPhase = "extension.intended"
	journal, err := guard.IntendJournal(ctx, p, a.TransitionID)
	if err != nil || !journal.Confirmed || !journal.Inhibited || journal.NeedsAttention || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, evidence, process, policy) != nil {
		return fail()
	}
	progress.LastConfirmedExtensionPhase = "intended"
	progress.PendingPhase = ""
	if err = guard.RetireControl(ctx, p); err != nil {
		return fail()
	}
	manifests := make([]data.ChromeRetirementManifest, 0, len(snapshot.Roots))
	for _, root := range snapshot.Roots {
		// Inspect recording state before quiescence. Recorded history requires the
		// separately enrolled retainer; stopping a recorder alone is not retention.
		before, err := guard.Collect(ctx, p, root)
		if err != nil {
			return fail()
		}
		if verifyRetirementResumeInventory(ctx, p, guard, snapshot) != nil {
			return fail()
		}
		if before.Readiness.RecordingState != "none" {
			if recordings == nil || recordings(ctx, p, guard, root) != nil {
				return fail()
			}
		}
		if err = guard.Quiesce(ctx, p, root); err != nil {
			return fail()
		}
		exported, err := guard.Collect(ctx, p, root)
		if err != nil {
			return fail()
		}
		if verifyRetirementResumeInventory(ctx, p, guard, snapshot) != nil {
			return fail()
		}
		manifest, err := retirementManifest(exported)
		if err != nil {
			return fail()
		}
		manifests = append(manifests, manifest)
	}
	current, err := guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return fail()
	}
	// Renew evidence only after the actual guarded inventory and executable
	// evidence still match. Stored phase/audit timestamps remain immutable.
	refreshedProcess, refreshedPolicy, err := evidence(ctx, current)
	if err != nil || refreshedProcess != process || refreshedPolicy != policy {
		return fail()
	}
	a.EvidenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	bound, err = data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		return fail()
	}
	fence := ChromeRetirementFence{a.ProfileChannel, a.BrowserInstance, a.OldBrokerEpoch, a.OldChannelEpoch, a.OldScopeHash}
	digest, err := collectChromeRetirementHistory(bound, p, fence, manifests, invoke)
	if err != nil || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, evidence, process, policy) != nil {
		return fail()
	}
	current, err = guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return fail()
	}
	a.Now = time.Now().UTC().Format(time.RFC3339Nano)
	a.Phase = "prepared"
	a.PriorRevision = 1
	a.Manifests = manifests
	a.Proof = data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true, NoPending: true, NoUnknown: true, ExecutorsQuiescent: true, ReceiptCoverageComplete: true, RecordingHistoryRetained: true, BusinessLedgerReconciled: true, HostResolutionDigest: digest}
	bound, err = data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		return fail()
	}
	progress.PendingPhase = "database." + a.Phase
	if _, err = commitChromeRetirement(bound, invoke); err != nil {
		return fail()
	}
	progress.LastConfirmedDatabasePhase = a.Phase
	progress.PendingPhase = ""
	current, err = guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return fail()
	}
	ordered := append([]data.ChromeRetirementManifest{}, manifests...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Identity.TabID != ordered[j].Identity.TabID {
			return ordered[i].Identity.TabID < ordered[j].Identity.TabID
		}
		return ordered[i].Identity.DocumentID < ordered[j].Identity.DocumentID
	})
	version := 2
	if len(ordered) > 0 {
		version = ordered[0].Version
	}
	envelope := chrome.LifecycleJournalEnvelope{Version: version, Complete: true, Executors: ordered}
	progress.PendingPhase = "extension.prepared"
	journal, err = guard.PrepareJournal(ctx, p, chrome.LifecycleJournalPreparation{TransitionID: a.TransitionID, Manifest: envelope, EnvelopeDigest: data.ChromeRetirementDigest(envelope), HostResolutionDigest: digest})
	if err != nil || !journal.Confirmed || !journal.Inhibited || journal.NeedsAttention || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, evidence, process, policy) != nil {
		return fail()
	}
	progress.LastConfirmedExtensionPhase = "prepared"
	progress.PendingPhase = ""
	current, err = guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return fail()
	}
	return a.TransitionID, nil
}
