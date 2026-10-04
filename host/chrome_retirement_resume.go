package host

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
)

func verifyRetirementResumeInventory(ctx context.Context, p auth.Principal, guard retirementReceiptGuard, pinned chrome.LifecycleReceiptInventory) error {
	current, err := guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(current, pinned) {
		return errChromeRetirementRestore
	}
	return nil
}
func verifyRetirementResumeEvidence(ctx context.Context, p auth.Principal, guard retirementReceiptGuard, pinned chrome.LifecycleReceiptInventory, provider retirementEvidenceProvider, process data.ChromeRetirementProcessEvidence, policy data.ChromeRetirementPolicyEvidence) error {
	current, err := guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(current, pinned) {
		return errChromeRetirementRestore
	}
	actualProcess, actualPolicy, err := provider(ctx, current)
	if err != nil || actualProcess != process || actualPolicy != policy {
		return errChromeRetirementRestore
	}
	after, err := guard.Inventory(ctx, p)
	if err != nil || !reflect.DeepEqual(after, pinned) {
		return errChromeRetirementRestore
	}
	return nil
}
func loadRetainedChromeRetirement(ctx context.Context, p auth.Principal, a data.ChromeRetirementAuthority, invoke committedComponentInvoker) (*get.Retirement, error) {
	input := &get.LoadChromeRetirementInput{}
	input.SetNamespace(p.Namespace)
	input.SetClientID(p.ClientID)
	input.SetTransitionID(a.TransitionID)
	value, err := invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementget", Name: "LoadChromeRetirement"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeretirementget"}}, Input: input})
	if err != nil {
		return nil, errChromeRetirementRestore
	}
	out, ok := value.(*get.LoadChromeRetirementOutput)
	if !ok || out == nil || len(out.Data) > 1 {
		return nil, errChromeRetirementRestore
	}
	if len(out.Data) == 0 {
		return nil, nil
	}
	row := out.Data[0]
	if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.ClientId == nil || *row.ClientId != p.ClientID || row.Id == nil || *row.Id != a.TransitionID || row.RequestId == nil || *row.RequestId != a.RequestID {
		return nil, errChromeRetirementRestore
	}
	return row, nil
}
func retirementResumeJournalCompatible(status chrome.LifecycleJournalStatus, a data.ChromeRetirementAuthority, prepared bool) bool {
	if !status.Inhibited {
		return false
	}
	if !status.Confirmed {
		return !prepared && status.NeedsAttention && status.Reason == "retirementNotFound" && status.Record == nil && len(status.History) == 0 && status.StoreRevision == 0
	}
	r := status.Record
	channel := chrome.LifecycleJournalChannel{ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance}
	fence := chrome.LifecycleJournalFence{BrokerEpoch: a.OldBrokerEpoch, ChannelEpoch: a.OldChannelEpoch, ScopeHash: a.OldScopeHash}
	if status.NeedsAttention || status.Reason != "" || r == nil || r.Version != 1 || r.Channel != channel || r.TransitionID != a.TransitionID || r.OldFence != fence || r.AdoptedFence != nil || (r.Phase != "intended" && r.Phase != "prepared") || (!prepared && r.Phase != "intended") || r.Revision != data.ChromeRetirementPhaseRevision(r.Phase) || len(status.History) > 31 || status.StoreRevision != 4*len(status.History)+r.Revision {
		return false
	}
	seen := map[string]bool{r.TransitionID: true}
	var previous *chrome.LifecycleJournalRecord
	for i := range status.History {
		h := &status.History[i]
		if h.Version != 1 || h.Channel != channel || h.Phase != "adopted" || h.Revision != 4 || h.AdoptedFence == nil || seen[h.TransitionID] || !retirementMatchOpaque.MatchString(h.TransitionID) || !retirementMatchHash.MatchString(h.EnvelopeDigest) || !retirementMatchHash.MatchString(h.HostResolutionDigest) || h.Manifest == nil || !retirementResumeHistoricalEnvelopeValid(*h.Manifest, channel) || data.ChromeRetirementDigest(*h.Manifest) != h.EnvelopeDigest || !retirementResumeFenceValid(h.OldFence) || !retirementResumeFenceValid(*h.AdoptedFence) || h.AdoptedFence.ScopeHash != h.OldFence.ScopeHash || h.AdoptedFence.BrokerEpoch == h.OldFence.BrokerEpoch || h.AdoptedFence.ChannelEpoch == h.OldFence.ChannelEpoch || (previous != nil && *previous.AdoptedFence != h.OldFence) {
			return false
		}
		seen[h.TransitionID] = true
		previous = h
	}
	if previous != nil && *previous.AdoptedFence != fence {
		return false
	}
	if r.Phase == "intended" {
		return r.Manifest == nil && r.EnvelopeDigest == "" && r.HostResolutionDigest == ""
	}
	expected := retirementResumeEnvelope(a.Manifests)
	return r.Manifest != nil && reflect.DeepEqual(*r.Manifest, expected) && r.EnvelopeDigest == data.ChromeRetirementDigest(expected) && r.HostResolutionDigest == a.Proof.HostResolutionDigest
}
func retirementResumeEnvelope(manifests []data.ChromeRetirementManifest) chrome.LifecycleJournalEnvelope {
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
	return chrome.LifecycleJournalEnvelope{Version: version, Complete: true, Executors: ordered}
}

// resumePreparedChromeRetirementHeld reads complete current renderer and durable
// proofs before adopting the retained phase. It never quiesces or rewrites it.
func resumePreparedChromeRetirementHeld(ctx context.Context, p auth.Principal, guard retirementReceiptGuard, snapshot chrome.LifecycleReceiptInventory, provider retirementEvidenceProvider, process data.ChromeRetirementProcessEvidence, policy data.ChromeRetirementPolicyEvidence, bootstrap data.ChromeRetirementAuthority, row *get.Retirement, invoke committedComponentInvoker, progress *ChromeRetirementPreparationError) (string, error) {
	fail := func() (string, error) { copy := *progress; return "", &copy }
	progress.PendingPhase = "extension.status"
	journal, err := guard.JournalStatus(ctx, p)
	if err != nil || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, provider, process, policy) != nil || !journal.Confirmed {
		return fail()
	}
	manifests := make([]data.ChromeRetirementManifest, 0, len(snapshot.Roots))
	for _, root := range snapshot.Roots {
		exported, err := guard.Collect(ctx, p, root)
		if err != nil || verifyRetirementResumeInventory(ctx, p, guard, snapshot) != nil {
			return fail()
		}
		manifest, err := retirementManifest(exported)
		if err != nil {
			return fail()
		}
		manifests = append(manifests, manifest)
	}
	if verifyRetirementResumeEvidence(ctx, p, guard, snapshot, provider, process, policy) != nil {
		return fail()
	}
	bootstrap.EvidenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	bound, err := data.WithChromeRetirementAuthority(ctx, bootstrap)
	if err != nil {
		return fail()
	}
	fence := ChromeRetirementFence{snapshot.ProfileChannel, snapshot.BrowserInstance, snapshot.BrokerEpoch, snapshot.ChannelEpoch, snapshot.ScopeHash}
	digest, err := collectChromeRetirementHistory(bound, p, fence, manifests, invoke)
	if err != nil || verifyRetirementResumeEvidence(ctx, p, guard, snapshot, provider, process, policy) != nil {
		return fail()
	}
	restored, err := RestoreChromeRetirementAuthority(p, row, snapshot, process, policy, digest)
	if err != nil || data.ChromeRetirementDigest(restored.Manifests) != data.ChromeRetirementDigest(retirementRestoreSortedManifests(manifests)) || !retirementResumeJournalCompatible(journal, restored, true) {
		return fail()
	}
	progress.LastConfirmedExtensionPhase = journal.Record.Phase
	bound, err = data.WithChromeRetirementAuthority(ctx, restored)
	if err != nil {
		return fail()
	}
	progress.PendingPhase = "database.prepared"
	if _, err = commitChromeRetirement(bound, invoke); err != nil {
		return fail()
	}
	progress.PendingPhase = ""
	if journal.Record.Phase == "intended" {
		progress.PendingPhase = "extension.prepared"
		envelope := retirementResumeEnvelope(restored.Manifests)
		acknowledged, err := guard.PrepareJournal(ctx, p, chrome.LifecycleJournalPreparation{TransitionID: restored.TransitionID, Manifest: envelope, EnvelopeDigest: data.ChromeRetirementDigest(envelope), HostResolutionDigest: digest})
		if err != nil || !retirementResumeJournalCompatible(acknowledged, restored, true) || acknowledged.Record.Phase != "prepared" {
			return fail()
		}
	}
	if verifyRetirementResumeEvidence(ctx, p, guard, snapshot, provider, process, policy) != nil {
		return fail()
	}
	progress.LastConfirmedExtensionPhase = "prepared"
	progress.PendingPhase = ""
	return restored.TransitionID, nil
}
func retirementRestoreSortedManifests(manifests []data.ChromeRetirementManifest) []data.ChromeRetirementManifest {
	out := append([]data.ChromeRetirementManifest(nil), manifests...)
	sort.Slice(out, func(i, j int) bool {
		return data.ChromeRetirementManifestID(out[i].Identity) < data.ChromeRetirementManifestID(out[j].Identity)
	})
	return out
}

func retirementResumeFenceValid(f chrome.LifecycleJournalFence) bool {
	return retirementMatchOpaque.MatchString(f.BrokerEpoch) && retirementMatchOpaque.MatchString(f.ChannelEpoch) && retirementMatchHash.MatchString(f.ScopeHash)
}
func retirementResumeHistoricalEnvelopeValid(e chrome.LifecycleJournalEnvelope, c chrome.LifecycleJournalChannel) bool {
	if (e.Version != 1 && e.Version != 2) || !e.Complete || e.Executors == nil || len(e.Executors) > 64 {
		return false
	}
	seen := map[string]bool{}
	receipts, bytes := 0, 0
	for _, m := range e.Executors {
		if m.Version != e.Version || m.Identity.ProfileChannel != c.ProfileChannel || m.Identity.BrowserInstance != c.BrowserInstance {
			return false
		}
		raw, _, err := data.ChromeRetirementManifestJSON(m)
		if err != nil {
			return false
		}
		id := data.ChromeRetirementManifestID(m.Identity)
		if seen[id] {
			return false
		}
		seen[id] = true
		receipts += len(m.Receipts)
		bytes += len(raw)
		if receipts > 4096 || bytes > 2*1024*1024 {
			return false
		}
	}
	expected := retirementResumeEnvelope(e.Executors)
	expected.Version = e.Version
	return reflect.DeepEqual(e, expected)
}
