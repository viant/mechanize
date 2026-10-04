package host

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sort"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/objective"
)

// ChromeRetirementFence is the host-pinned predecessor channel, not transport authority.
type ChromeRetirementFence struct{ ProfileChannel, BrowserInstance, BrokerEpoch, ChannelEpoch, ScopeHash string }

var retirementMatchHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var retirementMatchOpaque = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var errRetirementMatch = errors.New("complete correlated resolved Chrome retirement ledger required")

// MatchChromeRetirementBindings performs no reads or writes. Rows must come from
// the actual generated bounded channel query while the host holds admission.
// Its digest retains renderer verification as a renderer fact, never business success.
// The graph has no immutable plan content. Before granting lifecycle authority,
// the coordinator must separately load the original generated plan and validate
// its content/step digests, including the reconciliation original step hash.
// This digest alone cannot qualify BusinessLedgerReconciled.
func MatchChromeRetirementBindings(p auth.Principal, fence ChromeRetirementFence, manifests []data.ChromeRetirementManifest, rows []*bindings.Binding) (string, error) {
	if p.Validate() != nil || !p.HasScope("desktop:control") || !retirementMatchOpaque.MatchString(p.ClientID) {
		return "", auth.ErrUnauthorized
	}
	if len(rows) >= 65 || len(manifests) > 64 || !retirementMatchHash.MatchString(fence.ScopeHash) {
		return "", errRetirementMatch
	}
	for _, v := range []string{fence.ProfileChannel, fence.BrowserInstance, fence.BrokerEpoch, fence.ChannelEpoch} {
		if !retirementMatchOpaque.MatchString(v) {
			return "", errRetirementMatch
		}
	}
	type rendererReceipt struct {
		identity data.ChromeRetirementDocumentIdentity
		receipt  data.ChromeRetirementReceipt
	}
	receipts := map[string]rendererReceipt{}
	documents := map[string]bool{}
	manifestDigests := []string{}
	for _, m := range manifests {
		_, digest, err := data.ChromeRetirementManifestJSON(m)
		if err != nil || m.Identity.ProfileChannel != fence.ProfileChannel || m.Identity.BrowserInstance != fence.BrowserInstance || (len(m.Receipts) > 0 && m.Version != 2) {
			return "", errRetirementMatch
		}
		id := data.ChromeRetirementManifestID(m.Identity)
		if documents[id] {
			return "", errRetirementMatch
		}
		documents[id] = true
		manifestDigests = append(manifestDigests, digest)
		for _, r := range m.Receipts {
			if _, exists := receipts[r.AttemptID]; exists {
				return "", errRetirementMatch
			}
			receipts[r.AttemptID] = rendererReceipt{m.Identity, r}
			if len(receipts) > 64 {
				return "", errRetirementMatch
			}
		}
	}
	type resolution struct {
		BindingID, BrowserAttemptID, EffectID, EvidenceDigest, OutcomeDigest, ReconciliationDigest, EffectState string
		Renderer                                                                                                *data.ChromeRetirementReceipt
	}
	resolved := []resolution{}
	seen := map[string]bool{}
	for _, b := range rows {
		if !retirementBindingValid(p, fence, b) {
			return "", errRetirementMatch
		}
		browserID := *b.BrowserAttemptId
		if seen[browserID] {
			return "", errRetirementMatch
		}
		seen[browserID] = true
		original, current, auditDigest, err := retirementBindingEvidence(p, b)
		if err != nil {
			return "", err
		}
		r, exists := receipts[browserID]
		var renderer *data.ChromeRetirementReceipt
		if exists {
			// A lost host acknowledgement can leave immutable dispatch unknown.
			// Only a fully correlated reconciliation audit may qualify the
			// renderer's independently retained dispatched fact. The original
			// unknown fact remains in OutcomeDigest and current StepResult.
			lostAck := original.DispatchState == "unknown" && current.DispatchState == "unknown" && auditDigest != "" && *b.Effect.State == "confirmed" && r.receipt.DispatchState == "dispatched"
			if r.identity != (data.ChromeRetirementDocumentIdentity{ProfileChannel: *b.ProfileChannel, BrowserInstance: *b.BrowserInstance, TabID: *b.TabId, FrameID: *b.FrameId, DocumentID: *b.DocumentId}) || r.receipt.FingerprintVersion != 2 || r.receipt.FingerprintSHA256 != *b.FingerprintDigest || (r.receipt.DispatchState != original.DispatchState && !lostAck) || (r.receipt.ErrorDispatchState != "" && r.receipt.ErrorDispatchState != r.receipt.DispatchState) {
				return "", errRetirementMatch
			}
			if original.DispatchState == "notDispatched" && r.receipt.EffectState != "none" || r.receipt.DispatchState == "dispatched" && (r.receipt.EffectState == "none" || r.receipt.EffectState == "verified" && original.VerificationState != "verified" && !lostAck) {
				return "", errRetirementMatch
			}
			copy := r.receipt
			renderer = &copy
			delete(receipts, browserID)
		} else if current.DispatchState != "notDispatched" || *b.Effect.State != "absent" {
			return "", errRetirementMatch
		}
		resolved = append(resolved, resolution{*b.Id, browserID, *b.EffectId, data.ChromeAttemptRawDigest(*b.Effect.EvidenceJson), data.ChromeRetirementDigest(original), auditDigest, *b.Effect.State, renderer})
	}
	if len(receipts) != 0 {
		return "", errRetirementMatch
	}
	sort.Strings(manifestDigests)
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].BindingID < resolved[j].BindingID })
	return data.ChromeRetirementDigest(struct {
		Version             int
		Namespace, ClientID string
		Fence               ChromeRetirementFence
		Manifests           []string
		Resolutions         []resolution
	}{2, p.Namespace, p.ClientID, fence, manifestDigests, resolved}), nil
}

func retirementBindingValid(p auth.Principal, f ChromeRetirementFence, b *bindings.Binding) bool {
	if b == nil {
		return false
	}
	for _, v := range []*string{b.Namespace, b.Id, b.ClientId, b.RunId, b.PlanId, b.StepId, b.DurableAttemptId, b.EffectId, b.BrowserAttemptId, b.ProfileChannel, b.BrowserInstance, b.BrokerEpoch, b.ChannelEpoch, b.ScopeHash, b.DocumentId, b.RendererLeaseId, b.FingerprintDigest, b.PlanContentDigest, b.StepDigest, b.BusinessKeyDigest, b.EndlySessionId, b.EndlyOperationId} {
		if v == nil || !retirementMatchOpaque.MatchString(*v) {
			return false
		}
	}
	for _, v := range []*string{b.Id, b.DurableAttemptId, b.EffectId, b.BrowserAttemptId, b.ScopeHash, b.FingerprintDigest, b.PlanContentDigest, b.StepDigest, b.BusinessKeyDigest} {
		if !retirementMatchHash.MatchString(*v) {
			return false
		}
	}
	if *b.Namespace != p.Namespace || *b.ClientId != p.ClientID || *b.ProfileChannel != f.ProfileChannel || *b.BrowserInstance != f.BrowserInstance || *b.BrokerEpoch != f.BrokerEpoch || *b.ChannelEpoch != f.ChannelEpoch || *b.ScopeHash != f.ScopeHash || *b.Id != data.ChromeAttemptBindingID(p.Namespace, p.ClientID, *b.DurableAttemptId) || *b.BrowserAttemptId != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, *b.DurableAttemptId) || *b.EffectId != data.ChromeRetirementDigest([]string{"effect", *b.DurableAttemptId}) {
		return false
	}
	if b.StepIndex == nil || *b.StepIndex < 0 || *b.StepIndex >= 2000 || b.TabId == nil || *b.TabId <= 0 || *b.TabId > 2147483647 || b.FrameId == nil || *b.FrameId != 0 || b.FingerprintVersion == nil || *b.FingerprintVersion != 2 || b.CommittedRunRevision == nil || *b.CommittedRunRevision < 1 {
		return false
	}
	for _, v := range []*int{b.DocumentGeneration, b.RendererLeaseGeneration} {
		if v == nil || *v < 1 || int64(*v) > 9007199254740991 {
			return false
		}
	}
	base := data.ChromeRetirementDigest([]string{"attempt", *b.RunId, *b.PlanId, *b.StepId})
	retry := data.ChromeRetirementDigest([]string{"attempt-resume", *b.RunId, *b.PlanId, *b.StepId, *b.EndlyOperationId})
	return *b.DurableAttemptId == base || *b.DurableAttemptId == retry
}

func retirementBindingEvidence(p auth.Principal, b *bindings.Binding) (integration.StepResult, integration.StepResult, string, error) {
	var original, current integration.StepResult
	fail := func() (integration.StepResult, integration.StepResult, string, error) {
		return original, current, "", errRetirementMatch
	}
	a, e := b.Attempt, b.Effect
	same := func(v *string, s string) bool { return v != nil && *v == s }
	if a == nil || e == nil || !same(a.Namespace, p.Namespace) || !same(a.Id, *b.DurableAttemptId) || !same(a.RunId, *b.RunId) || !same(a.PlanId, *b.PlanId) || !same(a.StepId, *b.StepId) || !same(a.State, "intent") || a.LeaseEpoch == nil || *a.LeaseEpoch != *b.RendererLeaseGeneration || !same(e.Namespace, p.Namespace) || !same(e.Id, *b.EffectId) || !same(e.AttemptId, *b.DurableAttemptId) || !same(e.RunId, *b.RunId) || e.BusinessKey == nil || len(*e.BusinessKey) > 65536 || data.ChromeAttemptRawDigest(*e.BusinessKey) != *b.BusinessKeyDigest || e.Revision == nil || e.State == nil || e.EvidenceJson == nil || len(*e.EvidenceJson) > 4<<20 || json.Unmarshal([]byte(*e.EvidenceJson), &current) != nil || len(b.Outcomes) > 2 {
		return fail()
	}
	var outcome, reconciliation *bindings.Outcome
	for _, o := range b.Outcomes {
		if o == nil || !same(o.Namespace, p.Namespace) || !same(o.RunId, *b.RunId) || !same(o.AttemptId, *b.DurableAttemptId) || o.Id == nil || o.Kind == nil || o.Sequence == nil || *o.Sequence < 1 || o.PayloadJson == nil || len(*o.PayloadJson) > 4<<20 {
			return fail()
		}
		switch *o.Kind {
		case "outcome":
			if outcome != nil || *o.Id != data.ChromeRetirementDigest([]string{"outcome-event", *b.DurableAttemptId}) {
				return fail()
			}
			outcome = o
		case "effect_reconciliation":
			if reconciliation != nil || !retirementMatchHash.MatchString(*o.Id) {
				return fail()
			}
			reconciliation = o
		default:
			return fail()
		}
	}
	if outcome == nil || json.Unmarshal([]byte(*outcome.PayloadJson), &original) != nil {
		return fail()
	}
	auditDigest := ""
	if reconciliation == nil {
		if *e.EvidenceJson != *outcome.PayloadJson || *e.Revision != 2 {
			return fail()
		}
	} else {
		var audit data.ReconcileEffectAudit
		if json.Unmarshal([]byte(*reconciliation.PayloadJson), &audit) != nil || audit.RunID != *b.RunId || audit.PlanID != *b.PlanId || audit.StepID != *b.StepId || audit.AttemptID != *b.DurableAttemptId || audit.EffectID != *b.EffectId || audit.BusinessKey != *e.BusinessKey || audit.OriginalEvidenceHash != data.ReconcileEffectHash([]byte(*outcome.PayloadJson)) || !retirementMatchHash.MatchString(audit.OriginalStepHash) || audit.PriorRunRevision < *b.CommittedRunRevision || audit.PriorEffectRevision != 2 || *e.Revision != 3 || *reconciliation.Sequence <= *outcome.Sequence || !reflect.DeepEqual(current, audit.Evidence.StepResult) || original.DispatchState != current.DispatchState || !reflect.DeepEqual(original.Value, current.Value) || current.Observation != nil || current.Postcondition == nil || !reflect.DeepEqual(*current.Postcondition, audit.Evidence.Result) || audit.Evidence.Result.Truth != objective.True || len(audit.Evidence.Result.Evidence) == 0 || !retirementMatchHash.MatchString(audit.Evidence.ContractHash) || !retirementMatchOpaque.MatchString(audit.Evidence.ContractID) || audit.Evidence.FreshnessMs < 1 || audit.Evidence.FreshnessMs > 30000 || audit.Evidence.Result.ObservedAt.IsZero() || (audit.Evidence.RequiredAuthority != objective.Observational && audit.Evidence.RequiredAuthority != objective.Authoritative) || (audit.Evidence.Result.Authority != audit.Evidence.RequiredAuthority && !(audit.Evidence.RequiredAuthority == objective.Observational && audit.Evidence.Result.Authority == objective.Authoritative)) || (original.DispatchState != "dispatched" && original.DispatchState != "unknown") {
			return fail()
		}
		if audit.Evidence.RequiredAuthority == objective.Authoritative {
			for _, v := range audit.Evidence.Result.Evidence {
				if v.BusinessKey != audit.BusinessKey {
					return fail()
				}
			}
		}
		auditDigest = data.ChromeAttemptRawDigest(*reconciliation.PayloadJson)
	}
	switch *e.State {
	case "confirmed":
		if current.VerificationState != "verified" || (current.DispatchState != "dispatched" && current.DispatchState != "unknown") {
			return fail()
		}
	case "absent":
		if current.DispatchState != "notDispatched" || current.VerificationState == "verified" || reconciliation != nil {
			return fail()
		}
	default:
		return fail()
	}
	return original, current, auditDigest, nil
}
