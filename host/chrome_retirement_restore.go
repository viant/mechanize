package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
)

var errChromeRetirementRestore = errors.New("exact retained intended/prepared Chrome retirement context required")

type retainedRetirementAudit struct {
	Version        int                             `json:"version"`
	TransitionID   string                          `json:"transitionId"`
	RequestID      string                          `json:"requestId"`
	Phase          string                          `json:"phase"`
	PriorRevision  int                             `json:"priorRevision"`
	GuardProof     string                          `json:"guardProof"`
	EvidenceDigest string                          `json:"evidenceDigest"`
	ManifestDigest string                          `json:"manifestDigest,omitempty"`
	AdoptionDigest string                          `json:"adoptionDigest,omitempty"`
	Proof          data.ChromeRetirementPhaseProof `json:"proof"`
}

func strictRetirementRestoreJSON(raw string, value any) bool {
	if len(raw) > 2<<20 {
		return false
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return false
	}
	return d.Decode(new(any)) == io.EOF
}

// RestoreChromeRetirementAuthority reconstructs retained phase identity without
// reads, writes, or browser authority. The caller must hold a live exact guard,
// supply its freshly verified provider evidence and actual generated read, and
// independently recompute the prepared matcher digest plus immutable plan checks.
// Only EvidenceObservedAt is refreshed; phase timestamps and audit remain intact.
func RestoreChromeRetirementAuthority(p auth.Principal, row *get.Retirement, inventory chrome.LifecycleReceiptInventory, process data.ChromeRetirementProcessEvidence, policy data.ChromeRetirementPolicyEvidence, recomputedDigest string) (data.ChromeRetirementAuthority, error) {
	fail := func() (data.ChromeRetirementAuthority, error) {
		return data.ChromeRetirementAuthority{}, errChromeRetirementRestore
	}
	if p.Validate() != nil || !p.HasScope("desktop:control") || row == nil || inventory.Owner != p.Namespace || inventory.ClientID != p.ClientID || !retirementMatchOpaque.MatchString(inventory.GuardID) {
		return fail()
	}
	for _, v := range []*string{row.Namespace, row.Id, row.ClientId, row.RequestId, row.ProfileChannel, row.BrowserInstance, row.TrustScope, row.OldBrokerEpoch, row.OldChannelEpoch, row.OldScopeHash, row.ProcessEvidenceJson, row.PolicyEvidenceJson, row.EvidenceDigest, row.Phase, row.CreatedAt, row.UpdatedAt} {
		if v == nil {
			return fail()
		}
	}
	if *row.Namespace != p.Namespace || *row.ClientId != p.ClientID || *row.ProfileChannel != inventory.ProfileChannel || *row.BrowserInstance != inventory.BrowserInstance || *row.TrustScope != inventory.TrustScope || *row.OldBrokerEpoch != inventory.BrokerEpoch || *row.OldChannelEpoch != inventory.ChannelEpoch || *row.OldScopeHash != inventory.ScopeHash || (*row.Phase != "intended" && *row.Phase != "prepared") || row.Revision == nil || *row.Revision != data.ChromeRetirementPhaseRevision(*row.Phase) || len(row.Audit) != *row.Revision || len(row.Manifests) > 64 || row.AdoptionEvidenceJson != nil || row.AdoptionDigest != nil {
		return fail()
	}
	if process.NativeHostPID != inventory.Process.NativeHost.PID || process.NativeHostUID != inventory.Process.NativeHost.UID || process.NativeHostBirth != inventory.Process.NativeHost.StartToken || process.ChromePID != inventory.Process.ChromeParent.PID || process.ChromeUID != inventory.Process.ChromeParent.UID || process.ChromeBirth != inventory.Process.ChromeParent.StartToken || !inventory.Process.KernelPeerQualified || policy.TrustScope != inventory.TrustScope || policy.ProfileQualified != inventory.ProfileQualified {
		return fail()
	}
	var storedProcess data.ChromeRetirementProcessEvidence
	var storedPolicy data.ChromeRetirementPolicyEvidence
	if !strictRetirementRestoreJSON(*row.ProcessEvidenceJson, &storedProcess) || !strictRetirementRestoreJSON(*row.PolicyEvidenceJson, &storedPolicy) || storedProcess != process || storedPolicy != policy {
		return fail()
	}
	if *row.Phase == "intended" {
		if len(row.Manifests) != 0 || row.ManifestDigest != nil || row.ManifestCount != nil || row.ReceiptCount != nil || recomputedDigest != "" {
			return fail()
		}
	} else if !retirementMatchHash.MatchString(recomputedDigest) {
		return fail()
	}
	manifests := make([]data.ChromeRetirementManifest, 0, len(row.Manifests))
	for _, m := range row.Manifests {
		if m == nil || m.CanonicalManifestJson == nil {
			return fail()
		}
		var manifest data.ChromeRetirementManifest
		if !strictRetirementRestoreJSON(*m.CanonicalManifestJson, &manifest) {
			return fail()
		}
		manifests = append(manifests, manifest)
	}
	if *row.Phase == "prepared" {
		if len(inventory.Roots) != len(manifests) {
			return fail()
		}
		roots := map[string]bool{}
		for _, root := range inventory.Roots {
			identity := data.ChromeRetirementDocumentIdentity{ProfileChannel: root.ProfileChannel, BrowserInstance: root.BrowserInstance, TabID: root.TabID, FrameID: root.FrameID, DocumentID: root.DocumentID}
			key := data.ChromeRetirementManifestID(identity)
			if roots[key] || root.Generation == 0 {
				return fail()
			}
			roots[key] = true
		}
		for _, manifest := range manifests {
			key := data.ChromeRetirementManifestID(manifest.Identity)
			if !roots[key] {
				return fail()
			}
			delete(roots, key)
		}
		if len(roots) != 0 {
			return fail()
		}
	}
	audits := make(map[string]*get.Audit, len(row.Audit))
	payloads := make(map[string]retainedRetirementAudit, len(row.Audit))
	for _, audit := range row.Audit {
		if audit == nil || audit.Phase == nil || audit.PayloadJson == nil || audit.CreatedAt == nil || (*audit.Phase != "intended" && *audit.Phase != "prepared") || audits[*audit.Phase] != nil {
			return fail()
		}
		var payload retainedRetirementAudit
		if !strictRetirementRestoreJSON(*audit.PayloadJson, &payload) || payload.Phase != *audit.Phase || payload.Version != 1 || payload.AdoptionDigest != "" || payload.Proof.FenceReleaseConfirmed {
			return fail()
		}
		if payload.Phase == "intended" && (!reflect.DeepEqual(payload.Proof, data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true}) || payload.ManifestDigest != "") {
			return fail()
		}
		if payload.Phase == "prepared" && payload.Proof.HostResolutionDigest != recomputedDigest {
			return fail()
		}
		audits[*audit.Phase] = audit
		payloads[*audit.Phase] = payload
	}
	intended := audits["intended"]
	if intended == nil || *intended.CreatedAt != *row.CreatedAt || payloads["intended"].GuardProof == "" {
		return fail()
	}
	if *row.Phase == "prepared" {
		if audits["prepared"] == nil || *audits["prepared"].CreatedAt != *row.UpdatedAt || payloads["prepared"].GuardProof != payloads["intended"].GuardProof {
			return fail()
		}
	}
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		return fail()
	}
	var prior *get.Retirement
	var result data.ChromeRetirementAuthority
	for revision := 1; revision <= *row.Revision; revision++ {
		phase := "intended"
		if revision == 2 {
			phase = "prepared"
		}
		audit, payload := audits[phase], payloads[phase]
		if audit == nil {
			return fail()
		}
		a := data.ChromeRetirementAuthority{Namespace: p.Namespace, ClientID: p.ClientID, TransitionID: *row.Id, RequestID: *row.RequestId, ProfileChannel: inventory.ProfileChannel, BrowserInstance: inventory.BrowserInstance, TrustScope: inventory.TrustScope, OldBrokerEpoch: inventory.BrokerEpoch, OldChannelEpoch: inventory.ChannelEpoch, OldScopeHash: inventory.ScopeHash, Phase: phase, PriorRevision: revision - 1, GuardProof: payload.GuardProof, CreatedAt: *row.CreatedAt, Now: *audit.CreatedAt, EvidenceObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Process: process, Policy: policy, Proof: payload.Proof}
		if revision == 2 {
			a.Manifests = manifests
		}
		bound, e := data.WithChromeRetirementAuthority(ctx, a)
		if e != nil {
			return fail()
		}
		canonical, e := data.RequireChromeRetirementAuthority(bound)
		if e != nil {
			return fail()
		}
		input, e := chromeRetirementInput(bound)
		if e != nil {
			return fail()
		}
		var phaseRow *get.Retirement
		if revision == *row.Revision {
			phaseRow = row
		} else {
			raw, e := json.Marshal(row)
			if e != nil || json.Unmarshal(raw, &phaseRow) != nil {
				return fail()
			}
			phaseRow.Phase = retirementValue("intended")
			phaseRow.Revision = retirementValue(1)
			phaseRow.UpdatedAt = phaseRow.CreatedAt
			phaseRow.ManifestDigest = nil
			phaseRow.ManifestCount = nil
			phaseRow.ReceiptCount = nil
			phaseRow.Manifests = nil
			phaseRow.Audit = []*get.Audit{intended}
		}
		if canonical.EvidenceDigest != *row.EvidenceDigest || canonical.ProcessJSON != *row.ProcessEvidenceJson || canonical.PolicyJSON != *row.PolicyEvidenceJson || canonical.AuditPayloadJSON != *audit.PayloadJson || !retirementReadbackMatches(input.WriteChromeRetirement[0], phaseRow, prior, revision) {
			return fail()
		}
		prior = phaseRow
		result = canonical
	}
	return result, nil
}
