package host

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/data"
	write "github.com/viant/mechanize/data/chromeretirementwrite"
)

// chromeRetirementInput maps only canonical host-held lifecycle evidence into the
// generated Datly writer. It grants no lifecycle authority and performs no I/O.
func chromeRetirementInput(ctx context.Context) (*write.WriteChromeRetirementInput, error) {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		return nil, err
	}
	row := &write.Retirement{}
	row.SetNamespace(retirementValue(a.Namespace))
	row.SetId(retirementValue(a.TransitionID))
	row.SetClientId(retirementValue(a.ClientID))
	row.SetRequestId(retirementValue(a.RequestID))
	row.SetProfileChannel(retirementValue(a.ProfileChannel))
	row.SetBrowserInstance(retirementValue(a.BrowserInstance))
	row.SetTrustScope(retirementValue(a.TrustScope))
	row.SetOldBrokerEpoch(retirementValue(a.OldBrokerEpoch))
	row.SetOldChannelEpoch(retirementValue(a.OldChannelEpoch))
	row.SetOldScopeHash(retirementValue(a.OldScopeHash))
	row.SetProcessEvidenceJson(retirementValue(a.ProcessJSON))
	row.SetPolicyEvidenceJson(retirementValue(a.PolicyJSON))
	row.SetEvidenceDigest(retirementValue(a.EvidenceDigest))
	row.SetPhase(retirementValue(a.Phase))
	row.SetCreatedAt(retirementValue(a.CreatedAt))
	row.SetUpdatedAt(retirementValue(a.Now))
	if a.Phase == "intended" {
		row.SetRevision(retirementValue(1))
	} else {
		// Datly's concurrency hook advances the supplied previous revision.
		row.SetRevision(retirementValue(a.PriorRevision))
		row.SetManifestDigest(retirementValue(a.ManifestDigest))
		row.SetManifestCount(retirementValue(a.ManifestCount))
		row.SetReceiptCount(retirementValue(a.ReceiptCount))
	}
	if a.Phase == "adopted" {
		row.SetAdoptionEvidenceJson(retirementValue(a.AdoptionJSON))
		row.SetAdoptionDigest(retirementValue(a.AdoptionDigest))
	}
	if a.Phase == "prepared" {
		manifests := make([]*write.Manifest, 0, len(a.Manifests))
		for _, m := range a.Manifests {
			raw, digest, err := data.ChromeRetirementManifestJSON(m)
			if err != nil {
				return nil, err
			}
			identity, err := json.Marshal(m.Identity)
			if err != nil {
				return nil, err
			}
			child := &write.Manifest{}
			child.SetNamespace(retirementValue(a.Namespace))
			child.SetTransitionId(retirementValue(a.TransitionID))
			child.SetId(retirementValue(data.ChromeRetirementManifestID(m.Identity)))
			child.SetDocumentIdentityJson(retirementValue(string(identity)))
			child.SetReceiptRevision(retirementValue(int(m.ReceiptRevision)))
			child.SetReceiptCount(retirementValue(len(m.Receipts)))
			child.SetCanonicalManifestJson(retirementValue(raw))
			child.SetManifestDigest(retirementValue(digest))
			child.SetCreatedAt(retirementValue(a.Now))
			manifests = append(manifests, child)
		}
		row.SetManifests(manifests)
	}
	audit := &write.Audit{}
	audit.SetNamespace(retirementValue(a.Namespace))
	audit.SetTransitionId(retirementValue(a.TransitionID))
	audit.SetId(retirementValue(a.AuditID))
	audit.SetPhase(retirementValue(a.Phase))
	audit.SetPriorRevision(retirementValue(a.PriorRevision))
	audit.SetSequence(retirementValue(a.PriorRevision + 1))
	audit.SetRequestId(retirementValue(a.RequestID))
	audit.SetPayloadJson(retirementValue(a.AuditPayloadJSON))
	audit.SetCreatedAt(retirementValue(a.Now))
	row.SetAudit([]*write.Audit{audit})
	input := &write.WriteChromeRetirementInput{}
	input.SetNamespace(a.Namespace)
	input.SetClientID(a.ClientID)
	input.SetTransitionID(a.TransitionID)
	input.SetWriteChromeRetirement([]*write.Retirement{row})
	return input, nil
}
func retirementValue[T any](value T) *T { return &value }
