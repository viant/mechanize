package host

import (
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/model"
)

// MatchChromeRetirementHistory combines resolved ledger matching with immutable
// plan/step linkage. Plans and bindings must be loaded by generated components
// under the same held lifecycle admission scope; no caller payload is evidence.
func MatchChromeRetirementHistory(p auth.Principal, fence ChromeRetirementFence, manifests []data.ChromeRetirementManifest, rows []*bindings.Binding, plans map[string]*loadplan.PlanRevision) (string, error) {
	ledger, err := MatchChromeRetirementBindings(p, fence, manifests, rows)
	if err != nil {
		return "", err
	}
	hashes := map[string]string{}
	for _, b := range rows {
		plan := plans[*b.PlanId]
		if plan == nil || plan.Namespace == nil || *plan.Namespace != p.Namespace || plan.Id == nil || *plan.Id != *b.PlanId || plan.ContentHash == nil || plan.ContentJson == nil || len(*plan.ContentJson) > 4<<20 || *plan.ContentHash != *b.PlanContentDigest || data.ChromeAttemptRawDigest(*plan.ContentJson) != *plan.ContentHash {
			return "", errRetirementMatch
		}
		var envelope struct {
			Plan model.Plan `json:"plan"`
		}
		if json.Unmarshal([]byte(*plan.ContentJson), &envelope) != nil || *b.StepIndex < 0 || *b.StepIndex >= len(envelope.Plan.Steps) {
			return "", errRetirementMatch
		}
		step := envelope.Plan.Steps[*b.StepIndex]
		if step.ID != *b.StepId || data.ChromeRetirementDigest(step) != *b.StepDigest {
			return "", errRetirementMatch
		}
		count := 0
		for _, candidate := range envelope.Plan.Steps {
			if candidate.ID == step.ID {
				count++
			}
		}
		if count != 1 {
			return "", errRetirementMatch
		}
		ordinary, err := data.ReconcileEffectStepHash(step)
		if err != nil {
			return "", errRetirementMatch
		}
		for _, event := range b.Outcomes {
			if event.Kind != nil && *event.Kind == "effect_reconciliation" {
				var audit data.ReconcileEffectAudit
				if event.PayloadJson == nil || json.Unmarshal([]byte(*event.PayloadJson), &audit) != nil || audit.OriginalStepHash != ordinary {
					return "", errRetirementMatch
				}
			}
		}
		hashes[*b.PlanId] = *plan.ContentHash
	}
	return data.ChromeRetirementDigest(struct {
		Version int
		Ledger  string
		Plans   map[string]string
	}{1, ledger, hashes}), nil
}
