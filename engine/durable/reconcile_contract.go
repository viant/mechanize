package durable

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// ReconciliationContext is reconstructed from immutable owned records, never
// from proposed replacement steps or caller-authored success evidence.
type ReconciliationContext struct {
	RunID, PlanID, AttemptID, EffectID, BusinessKey string
	Step                                            model.Step
	Plan                                            model.Plan
	Values                                          map[string]model.Value
	Original                                        integration.StepResult
}

type ReconciliationContract struct {
	ID        string          `json:"id"`
	Version   string          `json:"version"`
	Predicate model.Predicate `json:"predicate"`
}

func (c ReconciliationContract) Hash() (string, error) {
	if strings.TrimSpace(c.ID) == "" || len(c.ID) > 256 || strings.TrimSpace(c.Version) == "" || len(c.Version) > 64 {
		return "", errors.New("versioned enrolled reconciliation contract required")
	}
	if err := c.Predicate.Validate(); err != nil {
		return "", err
	}
	if c.Predicate.Kind != "adapter" || (c.Predicate.RequiredAuthority != "observational" && c.Predicate.RequiredAuthority != "authoritative") {
		return "", errors.New("qualified read-only reconciliation predicate required")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return data.ReconcileEffectHash(raw), nil
}

// DeclaredReconciliation uses only a predicate present in the original plan.
// An absent predicate needs a separately enrolled action-specific contract.
func DeclaredReconciliation(c ReconciliationContext) (ReconciliationContract, error) {
	return immutableDeclaredContract("plan.effect.reconcile", c.Step.Effect.Reconcile)
}

// DeclaredPostconditionReconciliation uses the success condition already stored
// in the immutable original step. It neither injects Effect.Reconcile nor adopts
// a caller-proposed replacement predicate. Host enrollment governs its use.
func DeclaredPostconditionReconciliation(c ReconciliationContext) (ReconciliationContract, error) {
	return immutableDeclaredContract("plan.postcondition.reconcile", c.Step.Postcondition)
}
func immutableDeclaredContract(id string, predicate *model.Predicate) (ReconciliationContract, error) {
	if predicate == nil {
		return ReconciliationContract{}, ErrNeedsReconciliation
	}
	raw, err := json.Marshal(predicate)
	if err != nil {
		return ReconciliationContract{}, err
	}
	var detached model.Predicate
	if err = json.Unmarshal(raw, &detached); err != nil {
		return ReconciliationContract{}, err
	}
	result := ReconciliationContract{ID: id, Version: "1", Predicate: detached}
	_, err = result.Hash()
	return result, err
}
