package durable

import (
	"encoding/json"

	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
)

// A new dispatched row is never inferred from an old unknown row. Its exact
// immutable step and receipt must agree, and it must carry no verified milestone.
func validateDispatchedHistory(run *loadrun.Run) error {
	var needs bool
	for _, effect := range run.Effects {
		needs = needs || effect.State != nil && *effect.State == "dispatched"
	}
	if !needs {
		return nil
	}
	envelope, e := decodeStatePlan(run)
	if e != nil {
		return e
	}
	for _, effect := range run.Effects {
		if effect.State == nil || *effect.State != "dispatched" {
			continue
		}
		if effect.AttemptId == nil || effect.EvidenceJson == nil {
			return ErrNeedsReconciliation
		}
		var receipt integration.StepResult
		if json.Unmarshal([]byte(*effect.EvidenceJson), &receipt) != nil || !receipt.DispatchedUnverified() || receipt.Value != nil && receipt.Value.Validate() != nil {
			return ErrNeedsReconciliation
		}
		stepID := ""
		for _, attempt := range run.Attempts {
			if attempt.Id != nil && *attempt.Id == *effect.AttemptId && attempt.StepId != nil {
				stepID = *attempt.StepId
			}
		}
		matched := false
		for _, step := range envelope.Plan.Steps {
			if step.ID == stepID {
				matched = step.Postcondition == nil && (step.Bind == "" || receipt.Value != nil)
			}
		}
		if !matched {
			return ErrNeedsReconciliation
		}
		for _, milestone := range run.Milestones {
			if milestone.AttemptId != nil && *milestone.AttemptId == *effect.AttemptId {
				return ErrNeedsReconciliation
			}
		}
	}
	return nil
}
