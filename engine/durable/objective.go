package durable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"reflect"
	"time"
)

func (b *Builder) EvaluatePostcondition(ctx context.Context, p auth.Principal, predicate model.Predicate, values map[string]model.Value) (objective.Result, error) {
	if b.options.ObjectiveEvaluator == nil {
		return objective.Result{Truth: objective.Unknown, Reason: "qualified predicate evaluator unavailable"}, nil
	}
	return b.options.ObjectiveEvaluator.Evaluate(ctx, p, predicate, values)
}

// CompleteObjective verifies immutable durable identity, then records the
// separate business outcome through the guarded generated TransitionRun graph.
func (b *Builder) CompleteObjective(ctx context.Context, p auth.Principal, request integration.CompletionRequest) (integration.BusinessResult, error) {
	result := integration.BusinessResult{BusinessStatus: "unverified", VerificationState: "unverified", Reason: "qualified objective unavailable"}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return result, err
	}
	user.mu.Lock()
	run, err := load(ctx, user.server, p, request.Metadata.RunID)
	if err != nil {
		user.mu.Unlock()
		return result, err
	}
	if run.PlanId == nil || *run.PlanId != request.Metadata.PlanID || run.Revision == nil || run.Plan == nil || run.Plan.ContentJson == nil {
		user.mu.Unlock()
		return result, errors.New("immutable completion plan identity missing")
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	err = json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope)
	revision := *run.Revision
	unresolved := false
	for _, effect := range run.Effects {
		if effect.State == nil || (*effect.State != "confirmed" && *effect.State != "absent") {
			unresolved = true
		}
	}
	user.mu.Unlock()
	if err != nil || !reflect.DeepEqual(envelope.Plan, request.Plan) {
		return result, errors.New("completion objective differs from immutable plan")
	}
	for k, v := range envelope.Inputs {
		if !reflect.DeepEqual(v, request.Values["input."+k]) {
			return result, errors.New("completion inputs differ from immutable plan")
		}
	}
	target := "paused"
	switch request.OperationStatus {
	case manager.OperationSucceeded:
		if unresolved {
			result.VerificationState = "unknown"
			break
		}
		if envelope.Plan.Objective != nil {
			verified, evalErr := b.EvaluatePostcondition(ctx, p, *envelope.Plan.Objective, request.Values)
			if evalErr != nil {
				// An unavailable/invalid oracle does not establish false business
				// truth. Persist a stopped repair boundary without replaying input.
				result.VerificationState = "unknown"
				result.Reason = "qualified objective could not be evaluated; stopped run requires attention"
				break
			}
			result.Objective = &verified
			result.Reason = verified.Reason
			if objective.RequireBusinessSuccess(verified) == nil {
				target = "succeeded"
				result.BusinessStatus = "succeeded"
				result.VerificationState = "verified"
			} else if authoritativeBusinessFalse(verified, envelope.Plan.Objective.FreshnessMs) {
				target = "failed"
				result.BusinessStatus = "failed"
				result.VerificationState = "verified"
			} else {
				result.VerificationState = "unknown"
			}
		}
	case manager.OperationFailed:
		// Locator, read and step failures describe execution, not the immutable
		// business objective. A stopped known-effect run remains repairable.
		result.VerificationState = "unknown"
		result.Reason = "Endly execution failed; business objective remains unverified and stopped run requires attention"
	case manager.OperationCancelled:
		target = "cancelled"
		result.BusinessStatus = "cancelled"
		result.Reason = "Endly operation cancelled"
	default:
		return result, errors.New("Endly completion must be terminal")
	}
	if unresolved {
		// Generated safe transitions reject unresolved effects. Retain their
		// durable barrier rather than terminalizing or pretending to pause them.
		result.VerificationState = "unknown"
		result.Reason = "Endly operation stopped with unresolved durable effects; reconciliation required before completion or resume"
		return result, nil
	}
	var proof *data.BusinessVerification
	if target == "succeeded" {
		raw, _ := json.Marshal(envelope.Plan.Objective)
		sum := sha256.Sum256(raw)
		proof = &data.BusinessVerification{Namespace: p.Namespace, RunID: request.Metadata.RunID, PlanID: request.Metadata.PlanID, ObjectiveHash: hex.EncodeToString(sum[:]), FreshnessMs: envelope.Plan.Objective.FreshnessMs, BusinessKey: result.Objective.Evidence[0].BusinessKey, Result: *result.Objective}
	}
	_, err = b.transitionRun(ctx, p, request.Metadata.RunID, revision, target, proof, &result)
	return result, err
}

// False becomes definitive business failure only with the same qualified,
// fresh, exact-entity evidence demanded for success. UI assertions and weaker
// observations cannot terminalize a business run.
func authoritativeBusinessFalse(result objective.Result, freshnessMs int64) bool {
	if result.Truth != objective.False || freshnessMs <= 0 || time.Since(result.ObservedAt) > time.Duration(freshnessMs)*time.Millisecond {
		return false
	}
	proof := result
	proof.Truth = objective.True
	return objective.RequireBusinessSuccess(proof) == nil
}
