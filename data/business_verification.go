package data

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/objective"
	"time"
)

type BusinessVerification struct {
	Namespace     string           `json:"-"`
	RunID         string           `json:"runId"`
	PlanID        string           `json:"planId"`
	ObjectiveHash string           `json:"objectiveHash"`
	FreshnessMs   int64            `json:"freshnessMs"`
	BusinessKey   string           `json:"businessKey"`
	Result        objective.Result `json:"objective"`
}
type businessVerificationKey struct{}

// WithBusinessVerification is an internal context capability minted only after
// a trusted evaluator verifies the immutable run objective. Wire fields alone
// cannot grant this capability to a generated mutation component.
func WithBusinessVerification(ctx context.Context, proof BusinessVerification) (context.Context, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != proof.Namespace {
		return nil, auth.ErrUnauthorized
	}
	age := time.Since(proof.Result.ObservedAt)
	if proof.Result.ObservedAt.IsZero() || age < 0 || proof.FreshnessMs <= 0 || age > time.Duration(proof.FreshnessMs)*time.Millisecond {
		return nil, errors.New("verified business evidence is stale")
	}
	if proof.RunID == "" || proof.PlanID == "" || proof.ObjectiveHash == "" || proof.BusinessKey == "" || objective.RequireBusinessSuccess(proof.Result) != nil || len(proof.Result.Evidence) == 0 {
		return nil, errors.New("complete verified business objective required")
	}
	for _, e := range proof.Result.Evidence {
		if e.BusinessKey != proof.BusinessKey || e.Kind == "" || e.Reference == "" {
			return nil, errors.New("verified business key mismatch")
		}
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, businessVerificationKey{}, string(raw)), nil
}
func RequireBusinessVerification(ctx context.Context, namespace, runID, planID string, payload string) error {
	encoded, ok := ctx.Value(businessVerificationKey{}).(string)
	if !ok {
		return errors.New("trusted business verification permit required")
	}
	var expected BusinessVerification
	if json.Unmarshal([]byte(encoded), &expected) != nil {
		return errors.New("invalid business verification permit")
	}
	var audit struct {
		Status string `json:"status"`
		BusinessVerification
	}
	if json.Unmarshal([]byte(payload), &audit) != nil || audit.Status != "succeeded" {
		return errors.New("business audit mismatch")
	}
	actual, err := json.Marshal(audit.BusinessVerification)
	if err != nil || string(actual) != encoded || expected.RunID != runID || expected.PlanID != planID {
		return errors.New("business audit differs from trusted verification")
	}
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != namespace {
		return auth.ErrUnauthorized
	}
	// Namespace is intentionally omitted from JSON and checked by principal scope.
	return nil
}
