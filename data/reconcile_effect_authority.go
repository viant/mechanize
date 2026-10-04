package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

// ReconcileEffectEvidence is minted only after a host-selected, qualified read
// contract evaluates the original effect. UI evidence cannot claim business success.
type ReconcileEffectEvidence struct {
	ContractID        string                 `json:"contractId"`
	ContractHash      string                 `json:"contractHash"`
	RequiredAuthority objective.Authority    `json:"requiredAuthority"`
	FreshnessMs       int64                  `json:"freshnessMs"`
	Result            objective.Result       `json:"result"`
	StepResult        integration.StepResult `json:"stepResult"`
}

// ReconcileEffectAuthority is trusted in-process metadata, never a tool input.
// The host holds an actual stopped-runtime guard until commit and refresh.
type ReconcileEffectAuthority struct {
	Namespace, RunID, PlanID, StepID, AttemptID, EffectID, BusinessKey string
	OriginalStepHash, OriginalEvidenceJSON                             string
	AuditID, MilestoneID                                               string
	RunRevision, EffectRevision, AuditSequence                         int
	Now                                                                string
	Evidence                                                           ReconcileEffectEvidence
	EvidenceJSON, AuditPayloadJSON                                     string
}
type reconcileEffectAuthorityKey struct{}

type ReconcileEffectAudit struct {
	PriorRunRevision     int                     `json:"priorRunRevision"`
	PriorEffectRevision  int                     `json:"priorEffectRevision"`
	RunID                string                  `json:"runId"`
	PlanID               string                  `json:"planId"`
	StepID               string                  `json:"stepId"`
	AttemptID            string                  `json:"attemptId"`
	EffectID             string                  `json:"effectId"`
	BusinessKey          string                  `json:"businessKey"`
	OriginalStepHash     string                  `json:"originalStepHash"`
	OriginalEvidenceHash string                  `json:"originalEvidenceHash"`
	Evidence             ReconcileEffectEvidence `json:"evidence"`
}

func ReconcileEffectHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func ReconcileEffectStepHash(step model.Step) (string, error) {
	raw, err := json.Marshal(step)
	if err != nil {
		return "", err
	}
	return ReconcileEffectHash(raw), nil
}
func ReconcileEffectKey(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return ReconcileEffectHash(raw)
}
func reconcileID(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validateReconcileAuthority(ctx context.Context, a ReconcileEffectAuthority) error {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != a.Namespace {
		return auth.ErrUnauthorized
	}
	if err := RequireStateMutationPermit(ctx, a.Namespace, a.RunID); err != nil {
		return err
	}
	for _, id := range []string{a.RunID, a.PlanID, a.StepID, a.AttemptID, a.EffectID, a.AuditID, a.MilestoneID, a.Evidence.ContractID} {
		if !reconcileID(id) {
			return errors.New("bounded exact reconciliation identities required")
		}
	}
	if !namespacePattern.MatchString(a.OriginalStepHash) || !namespacePattern.MatchString(a.Evidence.ContractHash) || a.BusinessKey == "" || len(a.BusinessKey) > 65536 || a.RunRevision < 1 || a.EffectRevision < 1 || a.AuditSequence < 1 {
		return errors.New("complete original reconciliation correlation required")
	}
	proof := a.Evidence
	if proof.RequiredAuthority != objective.Observational && proof.RequiredAuthority != objective.Authoritative {
		return errors.New("explicit qualified reconciliation authority required")
	}
	if proof.Result.Truth != objective.True || (proof.Result.Authority != proof.RequiredAuthority && !(proof.RequiredAuthority == objective.Observational && proof.Result.Authority == objective.Authoritative)) || len(proof.Result.Evidence) == 0 {
		return errors.New("qualified true reconciliation evidence required")
	}
	for _, e := range proof.Result.Evidence {
		if !reconcileID(e.Kind) || e.Reference == "" || len(e.Reference) > 65536 {
			return errors.New("bounded reconciliation evidence references required")
		}
	}
	if proof.RequiredAuthority == objective.Authoritative {
		for _, e := range proof.Result.Evidence {
			if e.BusinessKey != a.BusinessKey {
				return errors.New("authoritative reconciliation business key mismatch")
			}
		}
	}
	age := time.Since(proof.Result.ObservedAt)
	if proof.Result.ObservedAt.IsZero() || age < 0 || proof.FreshnessMs < 1 || proof.FreshnessMs > 30000 || age > time.Duration(proof.FreshnessMs)*time.Millisecond {
		return errors.New("reconciliation evidence is stale")
	}
	at, err := time.Parse(time.RFC3339Nano, a.Now)
	if err != nil || at.After(time.Now().Add(time.Second)) || time.Since(at) > 30*time.Second {
		return errors.New("bounded reconciliation audit time required")
	}
	if proof.StepResult.VerificationState != "verified" || proof.StepResult.Postcondition == nil || !reflect.DeepEqual(*proof.StepResult.Postcondition, proof.Result) {
		return errors.New("verified step result must bind the trusted evaluation")
	}
	var old integration.StepResult
	if len(a.OriginalEvidenceJSON) > 4<<20 || json.Unmarshal([]byte(a.OriginalEvidenceJSON), &old) != nil {
		return errors.New("original effect evidence required")
	}
	if proof.StepResult.DispatchState != old.DispatchState || !reflect.DeepEqual(proof.StepResult.Value, old.Value) {
		return errors.New("original dispatch and bound output are immutable")
	}
	if proof.StepResult.DispatchState != "dispatched" && proof.StepResult.DispatchState != "unknown" {
		return errors.New("only uncertain dispatched effects can be confirmed")
	}
	return nil
}

func WithReconcileEffectAuthority(ctx context.Context, a ReconcileEffectAuthority) (context.Context, error) {
	if err := validateReconcileAuthority(ctx, a); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a.Evidence.StepResult)
	if err != nil {
		return nil, err
	}
	a.EvidenceJSON = string(raw)
	audit := ReconcileEffectAudit{PriorRunRevision: a.RunRevision, PriorEffectRevision: a.EffectRevision, RunID: a.RunID, PlanID: a.PlanID, StepID: a.StepID, AttemptID: a.AttemptID, EffectID: a.EffectID, BusinessKey: a.BusinessKey, OriginalStepHash: a.OriginalStepHash, OriginalEvidenceHash: ReconcileEffectHash([]byte(a.OriginalEvidenceJSON)), Evidence: a.Evidence}
	raw, err = json.Marshal(audit)
	if err != nil {
		return nil, err
	}
	a.AuditPayloadJSON = string(raw)
	// Encoding detaches caller-owned maps, slices and pointer evidence from authority.
	raw, err = json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, reconcileEffectAuthorityKey{}, string(raw)), nil
}
func RequireReconcileEffectAuthority(ctx context.Context) (ReconcileEffectAuthority, error) {
	raw, ok := ctx.Value(reconcileEffectAuthorityKey{}).(string)
	if !ok {
		return ReconcileEffectAuthority{}, errors.New("trusted reconciliation evaluation capability required")
	}
	var a ReconcileEffectAuthority
	if json.Unmarshal([]byte(raw), &a) != nil {
		return a, errors.New("invalid reconciliation authority")
	}
	if err := validateReconcileAuthority(ctx, a); err != nil {
		return ReconcileEffectAuthority{}, err
	}
	return a, nil
}
