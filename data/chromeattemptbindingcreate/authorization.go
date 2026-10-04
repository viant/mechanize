package chromeattemptbindingcreate

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

func same(p *string, value string) bool   { return p != nil && *p == value }
func sameNumber(p *int, value int64) bool { return p != nil && int64(*p) == value }
func (in *CreateChromeAttemptBindingInput) Init(ctx context.Context) error {
	a, err := data.RequireChromeAttemptBindingAuthority(ctx)
	if err != nil {
		return err
	}
	if in.Namespace != a.Namespace || in.ClientID != a.ClientID || in.AttemptID != a.DurableAttemptID || in.EffectID != a.EffectID || in.RunID != a.RunID || in.PlanID != a.PlanID || len(in.CreateChromeAttemptBinding) != 1 {
		return errors.New("exact trusted binding input required")
	}
	// These independent view fields are generated database reads. The writable
	// body's auxiliary relations are never accepted as committed intent facts.
	if len(in.IntentRead) != 1 || len(in.AttemptRead) != 1 || len(in.RunRead) != 1 || len(in.PlanRead) != 1 || len(in.IntentEventRead) != 1 {
		return errors.New("one actual committed intent/attempt/run/plan/event required")
	}
	e, attempt, run, plan, event := in.IntentRead[0], in.AttemptRead[0], in.RunRead[0], in.PlanRead[0], in.IntentEventRead[0]
	if e == nil || !same(e.Namespace, a.Namespace) || !same(e.Id, a.EffectID) || !same(e.AttemptId, a.DurableAttemptID) || !same(e.RunId, a.RunID) || !same(e.State, "intent") || !sameNumber(e.Revision, 1) || e.EvidenceJson != nil || e.BusinessKey == nil || data.ChromeAttemptRawDigest(*e.BusinessKey) != a.BusinessKeyDigest {
		return errors.New("actual pristine committed effect intent differs")
	}
	if attempt == nil || !same(attempt.Namespace, a.Namespace) || !same(attempt.Id, a.DurableAttemptID) || !same(attempt.RunId, a.RunID) || !same(attempt.PlanId, a.PlanID) || !same(attempt.StepId, a.StepID) || !same(attempt.State, "intent") || !sameNumber(attempt.LeaseEpoch, a.RendererLeaseGeneration) {
		return errors.New("actual committed attempt/renderer generation differs")
	}
	if run == nil || !same(run.Namespace, a.Namespace) || !same(run.Id, a.RunID) || !same(run.PlanId, a.PlanID) || !sameNumber(run.Revision, int64(a.CommittedRunRevision)) || !same(run.EndlySessionId, a.EndlySessionID) || !same(run.EndlyOperationId, a.EndlyOperationID) || (!same(run.Status, "running") && !same(run.Status, "new")) {
		return errors.New("actual active run correlation differs")
	}
	if plan == nil || !same(plan.Namespace, a.Namespace) || !same(plan.Id, a.PlanID) || !same(plan.ContentHash, a.PlanContentDigest) || plan.ContentJson == nil || data.ChromeAttemptRawDigest(*plan.ContentJson) != a.PlanContentDigest {
		return errors.New("immutable plan content digest differs")
	}
	var envelope struct {
		Plan model.Plan `json:"plan"`
	}
	if json.Unmarshal([]byte(*plan.ContentJson), &envelope) != nil || envelope.Plan.Validate() != nil || a.StepIndex >= len(envelope.Plan.Steps) {
		return errors.New("actual immutable step unavailable")
	}
	step := envelope.Plan.Steps[a.StepIndex]
	if step.ID != a.StepID || step.Target.Surface.Kind != "web" || (step.Action != "element.press" && step.Action != "element.fill") || data.ChromeRetirementDigest(step) != a.StepDigest {
		return errors.New("binding differs from original immutable web step")
	}
	if event == nil || !same(event.Namespace, a.Namespace) || !same(event.RunId, a.RunID) || !same(event.AttemptId, a.DurableAttemptID) || !same(event.Kind, "intent") || !same(event.Id, data.ChromeRetirementDigest([]string{"intent-event", a.DurableAttemptID})) {
		return errors.New("actual original committed intent audit unavailable")
	}
	return nil
}
