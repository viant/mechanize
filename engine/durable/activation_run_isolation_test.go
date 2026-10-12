package durable

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// This pure graph test proves only the existing durable run boundary. A new run
// still requires independently qualified backend authority before BeginAttempt;
// it does not authorize bypassing any channel, consent or credential quarantine.
func TestActivationUnknownKeepsOriginalRunBlockedAndNewRunIndependent(t *testing.T) {
	originalMeta := integration.ExecutionMetadata{RunID: "original-run", PlanID: "original-plan", SessionID: "session", OperationID: "original-operation"}
	activation := model.Step{ID: "activate-tab", Action: "browser.activateTab"}
	oldAttempt := key("attempt", originalMeta.RunID, originalMeta.PlanID, activation.ID)
	original := &loadrun.Run{Id: pointer(originalMeta.RunID), PlanId: pointer(originalMeta.PlanID), Status: pointer("running"), EndlySessionId: pointer("session"), EndlyOperationId: pointer("original-operation"), Attempts: []*loadrun.Attempt{{Id: pointer(oldAttempt), RunId: pointer(originalMeta.RunID), PlanId: pointer(originalMeta.PlanID), StepId: pointer(activation.ID), State: pointer("intent")}}, Effects: []*loadrun.Effect{{Id: pointer(key("effect", oldAttempt)), RunId: pointer(originalMeta.RunID), AttemptId: pointer(oldAttempt), State: pointer("unknown"), BusinessKey: pointer("original-business-key"), EvidenceJson: pointer(`{"dispatchState":"unknown","verificationState":"unknown"}`)}}}
	before, _ := json.Marshal(original)
	dom := model.Step{ID: "fresh-dom-step", Action: "element.press"}
	for _, step := range []model.Step{activation, dom} {
		if _, _, e := admitStepAttempt(original, originalMeta, step, "original-business-key"); !errors.Is(e, ErrNeedsReconciliation) {
			t.Fatal("original UNKNOWN run admitted replay/dependent step", e)
		}
	}
	resumed := originalMeta
	resumed.Resumed = true
	if _, _, e := admitStepAttempt(original, resumed, activation, "original-business-key"); !errors.Is(e, ErrNeedsReconciliation) {
		t.Fatal("resume erased original UNKNOWN", e)
	}
	freshMeta := integration.ExecutionMetadata{RunID: "new-run", PlanID: "new-plan", SessionID: "session", OperationID: "new-operation"}
	fresh := &loadrun.Run{Id: pointer(freshMeta.RunID), PlanId: pointer(freshMeta.PlanID), Status: pointer("new")}
	attempt, previous, e := admitStepAttempt(fresh, freshMeta, dom, "new-business-key")
	if e != nil || previous != nil || attempt == oldAttempt || attempt != key("attempt", freshMeta.RunID, freshMeta.PlanID, dom.ID) {
		t.Fatal("independent run inherited activation outcome", e)
	}
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("new run rewrote original activation history")
	}
}
