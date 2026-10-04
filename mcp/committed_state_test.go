package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/engine/durable"
)

func TestCommittedStateFailurePreservesConfirmedRevision(t *testing.T) {
	state := durable.State{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 4, Status: "paused", NeedsAttention: true}
	r, rpcErr := failure(&durable.StatePatchCommittedError{State: state, Cause: errors.New("private callback detail")})
	if rpcErr != nil || r.IsError == nil || !*r.IsError {
		t.Fatal("committed failure reported as ordinary success")
	}
	raw, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Code      string        `json:"code"`
		Committed bool          `json:"committed"`
		State     durable.State `json:"state"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != "stateCommittedNeedsAttention" || !result.Committed || result.State.Revision != 4 || !result.State.NeedsAttention || result.State.Status != "paused" {
		t.Fatalf("commit evidence lost: %s", raw)
	}
	if strings.Contains(string(raw), "private callback detail") {
		t.Fatal("internal callback details exposed")
	}
}
