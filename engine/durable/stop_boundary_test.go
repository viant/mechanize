package durable

import (
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
)

func TestStoppedBoundaryAdoptionRequiresCommittedOriginalCorrelation(t *testing.T) {
	req := StopBoundaryRequest{RunID: "run", PlanID: "plan", RequestID: "request", ExpectedRunRevision: 2}
	auditID := data.StopBoundaryAuditID("namespace", req.RunID, req.RequestID)
	fixture := func() *loadrun.Run {
		payload, err := json.Marshal(data.StopBoundaryAudit{PriorRunRevision: 2, RunID: "run", PlanID: "plan", RequestID: "request", EndlySessionID: "session", EndlyOperationID: "operation", QuiescenceProof: "held-native-fence"})
		if err != nil {
			t.Fatal(err)
		}
		return &loadrun.Run{Revision: pointer(3), EndlySessionId: pointer("session"), EndlyOperationId: pointer("operation"), Events: []*loadrun.Event{{Id: pointer(auditID), RunId: pointer("run"), Kind: pointer("stopped_boundary"), PayloadJson: pointer(string(payload))}}}
	}
	for _, test := range []struct {
		name   string
		mutate func(*loadrun.Run)
	}{
		{"revision not committed", func(r *loadrun.Run) { r.Revision = pointer(2) }},
		{"missing revision", func(r *loadrun.Run) { r.Revision = nil }},
		{"changed operation", func(r *loadrun.Run) { r.EndlyOperationId = pointer("new-operation") }},
		{"changed session", func(r *loadrun.Run) { r.EndlySessionId = pointer("new-session") }},
		{"wrong event kind", func(r *loadrun.Run) { r.Events[0].Kind = pointer("outcome") }},
		{"wrong run", func(r *loadrun.Run) { r.Events[0].RunId = pointer("foreign-run") }},
		{"effect event", func(r *loadrun.Run) { r.Events[0].AttemptId = pointer("attempt") }},
		{"duplicate audit", func(r *loadrun.Run) { r.Events = append(r.Events, r.Events[0]) }},
		{"unknown payload field", func(r *loadrun.Run) {
			s := *r.Events[0].PayloadJson
			r.Events[0].PayloadJson = pointer(s[:len(s)-1] + `,"success":true}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := fixture()
			test.mutate(r)
			if adopted, err := stoppedBoundaryReadback(r, req, auditID); err == nil || adopted {
				t.Fatalf("invalid audit adopted: %v %v", adopted, err)
			}
		})
	}
	if adopted, err := stoppedBoundaryReadback(fixture(), req, auditID); err != nil || !adopted {
		t.Fatalf("exact committed audit rejected: %v %v", adopted, err)
	}
	r := fixture()
	r.Revision = pointer(5)
	if adopted, err := stoppedBoundaryReadback(r, req, auditID); err != nil || !adopted {
		t.Fatalf("later revision lost original audit: %v %v", adopted, err)
	}
	r.Events = nil
	if adopted, err := stoppedBoundaryReadback(r, req, auditID); err != nil || adopted {
		t.Fatalf("missing audit adopted: %v %v", adopted, err)
	}
}
