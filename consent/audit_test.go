package consent_test

import (
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/consentdecide"
	"github.com/viant/mechanize/data/consentrequests"
	"testing"
	"time"
)

func auditRows(t *testing.T, f *fixture, requestID string) []*consentrequests.Record {
	t.Helper()
	scope, _ := data.CurrentScope(f.admin)
	in := &consentrequests.ListRequestsInput{}
	in.SetNamespace(scope.Namespace)
	in.SetRecordID(requestID)
	ctx := data.WithConsentAuthority(f.admin, data.ConsentAuthority{Operation: "read", ActorID: "fixture-human", Now: int(time.Now().UnixMilli())})
	out, err := f.options.Invoke(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/consentrequests", Name: "consentrequests"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/consentrequests"}}, Input: in})
	if err != nil {
		t.Fatal(err)
	}
	return out.(*consentrequests.ListRequestsOutput).Data
}
func TestGeneratedImmutableConsentAudit(t *testing.T) {
	f := newFixture(t)
	request, err := f.service.CreateRequest(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	rows := auditRows(t, f, request.ID)
	if len(rows) != 1 || len(rows[0].Audit) != 1 {
		t.Fatalf("committed audit missing: %+v", rows)
	}
	current := rows[0]
	existing := current.Audit[0]
	raw, _ := json.Marshal(current)
	expected := map[string]any{}
	_ = json.Unmarshal(raw, &expected)
	delete(expected, "audit")
	at := int(time.Now().UnixMilli())
	expected["revision"] = float64(*current.Revision + 1)
	expected["requestState"] = "decided"
	expected["decision"] = "deny"
	payloadBytes, _ := json.Marshal(expected)
	payload := string(payloadBytes)
	authority := data.ConsentAuthority{Operation: "decide", ActorID: "fixture-human", AuditID: *existing.Id, Payload: payload, Now: at, Expected: expected}
	row := &consentdecide.Record{}
	row.SetNamespace(current.Namespace)
	row.SetId(current.Id)
	row.SetRevision(current.Revision)
	state, decision, kind, actor := "decided", "deny", "decide", "fixture-human"
	row.SetRequestState(&state)
	row.SetDecision(&decision)
	a := &consentdecide.Audit{}
	a.SetNamespace(current.Namespace)
	a.SetRequestId(current.Id)
	a.SetId(existing.Id)
	a.SetKind(&kind)
	a.SetActorId(&actor)
	a.SetCreatedAt(&at)
	a.SetPayloadJson(&payload)
	row.SetAudit([]*consentdecide.Audit{a})
	in := &consentdecide.DecideInput{}
	in.SetNamespace(*current.Namespace)
	in.SetConsentdecide([]*consentdecide.Record{row})
	_, err = f.options.Invoke(data.WithConsentAuthority(f.admin, authority), exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/consentdecide", Name: "consentdecide"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/consentdecide"}}, Input: in})
	if err == nil {
		t.Fatal("existing audit mutated")
	}
	after := auditRows(t, f, request.ID)
	if len(after[0].Audit) != 1 || *after[0].RequestState != "pending" || *after[0].Audit[0].Kind != "create" {
		t.Fatal("failed audit graph did not rollback")
	}
}
