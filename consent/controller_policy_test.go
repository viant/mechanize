package consent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/data/consentrequests"
	"testing"

	"github.com/viant/mechanize/consent"
)

func TestSavedControllerPolicyCreatesBoundedGrantWithoutHumanApproval(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.CreatePolicyGrant(f.client, "fixture-session", input()); err == nil {
		t.Fatal("missing trusted callback admitted")
	}
	allowed := true
	options := f.options
	options.VerifyPolicy = func(context.Context, consent.Client) error {
		if !allowed {
			return errors.New("policy revoked")
		}
		return nil
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.CreatePolicyGrant(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	if grant.Decision != consent.AllowSession || grant.Permanent || grant.ID == "" {
		t.Fatal("wrong policy lifetime")
	}
	if _, err = service.Decide(f.client, grant.RequestID, consent.AllowUntilRevoked); err == nil {
		t.Fatal("requester gained human authority")
	}
	lease, err := service.Authorize(consent.RequireReusableGrant(f.client), operation(grant))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	snapshot, err := service.Snapshot(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Requests) != 0 || len(snapshot.Grants) != 1 {
		t.Fatal("policy grant left a user approval request")
	}
	allowed = false
	if _, err = service.CreatePolicyGrant(f.client, "fixture-session", input()); err == nil {
		t.Fatal("revoked policy minted grant")
	}
	allowed = true
	f.deny = true
	if _, err = service.CreatePolicyGrant(f.client, "fixture-session", input()); err == nil {
		t.Fatal("policy bypassed operator ceiling")
	}
}

func TestSavedControllerPolicyLostAuthorityBetweenCreateAndDecisionGrantsNothing(t *testing.T) {
	f := newFixture(t)
	checks := 0
	options := f.options
	var records []*consentrequests.Record
	options.Invoke = func(ctx context.Context, request exec.ComponentRequest) (any, error) {
		result, err := f.options.Invoke(ctx, request)
		if out, ok := result.(*consentrequests.ListRequestsOutput); ok && err == nil {
			records = out.Data
		}
		return result, err
	}
	options.VerifyPolicy = func(context.Context, consent.Client) error {
		checks++
		if checks > 1 {
			return errors.New("revoked")
		}
		return nil
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if grant, err := service.CreatePolicyGrant(f.client, "fixture-session", input()); err == nil || grant != nil {
		t.Fatal("lost policy produced grant")
	}
	snapshot, err := service.Snapshot(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Grants) != 0 || len(snapshot.Requests) != 0 {
		t.Fatal("interrupted managed request became human approval or authority")
	}
	if len(records) != 1 || records[0].RequestState == nil || *records[0].RequestState != "pending" || records[0].GrantState == nil || *records[0].GrantState != "none" || len(records[0].Audit) != 1 {
		t.Fatal("durable interrupted record or CREATE audit was removed")
	}
	row := records[0]
	requestID := *row.Id
	before, _ := json.Marshal(row)
	audit := row.Audit[0]
	if audit.Kind == nil || *audit.Kind != "create" || audit.ActorId == nil || *audit.ActorId != "controller-policy:"+*row.ClientId {
		t.Fatal("policy CREATE provenance absent")
	}
	// A fresh service has no volatile managed-request cache. Existing Datly
	// CREATE evidence alone must suppress the orphan, without deleting history.
	restarted, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = restarted.Snapshot(f.admin)
	if err != nil || len(snapshot.Requests) != 0 || len(snapshot.Grants) != 0 {
		t.Fatal("restart exposed managed pending request", err)
	}
	for _, decision := range []consent.Decision{consent.AllowOnce, consent.AllowSession, consent.AllowUntilRevoked, consent.Deny} {
		if _, err = restarted.Decide(f.admin, requestID, decision); err == nil {
			t.Fatal("human decided a managed request", decision)
		}
	}
	_, err = restarted.Snapshot(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(records[0])
	if !bytes.Equal(before, after) {
		t.Fatal("managed record/audit changed after refused human decisions")
	}
	ordinary, err := restarted.CreateRequest(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.ListRequests(f.admin)
	if err != nil || len(pending) != 1 || pending[0].ID != ordinary.ID {
		t.Fatal("ordinary human request suppressed", err)
	}
	if _, err = restarted.Decide(f.admin, ordinary.ID, consent.AllowSession); err != nil {
		t.Fatal("ordinary human decision changed", err)
	}
	snapshot, err = restarted.Snapshot(f.admin)
	if err != nil || len(snapshot.Requests) != 0 || len(snapshot.Grants) != 1 {
		t.Fatal("ordinary human grant changed", err)
	}
}
