package consent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/consentconsume"
	"github.com/viant/mechanize/data/consentcreate"
	"github.com/viant/mechanize/data/consentdecide"
	"github.com/viant/mechanize/data/consentgrants"
	"github.com/viant/mechanize/data/consentrequests"
	"github.com/viant/mechanize/data/consentrevoke"
	"github.com/viant/mechanize/data/consenttrusted"
	"time"
)

type record struct {
	Namespace        string `json:"namespace"`
	ID               string `json:"id"`
	ClientID         string `json:"clientId"`
	ClientName       string `json:"clientName"`
	SessionID        string `json:"sessionId"`
	ScopeJSON        string `json:"scopeJson"`
	ModesJSON        string `json:"modesJson"`
	Purpose          string `json:"purpose"`
	DurationSeconds  int    `json:"durationSeconds"`
	CreatedAt        int    `json:"createdAt"`
	RequestExpiresAt int    `json:"requestExpiresAt"`
	RequestState     string `json:"requestState"`
	Decision         string `json:"decision"`
	GrantID          string `json:"grantId"`
	GrantCreatedAt   int    `json:"grantCreatedAt"`
	GrantExpiresAt   int    `json:"grantExpiresAt"`
	GrantState       string `json:"grantState"`
	RevocationState  string `json:"revocationState"`
	Revision         int    `json:"revision"`
}

func (r record) details() (Scope, []Mode, error) {
	var scope Scope
	var modes []Mode
	if err := json.Unmarshal([]byte(r.ScopeJSON), &scope); err != nil {
		return Scope{}, nil, err
	}
	if err := json.Unmarshal([]byte(r.ModesJSON), &modes); err != nil {
		return Scope{}, nil, err
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, nil, err
	}
	return scope, modes, nil
}
func (r record) request() (Request, error) {
	scope, modes, err := r.details()
	return Request{ID: r.ID, VerifiedClient: Client{ID: r.ClientID, DisplayName: r.ClientName, Verification: "verified"}, Scope: scope, Modes: modes, Purpose: r.Purpose, DurationSeconds: r.DurationSeconds, CreatedAt: time.UnixMilli(int64(r.CreatedAt)).UTC(), ExpiresAt: time.UnixMilli(int64(r.RequestExpiresAt)).UTC()}, err
}
func (r record) permanent() bool {
	return r.Decision == string(AllowUntilRevoked) && r.GrantExpiresAt == 0
}

func (r record) grant(now time.Time) (Grant, error) {
	scope, modes, err := r.details()
	state := r.GrantState
	if state == "active" && !r.permanent() && r.GrantExpiresAt <= int(now.UnixMilli()) {
		state = "expired"
	}
	expiresAt := time.UnixMilli(int64(r.GrantExpiresAt)).UTC()
	return Grant{Permanent: r.permanent(), ID: r.GrantID, RequestID: r.ID, ClientID: r.ClientID, Scope: scope, Modes: modes, Purpose: r.Purpose, DurationSeconds: r.DurationSeconds, Decision: Decision(r.Decision), CreatedAt: time.UnixMilli(int64(r.GrantCreatedAt)).UTC(), ExpiresAt: expiresAt, State: state, RevocationState: RevocationState(r.RevocationState)}, err
}
func (s *Service) read(ctx context.Context, pkg, id, actor string) ([]record, error) {
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, err
	}
	authority := data.ConsentAuthority{Operation: "read", ActorID: actor, Now: int(s.options.Now().UnixMilli())}
	var input any
	switch pkg {
	case "consentrequests":
		in := &consentrequests.ListRequestsInput{}
		in.SetNamespace(ns)
		in.SetRecordID(id)
		input = in
	case "consenttrusted":
		in := &consenttrusted.ListTrustedInput{}
		in.SetNamespace(ns)
		in.SetClientID(actor)
		input = in
	case "consentgrants":
		in := &consentgrants.ListGrantsInput{}
		in.SetNamespace(ns)
		in.SetRecordID(id)
		input = in
	default:
		return nil, fmt.Errorf("unknown consent reader")
	}
	result, err := s.invoke(ctx, pkg, "GET", input, authority)
	if err != nil {
		return nil, err
	}
	var rows []record
	switch out := result.(type) {
	case *consentrequests.ListRequestsOutput:
		for _, row := range out.Data {
			raw, err := json.Marshal(row)
			if err != nil {
				return nil, err
			}
			var r record
			if err = json.Unmarshal(raw, &r); err != nil {
				return nil, err
			}
			rows = append(rows, r)
		}
	case *consentgrants.ListGrantsOutput:
		for _, row := range out.Data {
			raw, err := json.Marshal(row)
			if err != nil {
				return nil, err
			}
			var r record
			if err = json.Unmarshal(raw, &r); err != nil {
				return nil, err
			}
			rows = append(rows, r)
		}
	case *consenttrusted.ListTrustedOutput:
		if len(out.Data) > 256 {
			return nil, fmt.Errorf("too many active permanent grants; human review required")
		}
		for _, row := range out.Data {
			raw, err := json.Marshal(row)
			if err != nil {
				return nil, err
			}
			var r record
			if err = json.Unmarshal(raw, &r); err != nil {
				return nil, err
			}
			rows = append(rows, r)
		}
	default:
		return nil, fmt.Errorf("unexpected generated consent reader result %T", result)
	}
	return rows, nil
}
func (s *Service) write(ctx context.Context, operation, actor string, r record, previous *record) error {
	auditID, err := randomID()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	expected := map[string]any{}
	if err = json.Unmarshal(raw, &expected); err != nil {
		return err
	}
	payload := string(raw)
	authority := data.ConsentAuthority{Operation: operation, ActorID: actor, AuditID: auditID, Payload: payload, Now: int(s.options.Now().UnixMilli()), Expected: expected}
	if operation == "create" {
		authority.Now = r.CreatedAt
	}
	if operation == "decide" && r.Decision != string(Deny) {
		authority.Now = r.GrantCreatedAt
	}
	var input any
	pkg := ""
	method := "PATCH"
	switch operation {
	case "create":
		pkg = "consentcreate"
		method = "POST"
		row := &consentcreate.Record{}
		row.SetNamespace(&r.Namespace)
		row.SetId(&r.ID)
		row.SetClientId(&r.ClientID)
		row.SetClientName(&r.ClientName)
		row.SetSessionId(&r.SessionID)
		row.SetScopeJson(&r.ScopeJSON)
		row.SetModesJson(&r.ModesJSON)
		row.SetPurpose(&r.Purpose)
		row.SetDurationSeconds(&r.DurationSeconds)
		row.SetCreatedAt(&r.CreatedAt)
		row.SetRequestExpiresAt(&r.RequestExpiresAt)
		row.SetRequestState(&r.RequestState)
		row.SetDecision(&r.Decision)
		row.SetGrantId(&r.GrantID)
		row.SetGrantCreatedAt(&r.GrantCreatedAt)
		row.SetGrantExpiresAt(&r.GrantExpiresAt)
		row.SetGrantState(&r.GrantState)
		row.SetRevocationState(&r.RevocationState)
		row.SetRevision(&r.Revision)
		a := &consentcreate.Audit{}
		a.SetNamespace(&r.Namespace)
		a.SetId(&auditID)
		a.SetRequestId(&r.ID)
		a.SetKind(&operation)
		a.SetActorId(&actor)
		a.SetCreatedAt(&authority.Now)
		a.SetPayloadJson(&payload)
		row.SetAudit([]*consentcreate.Audit{a})
		in := &consentcreate.CreateRequestInput{}
		in.SetNamespace(r.Namespace)
		in.SetConsentcreate([]*consentcreate.Record{row})
		input = in
	case "decide":
		pkg = "consentdecide"
		row := &consentdecide.Record{}
		row.SetNamespace(&r.Namespace)
		row.SetId(&r.ID)
		if r.ClientID != previous.ClientID {
			row.SetClientId(&r.ClientID)
		}
		if r.ClientName != previous.ClientName {
			row.SetClientName(&r.ClientName)
		}
		if r.SessionID != previous.SessionID {
			row.SetSessionId(&r.SessionID)
		}
		if r.ScopeJSON != previous.ScopeJSON {
			row.SetScopeJson(&r.ScopeJSON)
		}
		if r.ModesJSON != previous.ModesJSON {
			row.SetModesJson(&r.ModesJSON)
		}
		if r.Purpose != previous.Purpose {
			row.SetPurpose(&r.Purpose)
		}
		if r.DurationSeconds != previous.DurationSeconds {
			row.SetDurationSeconds(&r.DurationSeconds)
		}
		if r.CreatedAt != previous.CreatedAt {
			row.SetCreatedAt(&r.CreatedAt)
		}
		if r.RequestExpiresAt != previous.RequestExpiresAt {
			row.SetRequestExpiresAt(&r.RequestExpiresAt)
		}
		if r.RequestState != previous.RequestState {
			row.SetRequestState(&r.RequestState)
		}
		if r.Decision != previous.Decision {
			row.SetDecision(&r.Decision)
		}
		if r.GrantID != previous.GrantID {
			row.SetGrantId(&r.GrantID)
		}
		if r.GrantCreatedAt != previous.GrantCreatedAt {
			row.SetGrantCreatedAt(&r.GrantCreatedAt)
		}
		if r.GrantExpiresAt != previous.GrantExpiresAt {
			row.SetGrantExpiresAt(&r.GrantExpiresAt)
		}
		if r.GrantState != previous.GrantState {
			row.SetGrantState(&r.GrantState)
		}
		if r.RevocationState != previous.RevocationState {
			row.SetRevocationState(&r.RevocationState)
		}
		revision := previous.Revision
		row.SetRevision(&revision)
		a := &consentdecide.Audit{}
		a.SetNamespace(&r.Namespace)
		a.SetId(&auditID)
		a.SetRequestId(&r.ID)
		a.SetKind(&operation)
		a.SetActorId(&actor)
		a.SetCreatedAt(&authority.Now)
		a.SetPayloadJson(&payload)
		row.SetAudit([]*consentdecide.Audit{a})
		in := &consentdecide.DecideInput{}
		in.SetNamespace(r.Namespace)
		in.SetConsentdecide([]*consentdecide.Record{row})
		input = in
	case "consume":
		pkg = "consentconsume"
		row := &consentconsume.Record{}
		row.SetNamespace(&r.Namespace)
		row.SetId(&r.ID)
		if r.ClientID != previous.ClientID {
			row.SetClientId(&r.ClientID)
		}
		if r.ClientName != previous.ClientName {
			row.SetClientName(&r.ClientName)
		}
		if r.SessionID != previous.SessionID {
			row.SetSessionId(&r.SessionID)
		}
		if r.ScopeJSON != previous.ScopeJSON {
			row.SetScopeJson(&r.ScopeJSON)
		}
		if r.ModesJSON != previous.ModesJSON {
			row.SetModesJson(&r.ModesJSON)
		}
		if r.Purpose != previous.Purpose {
			row.SetPurpose(&r.Purpose)
		}
		if r.DurationSeconds != previous.DurationSeconds {
			row.SetDurationSeconds(&r.DurationSeconds)
		}
		if r.CreatedAt != previous.CreatedAt {
			row.SetCreatedAt(&r.CreatedAt)
		}
		if r.RequestExpiresAt != previous.RequestExpiresAt {
			row.SetRequestExpiresAt(&r.RequestExpiresAt)
		}
		if r.RequestState != previous.RequestState {
			row.SetRequestState(&r.RequestState)
		}
		if r.Decision != previous.Decision {
			row.SetDecision(&r.Decision)
		}
		if r.GrantID != previous.GrantID {
			row.SetGrantId(&r.GrantID)
		}
		if r.GrantCreatedAt != previous.GrantCreatedAt {
			row.SetGrantCreatedAt(&r.GrantCreatedAt)
		}
		if r.GrantExpiresAt != previous.GrantExpiresAt {
			row.SetGrantExpiresAt(&r.GrantExpiresAt)
		}
		if r.GrantState != previous.GrantState {
			row.SetGrantState(&r.GrantState)
		}
		if r.RevocationState != previous.RevocationState {
			row.SetRevocationState(&r.RevocationState)
		}
		revision := previous.Revision
		row.SetRevision(&revision)
		a := &consentconsume.Audit{}
		a.SetNamespace(&r.Namespace)
		a.SetId(&auditID)
		a.SetRequestId(&r.ID)
		a.SetKind(&operation)
		a.SetActorId(&actor)
		a.SetCreatedAt(&authority.Now)
		a.SetPayloadJson(&payload)
		row.SetAudit([]*consentconsume.Audit{a})
		in := &consentconsume.ConsumeOnceInput{}
		in.SetNamespace(r.Namespace)
		in.SetConsentconsume([]*consentconsume.Record{row})
		input = in
	case "revoke":
		pkg = "consentrevoke"
		row := &consentrevoke.Record{}
		row.SetNamespace(&r.Namespace)
		row.SetId(&r.ID)
		if r.ClientID != previous.ClientID {
			row.SetClientId(&r.ClientID)
		}
		if r.ClientName != previous.ClientName {
			row.SetClientName(&r.ClientName)
		}
		if r.SessionID != previous.SessionID {
			row.SetSessionId(&r.SessionID)
		}
		if r.ScopeJSON != previous.ScopeJSON {
			row.SetScopeJson(&r.ScopeJSON)
		}
		if r.ModesJSON != previous.ModesJSON {
			row.SetModesJson(&r.ModesJSON)
		}
		if r.Purpose != previous.Purpose {
			row.SetPurpose(&r.Purpose)
		}
		if r.DurationSeconds != previous.DurationSeconds {
			row.SetDurationSeconds(&r.DurationSeconds)
		}
		if r.CreatedAt != previous.CreatedAt {
			row.SetCreatedAt(&r.CreatedAt)
		}
		if r.RequestExpiresAt != previous.RequestExpiresAt {
			row.SetRequestExpiresAt(&r.RequestExpiresAt)
		}
		if r.RequestState != previous.RequestState {
			row.SetRequestState(&r.RequestState)
		}
		if r.Decision != previous.Decision {
			row.SetDecision(&r.Decision)
		}
		if r.GrantID != previous.GrantID {
			row.SetGrantId(&r.GrantID)
		}
		if r.GrantCreatedAt != previous.GrantCreatedAt {
			row.SetGrantCreatedAt(&r.GrantCreatedAt)
		}
		if r.GrantExpiresAt != previous.GrantExpiresAt {
			row.SetGrantExpiresAt(&r.GrantExpiresAt)
		}
		if r.GrantState != previous.GrantState {
			row.SetGrantState(&r.GrantState)
		}
		if r.RevocationState != previous.RevocationState {
			row.SetRevocationState(&r.RevocationState)
		}
		revision := previous.Revision
		row.SetRevision(&revision)
		a := &consentrevoke.Audit{}
		a.SetNamespace(&r.Namespace)
		a.SetId(&auditID)
		a.SetRequestId(&r.ID)
		a.SetKind(&operation)
		a.SetActorId(&actor)
		a.SetCreatedAt(&authority.Now)
		a.SetPayloadJson(&payload)
		row.SetAudit([]*consentrevoke.Audit{a})
		in := &consentrevoke.RevokeInput{}
		in.SetNamespace(r.Namespace)
		in.SetConsentrevoke([]*consentrevoke.Record{row})
		input = in
	default:
		return fmt.Errorf("unknown consent writer")
	}
	_, err = s.invoke(ctx, pkg, method, input, authority)
	return err
}
