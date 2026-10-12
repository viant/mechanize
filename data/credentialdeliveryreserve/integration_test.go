package credentialdeliveryreserve_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	finish "github.com/viant/mechanize/data/credentialdeliveryfinish"
	get "github.com/viant/mechanize/data/credentialdeliveryget"
	reserve "github.com/viant/mechanize/data/credentialdeliveryreserve"
	prep "github.com/viant/mechanize/data/credentialpreparationreserve"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/xdatly/handler"
)

func mark(v any) {
	rv := reflect.ValueOf(v)
	e := rv.Elem()
	for i := 0; i < e.NumField(); i++ {
		f := e.Field(i)
		name := e.Type().Field(i).Name
		if name == "Has" || f.Kind() == reflect.Pointer && f.IsNil() {
			continue
		}
		m := rv.MethodByName("Set" + name)
		if m.IsValid() {
			m.Call([]reflect.Value{f})
		}
	}
}
func fixtureRecord(p auth.Principal) data.CredentialDeliveryRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return data.CredentialDeliveryRecord{PurposeHash: data.CredentialDeliveryPurposeHash("login"), Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "session", AttemptID: strings.Repeat("a", 64), SelectionID: strings.Repeat("b", 64), SelectedRevision: strings.Repeat("c", 64), GrantID: "grant", Origin: "https://bank.invalid", ProfileChannel: "profile", BrowserInstance: "browser", DocumentID: "doc", DocumentGeneration: 1, TabID: 7, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("d", 64), RendererLeaseID: "lease", RendererLeaseGeneration: 1, ChromeStartToken: "123:456", NativeHostStartToken: "123:789", DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
}
func reserveInput(r data.CredentialDeliveryRecord) *reserve.CredentialDeliveryReserveInput {
	raw, _ := json.Marshal(r)
	row := &reserve.Delivery{}
	json.Unmarshal(raw, row)
	mark(row)
	audit := &reserve.Audit{}
	audit.SetNamespace(&r.Namespace)
	audit.SetClientId(&r.ClientID)
	audit.SetAttemptId(&r.AttemptID)
	audit.SetRevision(&r.Revision)
	audit.SetDispatchState(&r.DispatchState)
	audit.SetProtectionState(&r.ProtectionState)
	audit.SetCreatedAt(&r.UpdatedAt)
	row.SetAudit([]*reserve.Audit{audit})
	in := &reserve.CredentialDeliveryReserveInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetAttemptID(r.AttemptID)
	in.SetCredentialDeliveryReserve([]*reserve.Delivery{row})
	return in
}
func finishInput(before, after data.CredentialDeliveryRecord) *finish.CredentialDeliveryFinishInput {
	raw, _ := json.Marshal(after)
	row := &finish.Delivery{}
	json.Unmarshal(raw, row)
	mark(row)
	row.SetRevision(&before.Revision)
	audit := &finish.Audit{}
	audit.SetNamespace(&after.Namespace)
	audit.SetClientId(&after.ClientID)
	audit.SetAttemptId(&after.AttemptID)
	audit.SetRevision(&after.Revision)
	audit.SetDispatchState(&after.DispatchState)
	audit.SetProtectionState(&after.ProtectionState)
	audit.SetCreatedAt(&after.UpdatedAt)
	row.SetAudit([]*finish.Audit{audit})
	in := &finish.CredentialDeliveryFinishInput{}
	in.SetNamespace(after.Namespace)
	in.SetClientID(after.ClientID)
	in.SetAttemptID(after.AttemptID)
	in.SetCredentialDeliveryFinish([]*finish.Delivery{row})
	return in
}
func TestGeneratedPrivateDeliveryReservationAndCAS(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	p, _ := auth.NewPrincipal("fixture", "", "private-delivery", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	ctx, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(ctx, root, t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	invoke := func(ctx context.Context, pkg, name, method string, input any) (any, bool, error) {
		committed := false
		v, e := server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
		return v, committed, e
	}
	r := fixtureRecord(p)
	bound, revoke, err := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Record: r}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	if _, _, e := invoke(ctx, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(r)); e == nil {
		t.Fatal("missing private authority accepted")
	}
	other := p
	other.ClientID = "foreign-client"
	if _, _, e := invoke(auth.WithPrincipal(bound, other), "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(r)); e == nil {
		t.Fatal("foreign client borrowed sealed delivery authority")
	}
	bad := reserveInput(r)
	value := "dispatched"
	bad.CredentialDeliveryReserve[0].SetDispatchState(&value)
	if _, _, e := invoke(bound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", bad); e == nil {
		t.Fatal("nonunknown initial reservation accepted")
	}
	if _, _, e := invoke(bound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(r)); e == nil {
		t.Fatal("child admitted without preparation")
	}
	preparation := data.CredentialPreparationRecord{Namespace: r.Namespace, ClientID: r.ClientID, SessionID: r.SessionID, PreparationID: r.SelectionID, GrantID: r.GrantID, PurposeHash: r.PurposeHash, Origin: r.Origin, SelectedRevision: r.SelectedRevision, ProtectionState: "held", Revision: 1, CreatedAt: r.CreatedAt}
	preCtx, preRevoke, e := data.WithCredentialPreparationAuthority(ctx, preparation, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer preRevoke()
	raw, _ := json.Marshal(preparation)
	row := &prep.Preparation{}
	json.Unmarshal(raw, row)
	mark(row)
	pin := &prep.CredentialPreparationReserveInput{}
	pin.SetNamespace(r.Namespace)
	pin.SetClientID(r.ClientID)
	pin.SetPreparationID(r.SelectionID)
	pin.SetCredentialPreparationReserve([]*prep.Preparation{row})
	if _, committed, e := invoke(preCtx, "credentialpreparationreserve", "CredentialPreparationReserve", "POST", pin); e != nil || !committed {
		t.Fatal("preparation not committed", e)
	}
	for _, field := range []string{"selection", "client", "session", "grant", "purpose", "origin", "revision"} {
		mismatch := r
		probeCtx := ctx
		actor := p
		consent, _ := auth.ConsentBindingFromContext(ctx)
		switch field {
		case "selection":
			mismatch.SelectionID = strings.Repeat("f", 64)
		case "client":
			actor.ClientID = "other"
			mismatch.ClientID = actor.ClientID
			probeCtx = auth.WithPrincipal(probeCtx, actor)
		case "session":
			consent.SessionID = "other"
			mismatch.SessionID = consent.SessionID
		case "grant":
			consent.GrantID = "other"
			mismatch.GrantID = consent.GrantID
		case "purpose":
			consent.Purpose = "other"
			mismatch.PurposeHash = data.CredentialDeliveryPurposeHash(consent.Purpose)
		case "origin":
			mismatch.Origin = "https://other.invalid"
		case "revision":
			mismatch.SelectedRevision = strings.Repeat("e", 64)
		}
		probeCtx = auth.WithConsentBinding(probeCtx, consent)
		mismatchCtx, stop, e := data.WithCredentialDeliveryAuthority(probeCtx, data.CredentialDeliveryAuthority{Record: mismatch}, func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		_, _, e = invoke(mismatchCtx, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(mismatch))
		stop()
		if e == nil {
			t.Fatal("uncorrelated preparation admitted child", field)
		}
	}
	if _, committed, e := invoke(bound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(r)); e != nil || !committed {
		t.Fatalf("reservation not committed: %v", e)
	}
	in := &get.CredentialDeliveryGetInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetAttemptID(r.AttemptID)
	valueOut, _, err := invoke(bound, "credentialdeliveryget", "CredentialDeliveryGet", "GET", in)
	if err != nil {
		t.Fatal(err)
	}
	out := valueOut.(*get.CredentialDeliveryGetOutput)
	if len(out.Data) != 1 || *out.Data[0].DispatchState != "unknown" || *out.Data[0].ProtectionState != "held" || len(out.Data[0].Audit) != 1 {
		t.Fatal("unknown reservation readback missing")
	}
	if _, _, e := invoke(bound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(r)); e == nil {
		t.Fatal("same attempt replay accepted")
	}
	second := r
	second.AttemptID = strings.Repeat("e", 64)
	secondBound, stop, e := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Record: second}, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	if _, _, e = invoke(secondBound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(second)); e == nil {
		t.Fatal("unresolved owner admitted a second delivery")
	}
	after := r
	after.Revision = 2
	after.DispatchState = "dispatched"
	after.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	finished, release, e := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Before: &r, Record: after}, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, committed, e := invoke(finished, "credentialdeliveryfinish", "CredentialDeliveryFinish", "PATCH", finishInput(r, after)); e != nil || !committed {
		t.Fatalf("finish not committed: %v", e)
	}
	if _, _, e = invoke(finished, "credentialdeliveryfinish", "CredentialDeliveryFinish", "PATCH", finishInput(r, after)); e == nil {
		t.Fatal("stale finish CAS accepted")
	}
	valueOut, _, err = invoke(finished, "credentialdeliveryget", "CredentialDeliveryGet", "GET", in)
	if err != nil {
		t.Fatal(err)
	}
	out = valueOut.(*get.CredentialDeliveryGetOutput)
	if len(out.Data) != 1 || *out.Data[0].Revision != 2 || *out.Data[0].ProtectionState != "held" || len(out.Data[0].Audit) != 2 {
		t.Fatal("dispatch wrongly released protection")
	}
	// A confirmed fill may be followed by a distinct submit under the exact
	// same preparation. The previous unknown attempt above remained exclusive.
	changed := second
	changed.AttemptID = strings.Repeat("f", 64)
	changed.ChannelEpoch = "substituted-channel"
	changedCtx, cancelChanged, e := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Record: changed}, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = invoke(changedCtx, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(changed)); e == nil {
		t.Fatal("substituted lineage admitted")
	}
	cancelChanged()
	if _, committed, e := invoke(secondBound, "credentialdeliveryreserve", "CredentialDeliveryReserve", "POST", reserveInput(second)); e != nil || !committed {
		t.Fatal("confirmed parent could not reserve distinct private continuation", e)
	}
	closed := after
	closed.Revision = 3
	closed.ProtectionState = "closed"
	if _, _, e = data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Before: &after, Record: closed}, func(context.Context) error { return nil }); e == nil {
		t.Fatal("unqualified cleanup accepted")
	}
	release()
	if _, _, e = invoke(finished, "credentialdeliveryget", "CredentialDeliveryGet", "GET", in); e == nil {
		t.Fatal("revoked private context accepted")
	}
}
