package host

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

// Real Host pre-intent preparation, Endly and generated Datly consent/effects.
// The signed controller lifetime and renderer/OS provider are synthetic seams;
// no website or employee input is used.
func TestWebControllerPolicyPreparationUsesExistingAuthorityBeforeIntent(t *testing.T) {
	for _, permitted := range []bool{true, false} {
		t.Run(map[bool]string{true: "authorized", false: "revoked"}[permitted], func(t *testing.T) {
			f := newWebControlFixture(t)
			f.principal.ClientID = "controller:verified-fixture"
			f.principal.ClientName = "Verified controller fixture"
			f.dispatchedResult = automation.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}
			ctx := auth.WithPrincipal(context.Background(), f.principal)
			h := &Host{webControl: f.manager, users: map[string]User{f.principal.Namespace: {DesktopAccess: true}}}
			var err error
			h.durable, err = durable.New(durable.Options{SourceRoot: filepath.Join(t.TempDir(), "no-source"), StorageRoot: t.TempDir(), PrepareStepAuthority: h.prepareStepExecutor, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
				t.Fatal("web preparation acquired native input authority")
				return 0, nil
			}}, h.execute)
			if err != nil {
				t.Fatal(err)
			}
			defer h.durable.Close(context.Background())
			h.Runtime, err = automation.NewWithOptions(h.durable.Execute, automation.Options{PreparePlan: h.durable.PreparePlan, CompleteObjective: h.durable.CompleteObjective, AttachInitialOperation: func(c context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				_, err := h.durable.AttachOperation(c, p, run, revision, session, operation)
				return err
			}})
			if err != nil {
				t.Fatal(err)
			}
			h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: h.durable.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy, ControllerPolicy: func(c context.Context, actor auth.Principal) (context.Context, time.Time, func(), error) {
				if !permitted || actor.ClientID != f.principal.ClientID || auth.NativeHuman(c) || c.Err() != nil {
					return nil, time.Time{}, nil, auth.ErrUnauthorized
				}
				return c, time.Now().Add(2 * time.Minute), func() {}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			f.manager.options.Authorize = func(c context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
				return h.AuthorizeOperation(c, p, s, true, consent.Control)
			}
			session, err := h.Runtime.Open(ctx, "public controller fixture")
			if err != nil {
				t.Fatal(err)
			}
			defer h.Runtime.Close(ctx, session.SessionID)
			plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("message",exact:true).fill("Public fixture")`)
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[0].Target.Surface.TabID = f.ready.Authority.Document.QualifiedTabID()
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"field": {Kind: model.StringValue, String: "message"}}
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Public fixture automation"})
			if permitted {
				lease, err := h.AuthorizeOperation(ctx, f.principal, plan.Steps[0].Target.Surface, false, consent.Observe)
				if err != nil {
					t.Fatal("existing public read policy authorization failed", err)
				}
				lease.Release()
				scope, err := h.operationConsentScope(f.principal, plan.Steps[0].Target.Surface)
				if err != nil {
					t.Fatal(err)
				}
				permanent, err := h.consent.FindPermanentGrant(ctx, f.principal, consent.Operation{SessionID: session.SessionID, Scope: scope, Mode: consent.Control, Purpose: "Public fixture automation"})
				if err != nil || permanent != nil {
					t.Fatal("fixture policy grant became permanent trust", err)
				}
			}
			op, err := h.Runtime.StartPlanWithRequest(ctx, session.SessionID, "original-fill", *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			done, err := h.Runtime.Wait(wait, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if permitted {
				if done.Status != "succeeded" || f.dispatches != 1 || len(h.consent.policyGrants) != 1 {
					t.Fatal("existing controller policy did not prepare and dispatch once", done.Error)
				}
				repeated, err := h.Runtime.StartPlanWithRequest(ctx, session.SessionID, "original-fill", *plan, nil)
				if err != nil || repeated.ID != op.ID || f.dispatches != 1 {
					t.Fatal("original request was replayed")
				}
			} else if done.Status != "failed" || f.dispatches != 0 || f.qualifications != 0 || len(h.consent.policyGrants) != 0 {
				t.Fatal("revoked controller reached renderer qualification or input")
			}
			foreign := f.principal
			foreign.ClientID = "controller:foreign"
			if _, err = h.Runtime.Status(auth.WithPrincipal(ctx, foreign), session.SessionID, op.ID); !errors.Is(err, auth.ErrUnauthorized) {
				t.Fatal("foreign client inspected operation")
			}
		})
	}
}
