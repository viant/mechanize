package durable

import (
	"context"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestStepAuthorityCannotReplaceOwnerOrConsent(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	p.ClientID = "verified-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "task"})
	other := p
	other.ClientID = "other-client"
	for _, prepare := range []func(context.Context, auth.Principal, model.Step) (context.Context, int, error){
		func(context.Context, auth.Principal, model.Step) (context.Context, int, error) { return nil, 1, nil },
		func(ctx context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
			return auth.WithPrincipal(ctx, other), 1, nil
		},
		func(ctx context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
			return auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "other", GrantID: "grant", Purpose: "task"}), 1, nil
		},
	} {
		b := &Builder{options: Options{PrepareStepAuthority: prepare}}
		if _, _, err := b.prepareStepAuthority(ctx, p, model.Step{}); err == nil {
			t.Fatal("executor provider replaced trusted invocation facts")
		}
	}
	b := &Builder{options: Options{PrepareStepAuthority: func(ctx context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
		return context.WithValue(ctx, authorityFixtureKey{}, true), 7, nil
	}}}
	prepared, epoch, err := b.prepareStepAuthority(ctx, p, model.Step{})
	if err != nil || epoch != 7 || prepared.Value(authorityFixtureKey{}) != true {
		t.Fatalf("pinned executor context lost: epoch=%d err=%v", epoch, err)
	}
}

type authorityFixtureKey struct{}

func TestStepAuthorityMayPinOmittedReusableGrantWithoutChangingInvocation(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	p.ClientID = "verified-client"
	binding := auth.ConsentBinding{SessionID: "session", Purpose: "task"}
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), binding)
	for _, tc := range []struct {
		grant, session, purpose string
		allowed                 bool
	}{
		{"selected-grant", "session", "task", true}, {"selected-grant", "foreign", "task", false}, {"selected-grant", "session", "other", false},
	} {
		b := &Builder{options: Options{PrepareStepAuthority: func(ctx context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
			return auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: tc.grant, SessionID: tc.session, Purpose: tc.purpose}), 7, nil
		}}}
		prepared, epoch, err := b.prepareStepAuthority(ctx, p, model.Step{})
		if (err == nil) != tc.allowed {
			t.Fatal("grant selection guard", tc, err)
		}
		if tc.allowed {
			actual, _ := auth.ConsentBindingFromContext(prepared)
			if actual.GrantID != tc.grant || epoch != 7 {
				t.Fatal("selected grant lost")
			}
		}
	}
	explicit := binding
	explicit.GrantID = "original-grant"
	b := &Builder{options: Options{PrepareStepAuthority: func(ctx context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
		next := explicit
		next.GrantID = "replacement-grant"
		return auth.WithConsentBinding(ctx, next), 7, nil
	}}}
	if _, _, err := b.prepareStepAuthority(auth.WithConsentBinding(ctx, explicit), p, model.Step{}); err == nil {
		t.Fatal("explicit grant replaced")
	}
}
