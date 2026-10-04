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
