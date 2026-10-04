package data

import (
	"context"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
)

func TestApplicationPolicyWriteProofRequiresNativeHuman(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "human", []string{"consent:admin"})
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, _ = WithScope(ctx, Scope{Namespace: p.Namespace})
	json, _ := ApplicationPolicyJSON(ApplicationPolicy{DesktopWide: true})
	a := ApplicationPolicyAuthority{Namespace: p.Namespace, PolicyJSON: json, CreatedAt: "2026-10-02T00:00:00Z", UpdatedAt: "2026-10-02T00:00:00Z"}
	if _, err := RequireApplicationPolicyAuthority(WithApplicationPolicyAuthority(ctx, a), p.Namespace); err == nil {
		t.Fatal("admin claim self-authorized")
	}
	ctx, _ = auth.WithNativeHuman(ctx)
	if _, err := RequireApplicationPolicyAuthority(ctx, p.Namespace); err == nil {
		t.Fatal("missing write proof accepted")
	}
	if _, err := RequireApplicationPolicyAuthority(WithApplicationPolicyAuthority(ctx, a), p.Namespace); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ApplicationPolicyAuthority){func(a *ApplicationPolicyAuthority) { a.Namespace = strings.Repeat("b", 64) }, func(a *ApplicationPolicyAuthority) { a.ExpectedRevision = -1 }, func(a *ApplicationPolicyAuthority) {
		a.PolicyJSON = `{"desktopWide":true,"applications":[],"human":true}`
	}, func(a *ApplicationPolicyAuthority) { a.UpdatedAt = "forged" }} {
		bad := a
		mutate(&bad)
		if _, err := RequireApplicationPolicyAuthority(WithApplicationPolicyAuthority(ctx, bad), p.Namespace); err == nil {
			t.Fatal("invalid proof accepted")
		}
	}
}
