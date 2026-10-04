package objective

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

type adapterFunc func(context.Context, auth.Principal, string, map[string]model.Value) (Result, error)

func (f adapterFunc) Evaluate(ctx context.Context, p auth.Principal, n string, v map[string]model.Value) (Result, error) {
	return f(ctx, p, n, v)
}
func TestEvidenceAuthorityFreshnessAndWrongBusinessKey(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	cases := []struct {
		name   string
		result Result
		err    error
		want   Truth
	}{{"verified", Result{Truth: True, Authority: Authoritative, ObservedAt: time.Now(), Evidence: []Evidence{{Kind: "receipt", Reference: "fixture-order", BusinessKey: "case-1"}}}, nil, True}, {"wrong receipt key", Result{Truth: True, Authority: Authoritative, ObservedAt: time.Now(), Evidence: []Evidence{{Kind: "receipt", Reference: "other-order", BusinessKey: "case-2"}}}, nil, Unknown}, {"stale", Result{Truth: True, Authority: Authoritative, ObservedAt: time.Now().Add(-time.Hour), Evidence: []Evidence{{Kind: "receipt", Reference: "old"}}}, nil, Unknown}, {"visual only", Result{Truth: True, Authority: Visual, ObservedAt: time.Now(), Evidence: []Evidence{{Kind: "image", Reference: "img"}}}, nil, Unknown}, {"offline", Result{}, errors.New("secret backend detail"), Unknown}, {"missing evidence", Result{Truth: True, Authority: Authoritative, ObservedAt: time.Now()}, nil, Unknown}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := New(map[string]Enrollment{"orders": {Adapter: adapterFunc(func(_ context.Context, _ auth.Principal, _ string, inputs map[string]model.Value) (Result, error) {
				if inputs["case"].String != "case-1" {
					return Result{Truth: False, Authority: Authoritative, ObservedAt: time.Now(), Evidence: []Evidence{{Kind: "lookup", Reference: "wrong-key", BusinessKey: inputs["case"].String}}}, nil
				}
				return tc.result, tc.err
			}), BusinessKeyInput: "case", MaximumAuthority: Authoritative, AllowedPredicates: map[string]bool{"exists": true}}})
			if err != nil {
				t.Fatal(err)
			}
			predicate := model.Predicate{Kind: "adapter", Adapter: "orders", Name: "exists", Inputs: map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: "input.case"}}, TimeoutMs: 1000, FreshnessMs: 5000, RequiredAuthority: "authoritative"}
			got, err := eval.Evaluate(ctx, p, predicate, map[string]model.Value{"input.case": {Kind: model.StringValue, String: "case-1"}})
			if err != nil || got.Truth != tc.want {
				t.Fatalf("truth=%s err=%v", got.Truth, err)
			}
			if got.Truth != True && RequireBusinessSuccess(got) == nil {
				t.Fatal("unknown/false promoted to success")
			}
			wrong, err := eval.Evaluate(ctx, p, predicate, map[string]model.Value{"input.case": {Kind: model.StringValue, String: "case-2"}})
			if err != nil || wrong.Truth != False {
				t.Fatal("wrong business key accepted")
			}
		})
	}
}

func TestAuthoritativeClaimWithObservationalMinimumStillRequiresExactKey(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	e, _ := New(map[string]Enrollment{"receipt": {Adapter: adapterFunc(func(context.Context, auth.Principal, string, map[string]model.Value) (Result, error) {
		return Result{Truth: True, Authority: Authoritative, ObservedAt: time.Now(), Evidence: []Evidence{{Kind: "receipt", Reference: "wrong", BusinessKey: "case-other"}}}, nil
	}), MaximumAuthority: Authoritative, AllowedPredicates: map[string]bool{"complete": true}}})
	predicate := model.Predicate{Kind: "adapter", Adapter: "receipt", Name: "complete", RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}
	for _, inputs := range []map[string]model.Value{nil, {"businessKey": {Kind: model.StringValue, String: "case-1"}}} {
		predicate.Inputs = inputs
		result, err := e.Evaluate(ctx, p, predicate, nil)
		if err != nil || result.Truth != Unknown || RequireBusinessSuccess(result) == nil {
			t.Fatalf("weak minimum bypassed exact key: %+v %v", result, err)
		}
	}
}
