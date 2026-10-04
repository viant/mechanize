package leaseeffects

import (
	"context"
	"github.com/viant/mechanize/data"
	"strings"
	"testing"
)

func TestLeaseEffectsRequiresExactVerifiedScopeAndGeneration(t *testing.T) {
	namespace := strings.Repeat("a", 64)
	ctx, err := data.WithScope(context.Background(), data.Scope{Namespace: namespace, LeaseEpoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	input := &LeaseEffectsInput{}
	input.SetNamespace(namespace)
	input.SetLeaseEpoch(7)
	if err = input.Init(ctx); err != nil {
		t.Fatal(err)
	}
	input.SetLeaseEpoch(8)
	if input.Init(ctx) == nil {
		t.Fatal("generation widened")
	}
	input.SetLeaseEpoch(7)
	input.SetNamespace(strings.Repeat("b", 64))
	if input.Init(ctx) == nil {
		t.Fatal("namespace widened")
	}
	input.SetNamespace(namespace)
	if input.Init(context.Background()) == nil {
		t.Fatal("missing verified scope")
	}
}
