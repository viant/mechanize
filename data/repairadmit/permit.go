package repairadmit

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

// Permit is detached trusted admission evidence after stopped runtime, qualified
// fresh context, objective-preserving validation and finite budget reservation.
// It cannot be bound from transport or component input.
type Permit struct {
	ExpectedPlan                   *PlanRevision
	AnchorID                       string
	Namespace, RunID, ParentPlanID string
	ExpectedRevision               int
	ValidUntil                     time.Time
	Expected                       *RepairRun
}
type permitKey struct{}

func WithPermit(ctx context.Context, p Permit) (context.Context, error) {
	if _, err := data.RequireScope(ctx, p.Namespace); err != nil {
		return nil, err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || p.RunID == "" || p.ParentPlanID == "" || p.ExpectedRevision <= 0 || p.Expected == nil || p.ExpectedPlan == nil || p.AnchorID == "" || p.ValidUntil.IsZero() {
		return nil, errors.New("complete trusted repair admission evidence required")
	}
	content, err := json.Marshal(p.Expected)
	if err != nil {
		return nil, err
	}
	var detached RepairRun
	if err = json.Unmarshal(content, &detached); err != nil {
		return nil, err
	}
	p.Expected = &detached
	planBytes, err := json.Marshal(p.ExpectedPlan)
	if err != nil {
		return nil, err
	}
	var plan PlanRevision
	if err = json.Unmarshal(planBytes, &plan); err != nil {
		return nil, err
	}
	p.ExpectedPlan = &plan
	return context.WithValue(ctx, permitKey{}, p), nil
}
func requirePermit(ctx context.Context) (Permit, error) {
	p, ok := ctx.Value(permitKey{}).(Permit)
	if !ok || p.Expected == nil || time.Now().After(p.ValidUntil) {
		return Permit{}, errors.New("fresh trusted repair admission permit required")
	}
	if _, err := data.RequireScope(ctx, p.Namespace); err != nil {
		return Permit{}, err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace {
		return Permit{}, auth.ErrUnauthorized
	}
	return p, nil
}
func sameLeaf(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	var x, y any
	_ = json.Unmarshal(left, &x)
	_ = json.Unmarshal(right, &y)
	return reflect.DeepEqual(x, y)
}
func increment(previous, requested *int) *int {
	next := 1
	if previous != nil {
		next = *previous + 1
	}
	return &next
}
func sameOptional[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
