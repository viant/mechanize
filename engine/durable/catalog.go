package durable

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/listcheckpoints"
	"github.com/viant/mechanize/data/listevents"
	"github.com/viant/mechanize/data/listruns"
	"github.com/viant/mechanize/data/loadplan"
)

func (b *Builder) ListRuns(ctx context.Context, p auth.Principal) ([]*listruns.Run, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &listruns.ListRunsInput{}
	input.SetNamespace(p.Namespace)
	value, err := invoke(ctx, user.server, "listruns", "ListRuns", "GET", input, false)
	if err != nil {
		return nil, err
	}
	return value.(*listruns.ListRunsOutput).Data, nil
}
func (b *Builder) LoadPlan(ctx context.Context, p auth.Principal, id string) (*loadplan.PlanRevision, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &loadplan.LoadPlanInput{}
	input.SetNamespace(p.Namespace)
	input.SetPlanID(id)
	value, err := invoke(ctx, user.server, "loadplan", "LoadPlan", "GET", input, false)
	if err != nil {
		return nil, err
	}
	rows := value.(*loadplan.LoadPlanOutput).Data
	if len(rows) != 1 {
		return nil, errors.New("authorized immutable plan not found")
	}
	return rows[0], nil
}
func (b *Builder) ListEvents(ctx context.Context, p auth.Principal, runID string) ([]*listevents.Event, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &listevents.ListEventsInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(runID)
	value, err := invoke(ctx, user.server, "listevents", "ListEvents", "GET", input, false)
	if err != nil {
		return nil, err
	}
	return value.(*listevents.ListEventsOutput).Data, nil
}
func (b *Builder) ListCheckpoints(ctx context.Context, p auth.Principal, runID string) ([]*listcheckpoints.Checkpoint, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &listcheckpoints.ListCheckpointsInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(runID)
	value, err := invoke(ctx, user.server, "listcheckpoints", "ListCheckpoints", "GET", input, false)
	if err != nil {
		return nil, err
	}
	return value.(*listcheckpoints.ListCheckpointsOutput).Data, nil
}
