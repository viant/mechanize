package scenario

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

func fixture() (context.Context, Request, Candidate) {
	p, _ := auth.NewPrincipal("issuer", "", "user", []string{"desktop"})
	now := time.Now()
	env := Requirements{Surface: model.Surface{Kind: "native", BundleID: "fixture"}, Profile: "qualified", Version: "1", Capabilities: []string{"read"}, Permissions: []string{"desktop"}, Verification: "oracle", CohortKey: "cohort-v1"}
	r := Request{ObjectiveHash: "objective", Entity: map[string]model.Value{"case": {Kind: model.StringValue, String: "123"}}, InputSchema: map[string]model.InputDefinition{}, Now: now, MaxAge: time.Minute, Environment: env}
	c := Candidate{Namespace: p.Namespace, ID: "scenario", Revision: "1", ObjectiveHash: r.ObjectiveHash, Entity: r.Entity, Inputs: r.InputSchema, Requirements: env, ObservedAt: now, Qualified: Cohort{Key: env.CohortKey, Qualified: true, IndependentTrials: 100, VerifiedSuccesses: 98, PeriodStart: now.Add(-time.Hour), PeriodEnd: now}}
	return auth.WithPrincipal(context.Background(), p), r, c
}
func TestSelectionHardGates(t *testing.T) {
	for _, name := range []string{"profile", "objective", "entity", "namespace", "capability", "qualification"} {
		t.Run(name, func(t *testing.T) {
			ctx, r, c := fixture()
			switch name {
			case "profile":
				c.Requirements.Profile = "other"
			case "objective":
				c.ObjectiveHash = "other"
			case "entity":
				c.Entity = map[string]model.Value{}
			case "namespace":
				c.Namespace = "other"
			case "capability":
				c.Requirements.Capabilities = []string{"absent"}
			case "qualification":
				c.Qualified.IndependentTrials = 0
			}
			out, err := Select(ctx, r, []Candidate{c})
			if err != nil || out.Status != "needsAttention" || len(out.Rejected) != 1 {
				t.Fatalf("%+v %v", out, err)
			}
		})
	}
}
func TestAmbiguousProfilesAndRanking(t *testing.T) {
	ctx, r, c := fixture()
	b := c
	b.ID = "other"
	out, err := Select(ctx, r, []Candidate{b, c})
	if err != nil || out.Status != "needsAttention" {
		t.Fatalf("ambiguous selection %+v %v", out, err)
	}
	c.ExactConstraints = []string{"exact-document"}
	out, err = Select(ctx, r, []Candidate{b, c})
	if err != nil || out.Candidate == nil || out.Candidate.ID != c.ID {
		t.Fatalf("rank %+v %v", out, err)
	}
}
