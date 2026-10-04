package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/scenariolist"
	"github.com/viant/mechanize/data/scenariopublish"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	selector "github.com/viant/mechanize/scenario"
	"github.com/viant/xdatly/handler"
)

func fixture(t *testing.T) (context.Context, auth.Principal, PublishDraftRequest, Options) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "tenant", "scenario-alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	surface := model.Surface{Kind: "native", BundleID: "fixture.editor"}
	reference := model.Value{Kind: model.ReferenceValue, Expected: model.StringValue, Ref: "input.case"}
	req := PublishDraftRequest{ID: "scenario", Revision: "r1", RecordingID: "recording-fixture", Reviewed: true, Entity: map[string]model.Value{"case": reference}, Requirements: selector.Requirements{Surface: surface, Profile: "native.semantic.v1", Version: "fixture-1", Capabilities: []string{"observe"}, Permissions: []string{"desktop:observe"}, Verification: "oracle.confirmed", CohortKey: "fixture-cohort"}, Plan: model.Plan{SchemaVersion: 1, Name: "recording-fixture", Requires: &model.Requirements{Adapters: []string{"oracle"}}, Inputs: map[string]model.InputDefinition{"case": {Type: model.StringValue, Required: true, Sensitive: true}}, Surfaces: map[string]model.Surface{"app": surface}, Objective: &model.Predicate{Kind: "adapter", Adapter: "oracle", Name: "confirmed", Inputs: map[string]model.Value{"case": reference}, Scope: model.PredicateScope{SurfaceRef: "app"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}, Steps: []model.Step{{ID: "inspect", Action: "element.read", Target: model.Selector{Surface: surface, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "status"}, Exact: true}, Cardinality: "one"}, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}, TimeoutMs: 1000, Effect: model.Effect{Class: model.ReadOnly}}}}}
	now := time.Date(2026, 10, 1, 17, 0, 0, 0, time.UTC)
	opts := Options{Now: func() time.Time { return now }, Authorize: func(_ context.Context, actual auth.Principal, surface model.Surface) error {
		if actual.Namespace != p.Namespace && actual.Subject != "scenario-bob" {
			return auth.ErrUnauthorized
		}
		if surface.Kind != "" && surface != req.Requirements.Surface {
			return auth.ErrUnauthorized
		}
		return nil
	}}
	return auth.WithPrincipal(context.Background(), p), p, req, opts
}

type componentFixture struct {
	rows               map[string]*scenariolist.ScenarioRevision
	calls              int
	lost               bool
	unreadable         bool
	readFailAfterWrite bool
}

func (f *componentFixture) invoke(_ context.Context, p auth.Principal, req exec.ComponentRequest) (any, error) {
	f.calls++
	if req.Target.Component.Name == "ListScenarios" {
		input := req.Input.(*scenariolist.ListScenariosInput)
		if input.Namespace != p.Namespace {
			return nil, auth.ErrUnauthorized
		}
		if f.unreadable {
			return nil, errors.New("fixture database unreadable")
		}
		out := &scenariolist.ListScenariosOutput{}
		for _, row := range f.rows {
			if *row.Namespace == input.Namespace && (input.ScenarioID == "*" || input.ScenarioID == *row.ScenarioId) && (input.Revision == "*" || input.Revision == *row.Revision) && (input.ObjectiveHash == "*" || input.ObjectiveHash == *row.ObjectiveHash) {
				out.Data = append(out.Data, row)
			}
		}
		return out, nil
	}
	input := req.Input.(*scenariopublish.PublishScenarioDraftInput)
	if input.Namespace != p.Namespace {
		return nil, auth.ErrUnauthorized
	}
	row := input.PublishScenarioDraft[0]
	f.rows[p.Namespace+"/"+*row.ScenarioId+"/"+*row.Revision] = &scenariolist.ScenarioRevision{Namespace: row.Namespace, ScenarioId: row.ScenarioId, Revision: row.Revision, ContentHash: row.ContentHash, ObjectiveHash: row.ObjectiveHash, ContentJson: row.ContentJson, PublicationState: row.PublicationState, CreatedAt: row.CreatedAt}
	if f.readFailAfterWrite {
		f.unreadable = true
	}
	if f.lost {
		if req.Completion != nil {
			req.Completion(handler.Outcome{Transactions: []handler.TransactionOutcome{{State: handler.TransactionCommitUnknown}}})
		}
		return nil, errors.New("fixture commit acknowledgement lost")
	}
	if req.Completion != nil {
		req.Completion(handler.Outcome{Transactions: []handler.TransactionOutcome{{State: handler.TransactionCommitted}}})
	}
	return &scenariopublish.PublishScenarioDraftOutput{}, nil
}
func freshEnvironment(opts Options, req PublishDraftRequest) func(context.Context, auth.Principal, model.Surface) (Environment, error) {
	return func(_ context.Context, _ auth.Principal, surface model.Surface) (Environment, error) {
		return Environment{Requirements: req.Requirements, ObservedAt: opts.Now().Add(-time.Second), Verified: surface == req.Requirements.Surface}, nil
	}
}
func verifiedProvenance(_ context.Context, _ auth.Principal, def Definition) (Provenance, error) {
	return Provenance{RecordingID: def.Provenance.RecordingID, Reviewed: true, Verified: true}, nil
}
func selectRequest(req PublishDraftRequest, ref Reference) SelectRequest {
	return SelectRequest{ID: req.ID, Revision: req.Revision, ObjectiveHash: ref.ObjectiveHash, Entity: map[string]model.Value{"case": {Kind: model.StringValue, String: "current-sensitive-case"}}, InputSchema: req.Plan.Inputs, Inputs: map[string]model.Value{"case": {Kind: model.StringValue, String: "current-sensitive-case"}}, Surface: req.Requirements.Surface}
}

func TestDraftCanonicalSafetyAndExplicitNormalization(t *testing.T) {
	_, _, req, _ := fixture(t)
	base := Definition{SchemaVersion: 1, ID: req.ID, Revision: req.Revision, Plan: req.Plan, Entity: req.Entity, Requirements: req.Requirements, Provenance: Provenance{RecordingID: req.RecordingID}}
	content, err := scenariopublish.Canonical(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = scenariopublish.DecodeCanonical(string(content)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Definition){
		"default": func(d *Definition) {
			input := d.Plan.Inputs["case"]
			input.Default = &model.Value{Kind: model.StringValue, String: "captured-secret"}
			d.Plan.Inputs["case"] = input
		},
		"literal-mutation": func(d *Definition) {
			d.Plan.Steps[0].Action = "element.fill"
			d.Plan.Steps[0].Arguments = map[string]model.Value{"value": {Kind: model.StringValue, String: "captured-secret"}}
		},
		"literal-entity": func(d *Definition) {
			d.Entity["case"] = model.Value{Kind: model.StringValue, String: "captured-secret"}
		},
		"live-reference": func(d *Definition) {
			d.Plan.Objective.Inputs["case"] = model.Value{Kind: model.ReferenceValue, Ref: "run.id"}
		},
		"typed-live-object": func(d *Definition) {
			d.Plan.Objective.Inputs["case"] = model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{"epoch": {Kind: model.StringValue, String: "live-epoch"}}}
		},
		"captured-title":   func(d *Definition) { d.Requirements.Surface.Title = "secret document" },
		"embedded-command": func(d *Definition) { d.Plan.Steps[0].Command = `fill("captured-secret")` },
		"schema":           func(d *Definition) { d.SchemaVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			var clone Definition
			_ = json.Unmarshal(content, &clone)
			change(&clone)
			if _, err := scenariopublish.Canonical(clone); err == nil {
				t.Fatal("unsafe draft accepted")
			}
		})
	}
	var web Definition
	_ = json.Unmarshal(content, &web)
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test", TabID: "current-live-tab"}
	web.Requirements.Surface = surface
	web.Plan.Surfaces["app"] = surface
	web.Plan.Steps[0].Target.Surface = surface
	normalized, fields, err := normalize(web)
	if err != nil || len(fields) != 3 {
		t.Fatalf("normalization %v %v", fields, err)
	}
	content, err = scenariopublish.Canonical(normalized)
	if err != nil || strings.Contains(string(content), "current-live-tab") {
		t.Fatalf("portable content %s %v", content, err)
	}
	if web.Plan.Steps[0].Target.Surface.TabID != "current-live-tab" {
		t.Fatal("caller plan mutated")
	}
}

func TestUnknownAuthorityCannotQualifyCallerDraft(t *testing.T) {
	ctx, p, req, opts := fixture(t)
	memory := &componentFixture{rows: map[string]*scenariolist.ScenarioRevision{}}
	opts.Invoke = memory.invoke
	service, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	published, err := service.PublishDraft(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	if published.Summary.Qualified || published.Summary.Provenance.Reviewed || published.Summary.Provenance.Verified {
		t.Fatal("caller review claim became authority")
	}
	request := selectRequest(req, published.Summary.Reference)
	selected, err := service.Select(ctx, p, request)
	if err != nil || selected.Status != "needsAttention" || selected.Plan != nil || !selected.ProposalOnly {
		t.Fatalf("%+v %v", selected, err)
	}
	opts.Environment = freshEnvironment(opts, req)
	opts.Qualify = func(context.Context, auth.Principal, Reference, Environment) (selector.Cohort, error) {
		t.Fatal("unverified provenance reached qualifier")
		return selector.Cohort{}, nil
	}
	service, _ = New(opts)
	selected, err = service.Select(ctx, p, request)
	if err != nil || selected.Status != "needsAttention" || selected.Plan != nil {
		t.Fatalf("%+v %v", selected, err)
	}
}

func TestTrustedEnvironmentAndExactReferenceGates(t *testing.T) {
	ctx, p, req, opts := fixture(t)
	memory := &componentFixture{rows: map[string]*scenariolist.ScenarioRevision{}}
	opts.Invoke = memory.invoke
	opts.VerifyProvenance = verifiedProvenance
	opts.Environment = freshEnvironment(opts, req)
	var expected Reference
	qualifiers := 0
	opts.Qualify = func(_ context.Context, _ auth.Principal, ref Reference, env Environment) (selector.Cohort, error) {
		qualifiers++
		if ref != expected || !env.Verified {
			t.Fatal("qualification was not scoped to exact immutable revision/environment")
		}
		now := opts.Now()
		return selector.Cohort{Key: req.Requirements.CohortKey, Qualified: true, IndependentTrials: 100, VerifiedSuccesses: 98, PeriodStart: now.Add(-time.Hour), PeriodEnd: now.Add(-time.Second)}, nil
	}
	service, _ := New(opts)
	result, err := service.PublishDraft(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	expected = result.Summary.Reference
	request := selectRequest(req, expected)
	out, err := service.Select(ctx, p, request)
	if err != nil || out.Status != "selected" || out.Reference == nil || *out.Reference != expected || out.Plan == nil || !out.ProposalOnly || qualifiers != 1 {
		t.Fatalf("%+v %v", out, err)
	}
	for _, row := range memory.rows {
		if strings.Contains(*row.ContentJson, "current-sensitive-case") {
			t.Fatal("live selection input persisted")
		}
	}
	out.Plan.Steps[0].ID = "caller mutation"
	again, err := service.Select(ctx, p, request)
	if err != nil || again.Plan.Steps[0].ID != "inspect" {
		t.Fatalf("selected plan aliases stored revision: %v", err)
	}
	// Trusted read callbacks receive detached data and cannot mutate the plan
	// returned under the persisted hash or widen the verified environment.
	opts.VerifyProvenance = func(ctx context.Context, p auth.Principal, def Definition) (Provenance, error) {
		def.Plan.Steps[0].ID = "callback mutation"
		return verifiedProvenance(ctx, p, def)
	}
	originalQualifier := opts.Qualify
	opts.Qualify = func(ctx context.Context, p auth.Principal, ref Reference, env Environment) (selector.Cohort, error) {
		cohort, err := originalQualifier(ctx, p, ref, env)
		env.Requirements.Capabilities[0] = "callback mutation"
		return cohort, err
	}
	detachedService, _ := New(opts)
	detached, err := detachedService.Select(ctx, p, request)
	if err != nil || detached.Plan == nil || detached.Plan.Steps[0].ID != "inspect" || detached.Status != "selected" {
		t.Fatalf("callback mutated immutable proposal %+v %v", detached, err)
	}
	request.Entity["case"] = model.Value{Kind: model.StringValue, String: "different-case"}
	out, err = service.Select(ctx, p, request)
	if err != nil || out.Status != "needsAttention" {
		t.Fatalf("entity mismatch %+v %v", out, err)
	}
	request = selectRequest(req, expected)
	opts.Environment = func(context.Context, auth.Principal, model.Surface) (Environment, error) {
		env := Environment{Requirements: req.Requirements, ObservedAt: opts.Now().Add(-time.Second), Verified: true}
		env.Requirements.Version = "other-version"
		return env, nil
	}
	service, _ = New(opts)
	out, err = service.Select(ctx, p, request)
	if err != nil || out.Status != "needsAttention" {
		t.Fatalf("host version mismatch %+v %v", out, err)
	}
}

func TestDraftPublicationLostAcknowledgementAndConflict(t *testing.T) {
	ctx, p, req, opts := fixture(t)
	memory := &componentFixture{rows: map[string]*scenariolist.ScenarioRevision{}, lost: true}
	opts.Invoke = memory.invoke
	service, _ := New(opts)
	first, err := service.PublishDraft(ctx, p, req)
	if err != nil {
		t.Fatalf("committed lost acknowledgement: %v", err)
	}
	replay, err := service.PublishDraft(ctx, p, req)
	if err != nil || first.Summary.Reference != replay.Summary.Reference || len(memory.rows) != 1 {
		t.Fatalf("replay %+v %v", replay, err)
	}
	req.Requirements.Version = "changed-version"
	if _, err = service.PublishDraft(ctx, p, req); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal(err)
	}
	// A failed acknowledgement plus unreadable scoped database is not proof.
	missing := req
	missing.ID = "unknown-revision"
	memory.readFailAfterWrite = true
	uncertain, err := service.PublishDraft(ctx, p, missing)
	var publication *PublicationError
	if !errors.As(err, &publication) || uncertain.PublicationConfirmed || publication.Reference.ID != missing.ID {
		t.Fatalf("uncertain result %+v %v", uncertain, err)
	}
	memory.unreadable = false
	memory.readFailAfterWrite = false
	reconciled, err := service.PublishDraft(ctx, p, missing)
	if err != nil || !reconciled.PublicationConfirmed {
		t.Fatalf("later scoped reconciliation %+v %v", reconciled, err)
	}
	memory.unreadable = true
	if _, err = service.PublishDraft(ctx, p, req); err == nil {
		t.Fatal("unreadable catalogue accepted")
	}
}

func TestScenarioGeneratedPersistenceIsolationAndImmutableRevisions(t *testing.T) {
	ctx, p, req, opts := fixture(t)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	newBuilder := func() *durable.Builder {
		b, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
			t.Fatal("scenario selection dispatched an action")
			return integration.StepResult{}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	builder := newBuilder()
	defer func() { _ = builder.Close(context.Background()) }()
	opts.Invoke = builder.InvokePrivateComponent
	service, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.PublishDraft(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.PublishDraft(ctx, p, req)
	if err != nil || replay.Summary.Reference != first.Summary.Reference {
		t.Fatalf("replay %+v %v", replay, err)
	}
	changed := req
	changed.Requirements.Version = "other-version"
	if _, err = service.PublishDraft(ctx, p, changed); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("revision overwrite admitted: %v", err)
	}
	req.Revision = "r2"
	second, err := service.PublishDraft(ctx, p, req)
	if err != nil || second.Summary.Reference.Revision != "r2" {
		t.Fatalf("new revision %+v %v", second, err)
	}
	catalogue, err := service.List(ctx, p, ListRequest{ID: "scenario", Limit: 1})
	if err != nil || len(catalogue.Scenarios) != 1 || !catalogue.Truncated || catalogue.Next == nil {
		t.Fatalf("bounded catalogue %+v %v", catalogue, err)
	}
	next, err := service.List(ctx, p, ListRequest{ID: "scenario", Limit: 1, After: catalogue.Next})
	if err != nil || len(next.Scenarios) != 1 || next.Truncated || next.Scenarios[0].Reference.Revision != "r2" {
		t.Fatalf("keyset page %+v %v", next, err)
	}
	exact, err := service.List(ctx, p, ListRequest{ID: "scenario", Revision: "r1"})
	if err != nil || len(exact.Scenarios) != 1 || exact.Scenarios[0].Reference != first.Summary.Reference {
		t.Fatalf("exact keyed reader %+v %v", exact, err)
	}
	bob, _ := auth.NewPrincipal("fixture", "tenant", "scenario-bob", []string{"desktop:observe"})
	bobCtx := auth.WithPrincipal(context.Background(), bob)
	foreign, err := service.List(bobCtx, bob, ListRequest{})
	if err != nil || len(foreign.Scenarios) != 0 {
		t.Fatalf("foreign catalogue %+v %v", foreign, err)
	}
	if _, err = service.List(ctx, bob, ListRequest{}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("caller selected foreign namespace")
	}
	input := &scenariolist.ListScenariosInput{}
	input.SetNamespace(bob.Namespace)
	input.SetScenarioID("*")
	input.SetRevision("*")
	input.SetLimit(10)
	input.SetAfterID("*")
	input.SetAfterRevision("*")
	input.SetObjectiveHash("*")
	if _, err = builder.InvokePrivateComponent(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: specKey("scenariolist", "ListScenarios"), Route: specRoute("scenariolist", "GET")}, Input: input}); err == nil {
		t.Fatal("generated reader accepted foreign namespace")
	}
	// Exercise canonical hash validation through the actual generated writer.
	own := &scenariolist.ListScenariosInput{}
	own.SetNamespace(p.Namespace)
	own.SetScenarioID("scenario")
	own.SetRevision("r1")
	own.SetLimit(2)
	own.SetAfterID("*")
	own.SetAfterRevision("*")
	own.SetObjectiveHash("*")
	value, err := builder.InvokePrivateComponent(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: specKey("scenariolist", "ListScenarios"), Route: specRoute("scenariolist", "GET")}, Input: own})
	if err != nil {
		t.Fatal(err)
	}
	originalRow := value.(*scenariolist.ListScenariosOutput).Data[0]
	forged, err := scenariopublish.DecodeCanonical(*originalRow.ContentJson)
	if err != nil {
		t.Fatal(err)
	}
	forged.ID = "forged"
	forgedContent, err := scenariopublish.Canonical(forged)
	if err != nil {
		t.Fatal(err)
	}
	row := &scenariopublish.ScenarioRevision{}
	row.SetNamespace(ptr(p.Namespace))
	row.SetScenarioId(ptr(forged.ID))
	row.SetRevision(ptr(forged.Revision))
	row.SetContentHash(ptr(strings.Repeat("0", 64)))
	row.SetObjectiveHash(originalRow.ObjectiveHash)
	row.SetContentJson(ptr(string(forgedContent)))
	row.SetPublicationState(ptr("draft"))
	row.SetCreatedAt(ptr(opts.Now().Format(time.RFC3339)))
	publish := &scenariopublish.PublishScenarioDraftInput{}
	publish.SetNamespace(p.Namespace)
	publish.SetPublishScenarioDraft([]*scenariopublish.ScenarioRevision{row})
	if _, err = builder.InvokePrivateComponent(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: specKey("scenariopublish", "PublishScenarioDraft"), Route: specRoute("scenariopublish", "POST")}, Input: publish}); err == nil {
		t.Fatal("generated writer accepted false canonical hash")
	}
	absent, err := service.List(ctx, p, ListRequest{ID: "forged"})
	if err != nil || len(absent.Scenarios) != 0 {
		t.Fatalf("rejected hash persisted %+v %v", absent, err)
	}
	if err = builder.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	builder = newBuilder()
	opts.Invoke = builder.InvokePrivateComponent
	service, _ = New(opts)
	restarted, err := service.List(ctx, p, ListRequest{ID: "scenario", Revision: "r1"})
	if err != nil || len(restarted.Scenarios) != 1 || restarted.Scenarios[0].Reference != first.Summary.Reference {
		t.Fatalf("restart catalogue %+v %v", restarted, err)
	}
}

func specKey(pkg, name string) spec.Key {
	return spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}
}
func specRoute(pkg, method string) spec.RouteRef {
	return spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}
}

func TestMixedPlanSurfaceCeilingsAndTrustedCoverage(t *testing.T) {
	ctx, p, req, opts := fixture(t)
	web := model.Surface{Kind: "web", Origin: "https://fixture.test"}
	req.Plan.Surfaces["web"] = web
	second := req.Plan.Steps[0]
	second.ID = "web-inspect"
	second.Target.Surface = web
	req.Plan.Steps = append(req.Plan.Steps, second)
	memory := &componentFixture{rows: map[string]*scenariolist.ScenarioRevision{}}
	opts.Invoke = memory.invoke
	denied, _ := New(opts)
	if _, err := denied.PublishDraft(ctx, p, req); !errors.Is(err, auth.ErrUnauthorized) || memory.calls != 0 {
		t.Fatalf("secondary surface bypassed publication ceiling: %v calls%d", err, memory.calls)
	}
	opts.Authorize = func(_ context.Context, actual auth.Principal, surface model.Surface) error {
		if actual.Namespace != p.Namespace {
			return auth.ErrUnauthorized
		}
		if surface.Kind != "" && surface != req.Requirements.Surface && surface != web {
			return auth.ErrUnauthorized
		}
		return nil
	}
	opts.VerifyProvenance = verifiedProvenance
	opts.Environment = freshEnvironment(opts, req)
	qualifications := 0
	opts.Qualify = func(context.Context, auth.Principal, Reference, Environment) (selector.Cohort, error) {
		qualifications++
		now := opts.Now()
		return selector.Cohort{Key: req.Requirements.CohortKey, Qualified: true, IndependentTrials: 100, VerifiedSuccesses: 98, PeriodStart: now.Add(-time.Hour), PeriodEnd: now.Add(-time.Second)}, nil
	}
	allowed, _ := New(opts)
	published, err := allowed.PublishDraft(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	request := selectRequest(req, published.Summary.Reference)
	out, err := allowed.Select(ctx, p, request)
	if err != nil || out.Status != "needsAttention" || out.Plan != nil || qualifications != 0 {
		t.Fatalf("primary-only observation qualified mixed plan %+v %v", out, err)
	}
	opts.Environment = func(ctx context.Context, p auth.Principal, surface model.Surface) (Environment, error) {
		env, err := freshEnvironment(opts, req)(ctx, p, surface)
		env.CoveredSurfaces = []model.Surface{web}
		return env, err
	}
	covered, _ := New(opts)
	out, err = covered.Select(ctx, p, request)
	if err != nil || out.Status != "selected" || out.Plan == nil || qualifications != 1 {
		t.Fatalf("covered fixture %+v %v", out, err)
	}
	// A later tightened surface ceiling hides the entire plan and all summaries,
	// including secondary surface metadata, even when primary surface is allowed.
	opts.Authorize = func(_ context.Context, actual auth.Principal, surface model.Surface) error {
		if actual.Namespace != p.Namespace || surface == web {
			return auth.ErrUnauthorized
		}
		return nil
	}
	tightened, _ := New(opts)
	listed, err := tightened.List(ctx, p, ListRequest{})
	if err != nil || len(listed.Scenarios) != 0 {
		t.Fatalf("denied secondary surface leaked summary %+v %v", listed, err)
	}
	out, err = tightened.Select(ctx, p, request)
	if err != nil || out.Status != "needsAttention" || out.Plan != nil || qualifications != 1 {
		t.Fatalf("denied secondary surface leaked plan %+v %v", out, err)
	}
}
