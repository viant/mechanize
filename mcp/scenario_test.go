package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	scenarios "github.com/viant/mechanize/engine/scenario"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	selector "github.com/viant/mechanize/scenario"
	"github.com/viant/mechanize/script"
)

func TestMCPScenarioCatalogueNeverQualifiesCallerClaims(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "catalogue-alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	_, file, _, _ := runtime.Caller(0)
	var dispatches atomic.Int32
	dispatch := func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		dispatches.Add(1)
		return automation.StepResult{}, nil
	}
	store, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)
	surface := model.Surface{Kind: "native", BundleID: "fixture.editor"}
	catalogue, err := scenarios.New(scenarios.Options{Invoke: store.InvokePrivateComponent, Authorize: func(_ context.Context, actual auth.Principal, scope model.Surface) error {
		if actual.Namespace != p.Namespace || !actual.HasScope("desktop:observe") || scope != (model.Surface{}) && scope != surface {
			return auth.ErrUnauthorized
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator, err := automation.New(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Dependencies{Runtime: orchestrator, Scenarios: catalogue, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	call := func(name string, input any, output any) {
		t.Helper()
		encoded, _ := json.Marshal(input)
		args := map[string]any{}
		if err := json.Unmarshal(encoded, &args); err != nil {
			t.Fatal(err)
		}
		r, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if err != nil || r.IsError != nil && *r.IsError {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
		encoded, _ = json.Marshal(r.StructuredContent)
		if err = json.Unmarshal(encoded, output); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := script.Compile(`app("fixture.editor").getById("status").read("text")`)
	if err != nil {
		t.Fatal(err)
	}
	inputRef := model.Value{Kind: model.ReferenceValue, Expected: model.StringValue, Ref: "input.case"}
	plan.Inputs = map[string]model.InputDefinition{"case": {Type: model.StringValue, Required: true}}
	plan.Surfaces = map[string]model.Surface{"app": surface}
	plan.Requires = &model.Requirements{Adapters: []string{"fixture-oracle"}}
	plan.Objective = &model.Predicate{Kind: "adapter", Adapter: "fixture-oracle", Name: "completed", Inputs: map[string]model.Value{"businessKey": inputRef}, Scope: model.PredicateScope{SurfaceRef: "app"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}
	draft := scenarios.PublishDraftRequest{ID: "inspect-case", Revision: "r1", RecordingID: "fixture-recording", Reviewed: true, Plan: *plan, Entity: map[string]model.Value{"case": inputRef}, Requirements: selector.Requirements{Surface: surface, Profile: "fixture.semantic.v1", Version: "fixture-1", Capabilities: []string{"native:attributeRead"}, Permissions: []string{"desktop:observe"}, Verification: "fixture-oracle.completed", CohortKey: "fixture-cohort"}}
	var published scenarios.PublishResult
	call("mechanize_scenario_publish", draft, &published)
	if !published.PublicationConfirmed || published.Summary.Qualified || published.Summary.Provenance.Verified || published.Summary.Provenance.Reviewed {
		t.Fatalf("caller qualified draft: %+v", published)
	}
	var listed scenarios.ListResult
	call("mechanize_scenario_list", scenarios.ListRequest{Limit: 10}, &listed)
	if len(listed.Scenarios) != 1 || listed.Scenarios[0].Reference != published.Summary.Reference {
		t.Fatalf("catalogue lost revision: %+v", listed)
	}
	var selected scenarios.Selection
	call("mechanize_scenario_select", scenarios.SelectRequest{ObjectiveHash: published.Summary.Reference.ObjectiveHash, Entity: map[string]model.Value{"case": {Kind: model.StringValue, String: "private-fixture-case"}}, InputSchema: plan.Inputs, Inputs: map[string]model.Value{"case": {Kind: model.StringValue, String: "private-fixture-case"}}, Surface: surface}, &selected)
	if selected.Status != "needsAttention" || !selected.ProposalOnly || selected.Plan != nil || dispatches.Load() != 0 {
		t.Fatalf("unqualified selection executed/promoted: %+v", selected)
	}
	other, _ := auth.NewPrincipal("fixture", "", "other-user", []string{"desktop:observe"})
	denied, err := client.CallTool(auth.WithPrincipal(ctx, other), &schema.CallToolRequestParams{Name: "mechanize_scenario_list", Arguments: map[string]any{}})
	if err != nil || denied.IsError == nil || !*denied.IsError {
		t.Fatal("foreign catalogue disclosed")
	}
}
