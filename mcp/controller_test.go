package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func controllerFixture(t *testing.T, configure ...func(*Dependencies)) (*ControllerDispatcher, chrome.ControllerIdentity, context.Context, *atomic.Int32) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "controller", []string{"desktop:observe", "desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "controller:fixture"
	p.ClientName = "Controller fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	id := chrome.ControllerIdentity{Principal: p, ConversationID: "conversation1", Origin: "https://shell.fixture.test", DocumentID: "doc1", CatalogToolLimit: 64}
	count := &atomic.Int32{}
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		count.Add(1)
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}
	deps := Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }, Observe: func(ctx context.Context, p auth.Principal, s model.Surface) (model.Observation, error) {
		if p.ClientID != id.Principal.ClientID {
			return model.Observation{}, errors.New("RAW_SECRET should never escape")
		}
		return model.Observation{Surface: s, Nodes: []model.Node{}}, nil
	}}
	for _, option := range configure {
		option(&deps)
	}
	server, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewControllerDispatcher(server, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = dispatcher.CloseController(closeCtx, id)
	})
	return dispatcher, id, ctx, count
}
func controllerCall(t *testing.T, d *ControllerDispatcher, ctx context.Context, id chrome.ControllerIdentity, name string, args any) *schema.CallToolResult {
	t.Helper()
	raw, _ := json.Marshal(args)
	out, err := d.CallTool(ctx, id, chrome.ControllerToolCall{Name: name, Arguments: raw})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func controllerBody(t *testing.T, out *schema.CallToolResult) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(out.StructuredContent)
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("object result required")
	}
	return value
}
func TestControllerCanonicalCatalogSessionScriptAndObserver(t *testing.T) {
	d, id, ctx, count := controllerFixture(t)
	initialized, err := d.Initialize(ctx, id)
	if err != nil || initialized.ProtocolVersion != "2025-11-25" {
		t.Fatal(err)
	}
	listed, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	catalogBytes, _ := json.Marshal(listed)
	if len(catalogBytes) > 192*1024 {
		t.Fatalf("canonical catalog exceeds native result budget: %d", len(catalogBytes))
	}
	var wire struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(catalogBytes, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Tools) > 64 {
		t.Fatalf("extension catalog tool limit exceeded: %d", len(wire.Tools))
	}
	for _, tool := range wire.Tools {
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("extension rejects schema for %s: type=%v", tool.Name, tool.InputSchema["type"])
		}
	}
	names := map[string]bool{}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
		if !controllerTools[tool.Name] {
			t.Fatal("unexpected tool")
		}
	}
	for _, name := range []string{"mechanize_observe", "mechanize_script_run", "mechanize_operation_cancel", "mechanize_permission_status"} {
		if name == "mechanize_permission_status" {
			continue
		}
		if !names[name] {
			t.Fatal("missing canonical tool", name)
		}
	}
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "fixture"}))["sessionId"].(string)
	if out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{"sessionId": session, "surface": model.Surface{Kind: "native", BundleID: "com.example.Fixture"}}); out.IsError != nil && *out.IsError {
		t.Fatal(out)
	}
	out := controllerCall(t, d, ctx, id, "mechanize_step_run", map[string]any{"sessionId": session, "clientRequestId": "once", "source": `app("com.example.Fixture").getById("save").click()`})
	if out.IsError != nil && *out.IsError {
		t.Fatal(out)
	}
	operation := controllerBody(t, out)["operationId"].(string)
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		status := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_operation_status", map[string]any{"sessionId": session, "operationId": operation}))
		if status["executionStatus"] == "succeeded" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 1 {
		t.Fatalf("canonical runtime executions %d", count.Load())
	}
	// Same idempotency key never authorizes another execution.
	controllerCall(t, d, ctx, id, "mechanize_step_run", map[string]any{"sessionId": session, "clientRequestId": "once", "source": `app("com.example.Fixture").getById("save").click()`})
	if count.Load() != 1 {
		t.Fatal("replayed effect")
	}
	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err = d.CloseController(closeCtx, id); err != nil {
		t.Fatal(err)
	}
	if err = d.runtime.CheckSession(ctx, id.Principal, session); err == nil {
		t.Fatal("controller session remained open")
	}
}
func TestControllerRejectsForeignSessionsSecretsAndUnclosedArguments(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t)
	other := id.Principal
	other.ClientID = ""
	foreign, err := d.runtime.Open(auth.WithPrincipal(ctx, other), "legacy-unscoped")
	if err != nil {
		t.Fatal(err)
	}
	defer d.runtime.Close(auth.WithPrincipal(ctx, other), foreign.SessionID)
	for _, test := range []struct {
		name string
		args any
	}{{"mechanize_session_close", map[string]any{"sessionId": foreign.SessionID}}, {"vault.read", map[string]any{}}, {"mechanize_session_open", map[string]any{"name": "test", "credential": "RAW_SECRET"}}, {"mechanize_observe", map[string]any{"surface": model.Surface{Kind: "native", BundleID: "com.example.Fixture"}}}} {
		out := controllerCall(t, d, ctx, id, test.name, test.args)
		if out.IsError == nil || !*out.IsError {
			t.Fatalf("accepted %s", test.name)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "RAW_SECRET") {
			t.Fatal("secret leaked")
		}
	}
	out := controllerCall(t, d, ctx, id, "mechanize_script_validate", map[string]any{"source": `app("com.example.Fixture").getById("PRIVATE-LITERAL").click()`})
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "PRIVATE-LITERAL") {
		t.Fatal("compiled plan echoed")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = d.ListTools(canceled, id); err == nil {
		t.Fatal("canceled document reopened dispatcher")
	}
}
func TestControllerCannotAutomateNativeAuthorityWindow(t *testing.T) {
	d, id, ctx, count := controllerFixture(t)
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	for _, tc := range []struct {
		name string
		args any
	}{
		{"mechanize_observe", map[string]any{"sessionId": session, "surface": model.Surface{Kind: "native", BundleID: "com.viant.mechanize.consent"}}},
		{"mechanize_step_run", map[string]any{"sessionId": session, "clientRequestId": "admin-ui", "source": `app("com.viant.mechanize.consent").getById("approve").click()`}},
		{"mechanize_script_validate", map[string]any{"source": `app("com.viant.mechanize.consent").getById("approve").click()`}},
	} {
		out := controllerCall(t, d, ctx, id, tc.name, tc.args)
		if out.IsError == nil || !*out.IsError {
			t.Fatalf("authority recursion via %s", tc.name)
		}
	}
	admin := &model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.viant.mechanize.consent"}}
	for _, p := range []*model.Plan{
		{Steps: []model.Step{{Target: model.Selector{Ancestor: admin}}}},
		{Steps: []model.Step{{Postcondition: &model.Predicate{Scope: model.PredicateScope{Target: admin}}}}},
		{Objective: &model.Predicate{Scope: model.PredicateScope{Target: admin}}},
		{Bindings: []model.Binding{{Selector: admin}}},
	} {
		if controllerPlanAllowed(p) {
			t.Fatal("nested authority target accepted")
		}
	}
	if count.Load() != 0 {
		t.Fatal("native authority input dispatched")
	}
}

func TestControllerOptionalToolCatalogFitsExtensionContract(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		value := reflect.ValueOf(deps).Elem()
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.Kind() == reflect.Func && field.IsNil() {
				field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value { panic("catalog discovery must not execute a tool") }))
			}
		}
	})
	listed, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 192*1024 {
		t.Fatalf("full catalog too large: %d", len(raw))
	}
	var wire struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Tools) > 64 {
		t.Fatalf("too many tools: %d", len(wire.Tools))
	}
	for _, tool := range wire.Tools {
		if tool.InputSchema["type"] != "object" {
			t.Errorf("invalid input schema: %s type=%v", tool.Name, tool.InputSchema["type"])
		}
	}
	t.Logf("full catalog: %d tools, %d bytes", len(wire.Tools), len(raw))
}
