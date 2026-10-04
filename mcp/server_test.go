package mcp

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestViantMCPDiscoveryAndEndlyGateway(t *testing.T) {
	p, err := auth.NewPrincipal("fixture:issuer", "", "alice", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	var dispatches atomic.Int32
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		dispatches.Add(1)
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}
	policy.CapabilityReasons = map[string]string{"native:recordingTransport": "Recording disabled by operator enrollment"}
	server, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
	if err != nil {
		t.Fatal(err)
	}
	anonymous := server.AsClient(context.Background())
	if _, err = anonymous.CallTool(context.Background(), &schema.CallToolRequestParams{Name: "skill_list", Arguments: map[string]any{}}); err == nil {
		t.Fatal("anonymous skill listing allowed")
	}
	if _, err = anonymous.CallTool(context.Background(), &schema.CallToolRequestParams{Name: "skill_get", Arguments: map[string]any{"uri": "skill://mechanize-desktop/SKILL.md"}}); err == nil {
		t.Fatal("anonymous skill retrieval allowed")
	}
	if _, err = anonymous.ReadResource(context.Background(), &schema.ReadResourceRequestParams{Uri: "skill://mechanize-desktop/SKILL.md"}); err == nil {
		t.Fatal("anonymous skill resource read allowed")
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) < 11 {
		t.Fatal("gateway tools not advertised")
	}
	call := func(name string, args map[string]any) *schema.CallToolResult {
		t.Helper()
		r, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if r.IsError != nil && *r.IsError {
			t.Fatalf("tool rejected: %+v", r)
		}
		return r
	}
	for _, method := range []string{"mechanize_capabilities", "mechanize_describe"} {
		out := call(method, map[string]any{})
		raw, _ := json.Marshal(out.StructuredContent)
		var discovery Discovery
		if json.Unmarshal(raw, &discovery) != nil || discovery.CapabilityReasons["native:recordingTransport"] != policy.CapabilityReasons["native:recordingTransport"] {
			t.Fatal("capability reason omitted", method)
		}
	}
	skillList := call("skill_list", map[string]any{})
	if skillList.StructuredContent == nil {
		t.Fatal("no skill catalog")
	}
	skillsRaw, _ := json.Marshal(skillList.StructuredContent)
	var catalog SkillCatalog
	if err = json.Unmarshal(skillsRaw, &catalog); err != nil || len(catalog.Skills) != 6 {
		t.Fatalf("expected desktop, recording, scenario, app-discovery, OpenOffice and Finder bundles: %s", skillsRaw)
	}
	for _, skill := range catalog.Skills {
		if skill.Name == "" || skill.Description == "" || skill.Ref != skill.Uri {
			t.Fatalf("skill listing missing description/reference: %+v", skill)
		}
		call("skill_get", map[string]any{"uri": skill.Uri})
	}
	guide := call("skill_get", map[string]any{"uri": "skill://mechanize-desktop/SKILL.md"})
	if text, ok := guide.StructuredContent.(map[string]any)["entrypointText"].(string); !ok || len(text) == 0 {
		t.Fatal("missing skill content")
	}
	resources, err := client.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) == 0 {
		t.Fatalf("standard skill resources unavailable: %v", err)
	}
	read, err := client.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: "skill://mechanize-desktop/SKILL.md"})
	if err != nil || len(read.Contents) == 0 {
		t.Fatalf("portable skill resource read failed: %v", err)
	}
	for _, uri := range []string{
		"skill://mechanize-app-discovery/SKILL.md",
		"skill://mechanize-app-discovery/references/app-evidence.md",
		"skill://mechanize-openoffice/SKILL.md",
		"skill://mechanize-finder/SKILL.md",
		"skill://mechanize-finder/references/files.md",
		"skill://mechanize-openoffice/references/discovery.md",
	} {
		resource, readErr := client.ReadResource(ctx, &schema.ReadResourceRequestParams{Uri: uri})
		if readErr != nil || resource == nil || len(resource.Contents) == 0 {
			t.Fatalf("app skill resource unavailable %s: %v", uri, readErr)
		}
	}
	opened := call("mechanize_session_open", map[string]any{"name": "fixture"})
	var session SessionRef
	encoded, _ := json.Marshal(opened.StructuredContent)
	if err = json.Unmarshal(encoded, &session); err != nil || session.SessionID == "" {
		t.Fatal("no session ref returned")
	}
	source := `app("com.example.Fixture").getById("save").click()`
	call("mechanize_script_validate", map[string]any{"source": source})
	started := call("mechanize_step_run", map[string]any{"sessionId": session.SessionID, "clientRequestId": "test-request", "source": source})
	var operation Operation
	encoded, _ = json.Marshal(started.StructuredContent)
	if err = json.Unmarshal(encoded, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.BusinessStatus != "unverified" {
		t.Fatal("dispatch incorrectly promoted to business success")
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = runtime.Wait(wait, session.SessionID, operation.ID); err != nil {
		t.Fatal(err)
	}
	if dispatches.Load() != 1 {
		t.Fatal("Endly did not dispatch once")
	}
	replay := call("mechanize_step_run", map[string]any{"sessionId": session.SessionID, "clientRequestId": "test-request", "source": source})
	encoded, _ = json.Marshal(replay.StructuredContent)
	var replayOp Operation
	_ = json.Unmarshal(encoded, &replayOp)
	if replayOp.ID != operation.ID || replayOp.RunID == "" || dispatches.Load() != 1 {
		t.Fatal("same request was replayed rather than deduplicated")
	}
	conflict, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_step_run", Arguments: map[string]any{"sessionId": session.SessionID, "clientRequestId": "test-request", "source": `app("com.example.Fixture").getById("different").click()`}})
	if err != nil || conflict.IsError == nil || !*conflict.IsError {
		t.Fatal("conflicting request key admitted")
	}

	call("mechanize_operation_status", map[string]any{"sessionId": session.SessionID, "operationId": operation.ID})
	denied, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_step_run", Arguments: map[string]any{"sessionId": session.SessionID, "clientRequestId": "outside", "source": `app("com.other.App").getById("save").click()`}})
	if err != nil {
		t.Fatal(err)
	}
	if denied.IsError == nil || !*denied.IsError {
		t.Fatal("outside-scope action admitted")
	}
	if dispatches.Load() != 1 {
		t.Fatal("scope rejection dispatched")
	}
	if _, err = server.AsClient(context.Background()).Initialize(context.Background()); err == nil {
		t.Fatal("unauthenticated MCP initialized")
	}
}
