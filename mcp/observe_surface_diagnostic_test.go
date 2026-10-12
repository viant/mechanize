package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestControllerObserveMalformedSurfaceIsRepairableWithoutPermissionPrompt(t *testing.T) {
	ordinary, scoped := 0, 0
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			return script.Policy{AllowAllNative: true, AllowAllWeb: true}, nil
		}
		deps.Observe = func(_ context.Context, _ auth.Principal, s model.Surface) (model.Observation, error) {
			ordinary++
			return model.Observation{Surface: s}, nil
		}
		deps.ObserveNativeRoot = func(_ context.Context, _ auth.Principal, s model.Surface, r string, _ ...string) (model.Observation, error) {
			scoped++
			return model.Observation{Surface: s, NativeRoot: r}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	args := map[string]any{"sessionId": session, "purpose": "Inspect current UI", "nativeRoot": "menuBar"}
	for _, surface := range []model.Surface{
		{Kind: "native", Title: "PRIVATE_CANARY"},
		{Kind: "native", BundleID: "   ", Title: "PRIVATE_CANARY"},
		{Kind: "web", Title: "PRIVATE_CANARY"},
		{Kind: "web", Origin: "https://fixture.test/PRIVATE_CANARY"},
		{Kind: "chrome", Origin: "https://fixture.test"},
	} {
		args["surface"] = surface
		out := controllerCall(t, d, ctx, id, "mechanize_observe", args)
		body := controllerBody(t, out)
		if out.IsError == nil || !*out.IsError || body["code"] != "invalidSurface" || body["dispatchState"] != "notDispatched" || body["message"] != invalidSurfaceMessage {
			t.Fatal("surface error lost repair guidance", body)
		}
		wire, _ := json.Marshal(out)
		if strings.Contains(string(wire), "PRIVATE_CANARY") || strings.Contains(string(wire), "review local permissions") {
			t.Fatal("surface repair leaked input or requested permission")
		}
	}
	if ordinary != 0 || scoped != 0 {
		t.Fatal("malformed surface reached observer")
	}
	args["surface"] = model.Surface{Kind: "native", BundleID: "com.example.Fixture", Title: "Fixture"}
	out := controllerCall(t, d, ctx, id, "mechanize_observe", args)
	if out.IsError != nil && *out.IsError || scoped != 1 || ordinary != 0 {
		t.Fatal("valid native identity rejected")
	}
	delete(args, "nativeRoot")
	args["surface"] = model.Surface{Kind: "web", Origin: "https://fixture.test"}
	out = controllerCall(t, d, ctx, id, "mechanize_observe", args)
	if out.IsError != nil && *out.IsError || scoped != 1 || ordinary != 1 {
		t.Fatal("valid web identity rejected")
	}
	args["surface"] = model.Surface{Kind: "native", BundleID: "com.viant.mechanize.consent"}
	out = controllerCall(t, d, ctx, id, "mechanize_observe", args)
	if out.IsError == nil || !*out.IsError || ordinary != 1 || scoped != 1 {
		t.Fatal("authority surface became observable")
	}
}

func TestObserveDirectServerSurfaceErrorMatchesControllerRepair(t *testing.T) {
	calls := 0
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			calls++
			return script.Policy{AllowAllNative: true, AllowAllWeb: true}, nil
		}
	})
	c, e := d.clientFor(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	for _, surface := range []model.Surface{{Kind: "native", Title: "PRIVATE_CANARY"}, {Kind: "web", Origin: "https://fixture.test/path"}, {Kind: "unknown"}} {
		out, e := c.client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: map[string]any{"surface": surface, "nativeRoot": "menuBar"}})
		if e != nil {
			t.Fatal(e)
		}
		body := controllerBody(t, out)
		if body["code"] != "invalidSurface" || body["dispatchState"] != "notDispatched" || body["message"] != invalidSurfaceMessage || body["effectState"] != "none" {
			t.Fatal("direct invalid surface error differs", body)
		}
	}
	if calls != 0 {
		t.Fatal("malformed surface reached authorization/observer")
	}
}

func TestObserveDiscoveryDeclaresConditionalSurfaceIdentity(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t)
	listed, e := d.ListTools(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(listed)
	var wire struct {
		Tools []struct {
			Name, Description string
			InputSchema       struct {
				Properties map[string]struct{ Description string } `json:"properties"`
			} `json:"inputSchema"`
		}
	}
	if e = json.Unmarshal(raw, &wire); e != nil {
		t.Fatal(e)
	}
	for _, tool := range wire.Tools {
		if tool.Name == "mechanize_observe" {
			for _, description := range []string{tool.Description, tool.InputSchema.Properties["surface"].Description} {
				if !strings.Contains(description, "Native surfaces require") || !strings.Contains(description, "bundleId") || !strings.Contains(description, "web surfaces require") || !strings.Contains(description, "exact http(s) origin") || !strings.Contains(description, "title") {
					t.Fatal("conditional identity guidance missing", description)
				}
			}
			return
		}
	}
	t.Fatal("observe catalog missing")
}

func TestControllerNativeWindowMissingProcessExplainsDiscovery(t *testing.T) {
	calls := 0
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			return script.Policy{AllowAllNative: true}, nil
		}
		deps.ObserveNativeWindow = func(context.Context, auth.Principal, model.Surface, string, string) (model.Observation, error) {
			calls++
			return model.Observation{}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{
		"sessionId": session, "purpose": "Inspect current interface",
		"surface":     model.Surface{Kind: "native", BundleID: "com.example.Fixture"},
		"windowScope": map[string]any{"title": "PRIVATE_CANARY"},
	})
	body := controllerBody(t, out)
	message, _ := body["message"].(string)
	if out.IsError == nil || !*out.IsError || body["code"] != "invalidScope" || body["dispatchState"] != "notDispatched" || !strings.Contains(message, "processStartToken") || !strings.Contains(message, "mechanize_capture_windows") || calls != 0 {
		t.Fatal("missing native identity lost discovery guidance", body)
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "PRIVATE_CANARY") || strings.Contains(string(wire), "review local permissions") {
		t.Fatal("scope repair leaked input or requested permission")
	}
}
