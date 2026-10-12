package mcp

import (
	"context"
	"encoding/json"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"sync/atomic"
	"testing"
)

func TestObserveUnknownScopeNeverWidensToApp(t *testing.T) {
	var calls atomic.Int32
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.Observe = func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
			calls.Add(1)
			return model.Observation{}, nil
		}
	})
	c, err := d.clientFor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nativeWindow", "windowTitel", "unrecognized"} {
		out, err := c.client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: map[string]any{"surface": map[string]any{"kind": "native", "bundleId": "com.example.Fixture"}, field: map[string]any{"title": "Fixture"}}})
		if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
			t.Fatalf("unknown scope %s silently accepted", field)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid scope reached backend")
	}
	var input ObserveInput
	if err := json.Unmarshal([]byte(`{"surface":{"kind":"native","bundleId":"fixture"},"nativeRoot":"menuBar","nativeMenu":"Git","sessionId":"s","grantId":"g","purpose":"inspect"}`), &input); err != nil || input.NativeMenu != "Git" {
		t.Fatal("accepted menu fields changed", err)
	}
	if err := json.Unmarshal([]byte(`{"surface":{"kind":"native"},"windowScope":{"title":"Fixture","role":"AXWindow"}}`), &input); err != nil || input.WindowScope == nil {
		t.Fatal("accepted window fields changed", err)
	}
}
