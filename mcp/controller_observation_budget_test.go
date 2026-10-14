package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mcp/client"
	"github.com/viant/mechanize/model"
)

type controllerBudgetResultClient struct {
	client.Interface
	answer *schema.CallToolResult
}

func (c *controllerBudgetResultClient) CallTool(context.Context, *schema.CallToolRequestParams, ...client.RequestOption) (*schema.CallToolResult, error) {
	return c.answer, nil
}

func TestControllerObservationResultBudget(t *testing.T) {
	const canary = "PRIVATE_OBSERVATION_CANARY"
	for _, name := range []string{"mechanize_observe", "mechanize_describe"} {
		t.Run(name, func(t *testing.T) {
			d, id, ctx, actions := controllerFixture(t)
			session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
			observed := model.Observation{ID: canary, Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture"}}
			for i := 0; i < 4000; i++ {
				observed.Nodes = append(observed.Nodes, model.Node{Role: "textbox", Name: "[redacted]", Values: map[string]model.Value{"value": {Kind: model.StringValue, String: "[redacted]"}}})
			}
			encoded, err := json.Marshal(observed)
			if err != nil || len(encoded) <= 192*1024 {
				t.Fatal("fixture must exceed the unchanged result budget", err)
			}
			c, err := d.clientFor(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			c.client = &controllerBudgetResultClient{Interface: c.client, answer: &schema.CallToolResult{StructuredContent: observed, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: canary}}}}
			args := map[string]any{}
			if name == "mechanize_observe" {
				args = map[string]any{"sessionId": session, "surface": observed.Surface}
			}
			out := controllerCall(t, d, ctx, id, name, args)
			body := controllerBody(t, out)
			if out.IsError == nil || !*out.IsError {
				t.Fatal("oversized response accepted")
			}
			if name == "mechanize_observe" {
				if body["code"] != "observationTooLarge" || body["dispatchState"] != "notDispatched" || body["effectState"] != "none" || body["stage"] != "observation" || !strings.Contains(body["message"].(string), "exact-window capture") {
					t.Fatal("read-only size failure lost its closed recovery diagnostic", body)
				}
			} else if body["code"] != "controllerToolRejected" || body["dispatchState"] != "unknown" {
				t.Fatal("non-observation result limit changed", body)
			}
			wire, err := json.Marshal(out)
			if err != nil || len(wire) > 2048 || strings.Contains(string(wire), canary) || strings.Contains(string(wire), "[redacted]") || len(out.Content) != 1 || actions.Load() != 0 {
				t.Fatal("oversized result exposed content or performed input", err)
			}
		})
	}
}

func TestControllerValidObservationResultUnchanged(t *testing.T) {
	d, id, ctx, actions := controllerFixture(t)
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	observed := model.Observation{ID: "public-observation", Surface: model.Surface{Kind: "native", BundleID: "com.example.Fixture"}, Nodes: []model.Node{{Role: "button", Name: "Review"}}}
	c, err := d.clientFor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	c.client = &controllerBudgetResultClient{Interface: c.client, answer: &schema.CallToolResult{StructuredContent: observed, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: "UNTRUSTED_DUPLICATE_CANARY"}}}}
	out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{"sessionId": session, "surface": observed.Surface})
	if out.IsError != nil && *out.IsError {
		t.Fatal("valid observation rejected")
	}
	expected, _ := result(observed)
	if !reflect.DeepEqual(controllerBody(t, out), controllerBody(t, expected)) || actions.Load() != 0 {
		t.Fatal("valid observation projection changed")
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "UNTRUSTED_DUPLICATE_CANARY") {
		t.Fatal("untrusted observation text forwarded")
	}
}
