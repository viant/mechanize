package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestOperationOutputsMCPExplicitClosedOwnedEphemeral(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "outputs-mcp", nil)
	p.ClientID = "client-a"
	ctx := auth.WithPrincipal(context.Background(), p)
	r, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		v := model.Value{Kind: model.StringValue, String: "2"}
		return automation.StepResult{Value: &v}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "calculator")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	plan, err := script.Compile(`let result = app("com.example.Fixture").getById("result").read("staticText")`)
	if err != nil {
		t.Fatal(err)
	}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(deadline, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	gateway, err := server.New(server.WithNewHandler(protocol.WithDefaultHandler(ctx, func(base *protocol.DefaultHandler) error { return registerOperationOutputs(base, r) })))
	if err != nil {
		t.Fatal(err)
	}
	client := gateway.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	tools, err := client.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "mechanize_operation_outputs" {
		t.Fatal("outputs tool not advertised")
	}
	body, _ := json.Marshal(tools.Tools[0].InputSchema)
	if !strings.Contains(string(body), `"additionalProperties":false`) {
		t.Fatal("input schema not closed")
	}
	args := map[string]any{"sessionId": session.SessionID, "operationId": op.ID, "bindings": []string{"result"}}
	out, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_operation_outputs", Arguments: args})
	if err != nil || out.IsError != nil && *out.IsError {
		t.Fatalf("output failed %v %+v", err, out)
	}
	body, _ = json.Marshal(out.StructuredContent)
	var got automation.OperationOutputs
	if err = json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outputs["result"].String != "2" || got.Storage != "ephemeralRuntime" {
		t.Fatalf("bad result %+v", got)
	}
	args["credentials"] = "must-never-enter-runtime"
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_operation_outputs", Arguments: args})
	if err == nil && (out.IsError == nil || !*out.IsError) {
		t.Fatal("unknown field admitted")
	}
	delete(args, "credentials")
	other := p
	other.ClientID = "client-b"
	out, err = client.CallTool(auth.WithPrincipal(ctx, other), &schema.CallToolRequestParams{Name: "mechanize_operation_outputs", Arguments: args})
	if err == nil && (out.IsError == nil || !*out.IsError) {
		t.Fatal("same-user other client admitted")
	}
}
