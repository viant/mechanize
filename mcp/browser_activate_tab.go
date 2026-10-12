package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type BrowserActivateTabInput struct {
	SessionID       string `json:"sessionId"`
	ClientRequestID string `json:"clientRequestId"`
	Origin          string `json:"origin"`
	TabHandle       string `json:"tabHandle"`
}
type BrowserActivateTabResult struct {
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	RunID       string `json:"runId"`
	OperationID string `json:"operationId"`
}
type BrowserActivateTab func(context.Context, auth.Principal, BrowserActivateTabInput) (BrowserActivateTabResult, error)

func registerBrowserActivateTab(base *protocol.DefaultHandler, d Dependencies) error {
	if d.BrowserActivateTab == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if e := json.Unmarshal([]byte(`{"type":"object","additionalProperties":false,"required":["sessionId","clientRequestId","origin","tabHandle"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":256},"clientRequestId":{"type":"string","minLength":1,"maxLength":128},"origin":{"type":"string","minLength":1,"maxLength":2048},"tabHandle":{"type":"string","minLength":1,"maxLength":300}}}`), &input); e != nil {
		return e
	}
	var output schema.ToolOutputSchema
	if e := output.Load((*BrowserActivateTabResult)(nil)); e != nil {
		return e
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_activate_tab", "Activate an existing opaque browser tab at the exact approved HTTP(S) origin and focus its Chrome window through a one-step durable plan. Requires owned session and current origin Control consent. Preserves tabs and private protection; reads no DOM or credentials and enters no input. Reuse clientRequestId to check the same request; uncertain activation is never transparently replayed. Returns activated/pending/notDispatched/unknown with finite reason and tracked run/operation references. Activated confirms browser tab/window state only.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		fail := func() (*schema.CallToolResult, *jsonrpc.Error) {
			return failure(errors.New("tracked browser tab activation unavailable"))
		}
		if req == nil {
			return fail()
		}
		raw, e := json.Marshal(req.Params.Arguments)
		if e != nil || len(raw) > 4096 {
			return fail()
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var in *BrowserActivateTabInput
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in == nil || len(in.SessionID) < 1 || len(in.SessionID) > 256 || len(in.ClientRequestID) < 1 || len(in.ClientRequestID) > 128 || !model.ExactHTTPOrigin(in.Origin) || !model.OpaqueTabHandle(in.TabHandle) {
			return fail()
		}
		p, e := auth.FromContext(ctx)
		if e != nil || d.Runtime == nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return fail()
		}
		out, e := d.BrowserActivateTab(ctx, p, *in)
		if e != nil || out.RunID == "" || out.OperationID == "" || out.Outcome != "activated" && out.Outcome != "unknown" && out.Outcome != "notDispatched" && out.Outcome != "pending" || out.Reason == "" || model.TabActivationReason(out.Reason) != out.Reason || out.Outcome == "activated" && out.Reason != "none" || out.Outcome != "activated" && out.Reason == "none" {
			return fail()
		}
		return result(out)
	})
	return nil
}
