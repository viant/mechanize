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

type BrowserOpenOriginInput struct {
	SessionID       string `json:"sessionId"`
	ClientRequestID string `json:"clientRequestId"`
	Origin          string `json:"origin"`
}
type BrowserOpenOriginResult struct {
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	TabHandle   string `json:"tabHandle,omitempty"`
	RunID       string `json:"runId"`
	OperationID string `json:"operationId"`
}
type BrowserOpenOrigin func(context.Context, auth.Principal, BrowserOpenOriginInput) (BrowserOpenOriginResult, error)

func registerBrowserOpenOrigin(base *protocol.DefaultHandler, d Dependencies) error {
	if d.BrowserOpenOrigin == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if e := json.Unmarshal([]byte(`{"type":"object","additionalProperties":false,"required":["sessionId","clientRequestId","origin"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":256},"clientRequestId":{"type":"string","minLength":1,"maxLength":128},"origin":{"type":"string","minLength":1,"maxLength":2048}}}`), &input); e != nil {
		return e
	}
	var output schema.ToolOutputSchema
	if e := output.Load((*BrowserOpenOriginResult)(nil)); e != nil {
		return e
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_open_origin", "Open an approved exact HTTP(S) origin root in one NEW BACKGROUND tab through a one-step durable plan. Requires owned session and current origin Control consent. Preserves existing tabs and private protection; reads no document or credentials. Reuse the same clientRequestId when checking this request: an unknown creation is never transparently replayed. Returns only created/pending/notDispatched/unknown outcome and finite reason, opaque tab handle when confirmed, and tracked run/operation references.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		fail := func() (*schema.CallToolResult, *jsonrpc.Error) {
			return failure(errors.New("tracked browser origin opening unavailable"))
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
		var in *BrowserOpenOriginInput
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in == nil || len(in.SessionID) < 1 || len(in.SessionID) > 256 || len(in.ClientRequestID) < 1 || len(in.ClientRequestID) > 128 || !model.ExactHTTPOrigin(in.Origin) {
			return fail()
		}
		p, e := auth.FromContext(ctx)
		if e != nil || d.Runtime == nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return fail()
		}
		out, e := d.BrowserOpenOrigin(ctx, p, *in)
		if e != nil || out.RunID == "" || out.OperationID == "" || out.Outcome != "created" && out.Outcome != "unknown" && out.Outcome != "notDispatched" && out.Outcome != "pending" || out.Outcome == "created" && !model.OpaqueTabHandle(out.TabHandle) || out.Outcome != "created" && out.TabHandle != "" || out.Reason == "" || model.OpenOriginReason(out.Reason) != out.Reason || out.Outcome == "created" && out.Reason != "none" || out.Outcome != "created" && out.Reason == "none" {
			return fail()
		}
		return result(out)
	})
	return nil
}
