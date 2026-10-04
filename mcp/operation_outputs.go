package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
)

type OperationOutputsInput struct {
	SessionID   string   `json:"sessionId"`
	OperationID string   `json:"operationId"`
	Bindings    []string `json:"bindings"`
}

func registerOperationOutputs(base *protocol.DefaultHandler, runtime *automation.Runtime) error {
	var input schema.ToolInputSchema
	if err := json.Unmarshal([]byte(`{"type":"object","additionalProperties":false,"required":["sessionId","operationId","bindings"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":256},"operationId":{"type":"string","minLength":1,"maxLength":256},"bindings":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z_][A-Za-z0-9_]*$"}}}}`), &input); err != nil {
		return err
	}
	var output schema.ToolOutputSchema
	if err := output.Load((*automation.OperationOutputs)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_operation_outputs", "Read explicitly named safe element.read bindings from your client's successfully completed live operation. Read only; bounded ephemeral runtime values disappear on session close/restart. This does not read durable state or resolve inputs, secrets or credentials. Pending/failed operations and unknown read bindings are rejected; withheld values have explicit unavailable reasons.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if req == nil {
			return failure(errors.New("explicit operation output request required"))
		}
		body, err := json.Marshal(req.Params.Arguments)
		if err != nil || len(body) > 4096 {
			return failure(errors.New("bounded operation output request required"))
		}
		var in OperationOutputsInput
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&in); err != nil {
			return failure(errors.New("closed operation output schema required"))
		}
		if _, err = auth.FromContext(ctx); err != nil {
			return failure(err)
		}
		if runtime == nil {
			return failure(errors.New("runtime outputs capability unavailable"))
		}
		value, err := runtime.OperationOutputs(ctx, in.SessionID, in.OperationID, in.Bindings)
		if err != nil {
			return failure(err)
		}
		return result(value)
	})
	return nil
}
