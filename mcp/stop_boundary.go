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
	"github.com/viant/mechanize/engine/durable"
)

type StopBoundaryInput struct {
	SessionID           string `json:"sessionId"`
	Purpose             string `json:"purpose"`
	RunID               string `json:"runId"`
	PlanID              string `json:"planId"`
	RequestID           string `json:"requestId"`
	ExpectedRunRevision int    `json:"expectedRunRevision"`
}

func registerStopBoundary(base *protocol.DefaultHandler, d Dependencies) error {
	if d.StateStopBoundary == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if err := input.Load((*StopBoundaryInput)(nil)); err != nil {
		return err
	}
	extra, ok := input.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if err := output.Load((*durable.StopBoundaryResult)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_state_stop_boundary", "Record an already-quiescent native run as paused while preserving unknown effects and original outcomes. Requires exact owned references and a stable requestId. Rejects live operations; cancel them through Endly first. Does not execute input, clear uncertainty or admit resume.", input, &output, func(ctx context.Context, request *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if request == nil {
			return failure(errors.New("stopped-boundary input required"))
		}
		raw, err := json.Marshal(request.Params.Arguments)
		if err != nil || len(raw) > 8192 {
			return failure(errors.New("bounded stopped-boundary input required"))
		}
		var in *StopBoundaryInput
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in == nil || in.SessionID == "" || in.Purpose == "" || len(in.Purpose) > 4000 {
			return failure(errors.New("closed stopped-boundary references and purpose required; caller proof is not accepted"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		if d.Runtime == nil {
			return failure(errors.New("owned runtime unavailable"))
		}
		if err = d.Runtime.CheckSession(ctx, p, in.SessionID); err != nil {
			return failure(err)
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: in.Purpose})
		stopped, err := d.StateStopBoundary(ctx, p, durable.StopBoundaryRequest{RunID: in.RunID, PlanID: in.PlanID, RequestID: in.RequestID, ExpectedRunRevision: in.ExpectedRunRevision})
		if err != nil && !stopped.CommitConfirmed {
			return failure(err)
		}
		r, rpcErr := result(stopped)
		if err != nil && r != nil {
			yes := true
			r.IsError = &yes
		}
		return r, rpcErr
	})
	return nil
}
