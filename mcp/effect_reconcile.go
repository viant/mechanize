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

type EffectReconcileInput struct {
	SessionID              string `json:"sessionId"`
	GrantID                string `json:"grantId,omitempty"`
	Purpose                string `json:"purpose"`
	RunID                  string `json:"runId"`
	PlanID                 string `json:"planId"`
	AttemptID              string `json:"attemptId"`
	EffectID               string `json:"effectId"`
	ExpectedRunRevision    int    `json:"expectedRunRevision"`
	ExpectedEffectRevision int    `json:"expectedEffectRevision"`
	RequestID              string `json:"requestId"`
}

func registerEffectReconciliation(base *protocol.DefaultHandler, d Dependencies) error {
	if d.EffectReconcile == nil {
		return nil
	}
	var inputSchema schema.ToolInputSchema
	if err := inputSchema.Load((*EffectReconcileInput)(nil)); err != nil {
		return err
	}
	extra, ok := inputSchema.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	inputSchema.AdditionalProperties = extra
	var outputSchema schema.ToolOutputSchema
	if err := outputSchema.Load((*durable.EffectReconcileResult)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_effect_reconcile", "Reconcile an owned unresolved effect using a host-enrolled fresh read contract and exact expected revisions. Never supplies success evidence, replays input, edits the original plan, or resumes execution. Reuse the requestId to inspect a lost commit reply.", inputSchema, &outputSchema, func(ctx context.Context, request *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if request == nil {
			return failure(errors.New("bounded reconciliation input required"))
		}
		raw, err := json.Marshal(request.Params.Arguments)
		if err != nil || len(raw) > 8192 {
			return failure(errors.New("bounded reconciliation input required"))
		}
		var in *EffectReconcileInput
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			return failure(errors.New("closed reconciliation identity input required; caller evidence or success fields are not accepted"))
		}
		if in == nil || in.SessionID == "" || in.Purpose == "" || len(in.Purpose) > 4000 {
			return failure(errors.New("owned session and bounded reconciliation purpose required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		if err = d.Runtime.CheckSession(ctx, p, in.SessionID); err != nil {
			return failure(err)
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, GrantID: in.GrantID, Purpose: in.Purpose})
		resolved, err := d.EffectReconcile(ctx, p, durable.EffectReconcileRequest{RunID: in.RunID, PlanID: in.PlanID, AttemptID: in.AttemptID, EffectID: in.EffectID, ExpectedRunRevision: in.ExpectedRunRevision, ExpectedEffectRevision: in.ExpectedEffectRevision, RequestID: in.RequestID})
		if err != nil && !resolved.CommitConfirmed {
			return failure(err)
		}
		r, protocolErr := result(resolved)
		if err != nil && r != nil {
			yes := true
			r.IsError = &yes
		}
		return r, protocolErr
	})
	return nil
}
