package mcp

import (
	"context"
	"errors"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
)

type StateRef struct {
	RunID string `json:"runId"`
}
type StateBoundary struct {
	RunID            string `json:"runId"`
	ExpectedRevision int    `json:"expectedRevision"`
}
type StateUpdate struct {
	RunID            string                 `json:"runId"`
	ExpectedRevision int                    `json:"expectedRevision"`
	Variables        map[string]model.Value `json:"variables"`
}

func registerState(base *protocol.DefaultHandler, d Dependencies) error {
	if d.StateGet != nil {
		if err := protocol.RegisterTool[*StateRef, *durable.State](base.Registry, "mechanize_state_get", "Inspect your durable run variables, revision, progress, checkpoints and unresolved effects. This does not execute or resume actions.", func(ctx context.Context, input *StateRef) (*schema.CallToolResult, *jsonrpc.Error) {
			if input == nil || input.RunID == "" {
				return failure(errors.New("runId required"))
			}
			p, err := auth.FromContext(ctx)
			if err != nil {
				return failure(err)
			}
			state, err := d.StateGet(ctx, p, input.RunID)
			if err != nil {
				return failure(err)
			}
			return result(state)
		}); err != nil {
			return err
		}
	}
	if d.StatePatch != nil {
		if err := protocol.RegisterTool[*StateUpdate, *durable.State](base.Registry, "mechanize_state_patch", "Update permitted typed variables in a safely paused/new owned run using its expected revision. Never changes objectives, history or the effect ledger; active/uncertain runs are rejected.", func(ctx context.Context, input *StateUpdate) (*schema.CallToolResult, *jsonrpc.Error) {
			if input == nil || input.RunID == "" || input.ExpectedRevision <= 0 || len(input.Variables) == 0 {
				return failure(errors.New("runId, positive expectedRevision and typed variables required"))
			}
			p, err := auth.FromContext(ctx)
			if err != nil {
				return failure(err)
			}
			state, err := d.StatePatch(ctx, p, input.RunID, input.ExpectedRevision, input.Variables)
			if err != nil {
				return failure(err)
			}
			return result(state)
		}); err != nil {
			return err
		}
	}
	if d.StatePause != nil {
		return protocol.RegisterTool[*StateBoundary, *durable.State](base.Registry, "mechanize_state_pause", "Stop the owned Endly run, wait for a safe boundary and publish a guarded durable pause. Uncertain effects remain a reconciliation barrier.", func(ctx context.Context, input *StateBoundary) (*schema.CallToolResult, *jsonrpc.Error) {
			if input == nil || input.RunID == "" || input.ExpectedRevision <= 0 {
				return failure(errors.New("runId and positive expectedRevision required"))
			}
			p, err := auth.FromContext(ctx)
			if err != nil {
				return failure(err)
			}
			state, err := d.StatePause(ctx, p, input.RunID, input.ExpectedRevision)
			if err != nil {
				return failure(err)
			}
			return result(state)
		})
	}
	return nil
}
