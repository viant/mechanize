package mcp

import (
	"context"
	"errors"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
)

type ResumeInput struct {
	SessionID           string `json:"sessionId"`
	RunID               string `json:"runId"`
	ExpectedRevision    int    `json:"expectedRevision"`
	ExpectedPlanID      string `json:"expectedPlanId"`
	ExpectedObjectiveID string `json:"expectedObjectiveId"`
	GrantID             string `json:"grantId"`
	Purpose             string `json:"purpose"`
}

func registerResume(base *protocol.DefaultHandler, d Dependencies) error {
	if d.StateResume == nil {
		return nil
	}
	return protocol.RegisterTool[*ResumeInput, *Operation](base.Registry, "mechanize_state_resume", "Resume a stopped owned run through Endly in your already-open, human-approved session. Supply current state revision and immutable plan/objective identities. Unknown effects, stale revisions or missing desktop fence block admission; confirmed effects are skipped.", func(ctx context.Context, in *ResumeInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil || in.SessionID == "" || in.RunID == "" || in.ExpectedRevision <= 0 || in.ExpectedPlanID == "" || in.ExpectedObjectiveID == "" || in.GrantID == "" || in.Purpose == "" {
			return failure(errors.New("owned session, run, revision, plan/objective identities, approved grant and purpose required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: in.GrantID, SessionID: in.SessionID, Purpose: in.Purpose})
		resumed, err := d.StateResume(ctx, p, in.SessionID, in.RunID, in.ExpectedRevision, in.ExpectedPlanID, in.ExpectedObjectiveID)
		if err != nil {
			return failure(err)
		}
		if resumed == nil || resumed.Operation == nil || resumed.SessionID != in.SessionID || resumed.RunID != in.RunID || resumed.Operation.SessionID != in.SessionID {
			return failure(errors.New("resume admission returned mismatched owned operation"))
		}
		o := resumed.Operation
		return operationResult(ctx, d.Runtime, Operation{RunID: resumed.RunID, ID: o.ID, SessionID: resumed.SessionID, ExecutionStatus: o.Status, Error: o.Error})
	})
}
