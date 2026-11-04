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
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/model"
)

type ApplicationPresence func(context.Context, auth.Principal, model.Surface) (native.ApplicationPresence, error)
type ApplicationPresenceInput struct {
	SessionID string `json:"sessionId"`
	GrantID   string `json:"grantId,omitempty"`
	Purpose   string `json:"purpose"`
	BundleID  string `json:"bundleId"`
}

func registerApplicationPresence(base *protocol.DefaultHandler, d Dependencies) error {
	if d.ApplicationPresence == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if err := input.Load((*ApplicationPresenceInput)(nil)); err != nil {
		return err
	}
	extra, _ := input.AdditionalProperties.(map[string]any)
	if extra == nil {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if err := output.Load((*native.ApplicationPresence)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_application_presence", "Read exact native app presence under owned session observe consent. Returns running with freshly checked PID/birth, ambiguous, or notObserved. notObserved is not proof of process exit or permission to relaunch. Reads no window titles or document content; performs no launch, activation, or input. Process presence does not establish UI readiness.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if req == nil {
			return closedBrowserFailure("invalidArguments")
		}
		raw, err := json.Marshal(req.Params.Arguments)
		if err != nil || len(raw) > 16384 {
			return closedBrowserFailure("invalidArguments")
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var in *ApplicationPresenceInput
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in == nil || in.BundleID == "" {
			return closedBrowserFailure("invalidArguments")
		}
		bound, p, err := captureContext(ctx, in.SessionID, in.GrantID, in.Purpose)
		if err != nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return closedBrowserFailure("sessionNotOwned")
		}
		value, err := d.ApplicationPresence(bound, p, model.Surface{Kind: "native", BundleID: in.BundleID})
		if err != nil {
			var typed *model.MechanizeError
			if errors.As(err, &typed) && typed.DispatchState == "notDispatched" {
				switch typed.Code {
				case "permissionRequired", "permissionExpired", "permissionDenied":
					return closedBrowserFailure(typed.Code)
				}
			}
			return closedBrowserFailure("applicationPresenceUnavailable")
		}
		return result(value)
	})
	return nil
}
