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
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
)

type BrowserTabs func(context.Context, auth.Principal, model.Surface) (chrome.TabHandleInventory, error)
type BrowserTabsInput struct {
	SessionID string        `json:"sessionId"`
	GrantID   string        `json:"grantId,omitempty"`
	Purpose   string        `json:"purpose"`
	Surface   model.Surface `json:"surface"`
}

func registerBrowserTabs(base *protocol.DefaultHandler, d Dependencies) error {
	if d.BrowserTabs == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if err := input.Load((*BrowserTabsInput)(nil)); err != nil {
		return err
	}
	extra, ok := input.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if err := output.Load((*chrome.TabHandleInventory)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_tabs", "List opaque tab handles for one approved exact website origin. Requires owned session and observe consent; omits page titles and contents.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		rejected := func() (*schema.CallToolResult, *jsonrpc.Error) { return closedBrowserFailure("invalidArguments") }
		if req == nil {
			return rejected()
		}
		raw, err := json.Marshal(req.Params.Arguments)
		if err != nil || len(raw) > 16384 {
			return rejected()
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var in *BrowserTabsInput
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in == nil || in.SessionID == "" || in.Purpose == "" {
			return rejected()
		}
		p, err := auth.FromContext(ctx)
		if err != nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return closedBrowserFailure("sessionNotOwned")
		}
		if in.Surface.Kind != "web" || !chrome.OrdinaryWebsiteOrigin(in.Surface.Origin) || in.Surface.TabID != "" || in.Surface.Title != "" || in.Surface.BundleID != "" || in.Surface.ProcessID != 0 || in.Surface.ProcessStartToken != "" {
			return closedBrowserFailure("invalidSurface")
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, GrantID: in.GrantID, Purpose: in.Purpose})
		out, err := d.BrowserTabs(ctx, p, in.Surface)
		if err != nil {
			var typed *model.MechanizeError
			if errors.As(err, &typed) && typed.DispatchState == "notDispatched" {
				switch typed.Code {
				case "permissionRequired", "permissionExpired", "permissionDenied":
					return closedBrowserFailure(typed.Code)
				}
			}
			return closedBrowserFailure("browserInventoryUnavailable")
		}
		return result(out)
	})
	return nil
}

// Only server-selected finite codes cross this metadata boundary. Raw callback
// errors may contain private state and are never serialized.
func closedBrowserFailure(code string) (*schema.CallToolResult, *jsonrpc.Error) {
	return failure(&model.MechanizeError{Code: code, Message: "Request unavailable; check the declared scope, session and permission status", Stage: "admission", DispatchState: "notDispatched", EffectState: "none"})
}
