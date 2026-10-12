package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
)

type ExtensionMaintenanceInput struct {
	SessionID       string `json:"sessionId"`
	ClientRequestID string `json:"clientRequestId"`
	ExpectedVersion string `json:"expectedVersion"`
	ProfileChannel  string `json:"profileChannel,omitempty"`
	BrowserInstance string `json:"browserInstance,omitempty"`
}
type ExtensionMaintenance func(context.Context, auth.Principal, ExtensionMaintenanceInput) (chrome.ExtensionMaintenanceResult, error)

func validExtensionMaintenanceInput(in *ExtensionMaintenanceInput) bool {
	return in != nil && len(in.SessionID) > 0 && len(in.SessionID) <= 256 && len(in.ClientRequestID) > 0 && len(in.ClientRequestID) <= 128 && chrome.ValidExtensionVersion(in.ExpectedVersion) && len(in.ProfileChannel) <= 128 && len(in.BrowserInstance) <= 128 && (in.ProfileChannel == "") == (in.BrowserInstance == "")
}
func registerExtensionMaintenance(base *protocol.DefaultHandler, d Dependencies) error {
	for _, entry := range []struct {
		name, description string
		call              ExtensionMaintenance
	}{
		{"mechanize_extension_reload", "Native MCP only: reload this enrolled local extension once for an owned session and original clientRequestId. Keeps pages and historical receipts; refuses active input/private exchanges. No website controller exposure. A missing acknowledgement remains unknown and is never automatically replayed; use extension reload status with the original request fields.", d.ExtensionReload},
		{"mechanize_extension_reload_status", "Native MCP only: read the original local extension maintenance intent under the same owned session and clientRequestId. Reports independently observed new boot and expected version without replaying reload or claiming business completion.", d.ExtensionReloadStatus},
	} {
		if entry.call == nil {
			continue
		}
		var input schema.ToolInputSchema
		if e := json.Unmarshal([]byte(`{"type":"object","additionalProperties":false,"required":["sessionId","clientRequestId","expectedVersion"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":256},"clientRequestId":{"type":"string","minLength":1,"maxLength":128},"expectedVersion":{"type":"string","minLength":1,"maxLength":23,"description":"Desired installed extension version, for example 0.1.70."},"profileChannel":{"type":"string","maxLength":128},"browserInstance":{"type":"string","maxLength":128}}}`), &input); e != nil {
			return e
		}
		var output schema.ToolOutputSchema
		if e := output.Load((*chrome.ExtensionMaintenanceResult)(nil)); e != nil {
			return e
		}
		call := entry.call
		base.Registry.RegisterToolWithSchema(entry.name, entry.description, input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
			denied := func() (*schema.CallToolResult, *jsonrpc.Error) {
				return failure(&model.MechanizeError{Code: "extensionMaintenanceUnavailable", Message: "Native local extension maintenance request unavailable.", Stage: "admission", DispatchState: "notDispatched"})
			}
			if req == nil {
				return denied()
			}
			raw, e := json.Marshal(req.Params.Arguments)
			if e != nil || len(raw) > 2048 {
				return denied()
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			var in *ExtensionMaintenanceInput
			if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || !validExtensionMaintenanceInput(in) {
				return denied()
			}
			p, e := auth.FromContext(ctx)
			if e != nil || !p.HasScope("desktop:control") || p.ClientID == "" || strings.HasPrefix(p.ClientID, "controller:") || d.Runtime == nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
				return denied()
			}
			out, e := call(ctx, p, *in)
			if e != nil {
				return denied()
			}
			return result(out)
		})
	}
	return nil
}
