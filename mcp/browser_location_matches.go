package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

type BrowserLocationMatches func(context.Context, auth.Principal, string) (chrome.FocusedOriginMatch, error)
type BrowserLocationMatchesInput struct {
	SessionID      string `json:"sessionId"`
	ExpectedOrigin string `json:"expectedOrigin"`
}

const focusedOriginPurpose = "Compare focused browser origin"

func registerBrowserLocationMatches(base *protocol.DefaultHandler, d Dependencies) error {
	if d.BrowserLocationMatches == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if err := input.Load((*BrowserLocationMatchesInput)(nil)); err != nil {
		return err
	}
	extra, ok := input.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if err := output.Load((*chrome.FocusedOriginMatch)(nil)); err != nil {
		return err
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_location_matches", "Compare one expected exact HTTP(S) origin with the loaded active tab in Chrome's focused window, or its last active normal window when Chrome is backgrounded. Requires owned session and existing observe consent. Returns only a boolean comparison and closed metadata; no URL, title, page content, native focus or omnibox verification. Available during credential protection without granting browser input authority.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		rejected := func() (*schema.CallToolResult, *jsonrpc.Error) {
			return failure(errors.New("focused browser origin comparison unavailable"))
		}
		if req == nil {
			return rejected()
		}
		raw, err := json.Marshal(req.Params.Arguments)
		if err != nil || len(raw) > 4096 {
			return rejected()
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var in *BrowserLocationMatchesInput
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in == nil || in.SessionID == "" || len(in.SessionID) > 512 || len(in.ExpectedOrigin) > 512 || !chrome.OrdinaryWebsiteOrigin(in.ExpectedOrigin) {
			return rejected()
		}
		p, err := auth.FromContext(ctx)
		if err != nil || d.Runtime == nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return rejected()
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: focusedOriginPurpose})
		out, err := d.BrowserLocationMatches(ctx, p, in.ExpectedOrigin)
		if err != nil || !focusedOriginResultValid(out) {
			return rejected()
		}
		return result(out)
	})
	return nil
}

func focusedOriginResultValid(out chrome.FocusedOriginMatch) bool {
	switch out.Reason {
	case "none", "noFocusedWindow", "ambiguousFocusedTab", "permissionUnavailable", "tabUnavailable", "pendingNavigation", "unsafeTab", "unsupportedLocation", "authorityChanged", "transportUnavailable", "noQualifiedChannel", "unsupportedWorker":
	default:
		return false
	}
	if out.Evidence != "" && out.Evidence != "extensionFocusedTab" && out.Evidence != "extensionLastActiveTab" {
		return false
	}
	if out.Available {
		if out.Reason != "none" || out.WindowFocused && out.Evidence != "extensionFocusedTab" || !out.WindowFocused && out.Evidence != "extensionLastActiveTab" {
			return false
		}
	} else if out.MatchesExpectedOrigin || out.Reason == "none" || out.Evidence != "" || out.WindowFocused {
		return false
	}
	if out.TabHandle != "" {
		if !out.Available || !out.MatchesExpectedOrigin || len(out.TabHandle) > 512 || strings.ContainsAny(out.TabHandle, ":?#\\ \t\n\r") {
			return false
		}
	}
	return true
}
