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

type BrowserTabLocationMatchesInput struct {
	SessionID      string `json:"sessionId"`
	TabHandle      string `json:"tabHandle"`
	ExpectedOrigin string `json:"expectedOrigin"`
	ExpectedPath   string `json:"expectedPath,omitempty"`
}
type BrowserTabLocationMatches func(context.Context, auth.Principal, BrowserTabLocationMatchesInput) (chrome.TabLocationMatch, error)

// Only caller-provided public path equality is supported; never a query,
// fragment, prefix match, raw URL read or page-supplied text projection.
func ValidBrowserComparisonPath(path string) bool {
	return chrome.ValidExpectedTabPath("https://comparison.invalid", path)
}

func tabLocationResultValid(out chrome.TabLocationMatch) bool {
	switch out.Reason {
	case "none", "permissionUnavailable", "tabUnavailable", "pendingNavigation", "unsafeTab", "unsupportedLocation", "authorityChanged", "transportUnavailable", "noQualifiedChannel", "unsupportedWorker":
	default:
		return false
	}
	if !out.Available {
		return out.Reason != "none" && !out.MatchesExpectedOrigin && !out.PathChecked && !out.MatchesExpectedPath
	}
	return out.Reason == "none" && (!out.MatchesExpectedPath || out.MatchesExpectedOrigin && out.PathChecked)
}

func registerBrowserTabLocationMatches(base *protocol.DefaultHandler, d Dependencies) error {
	if d.BrowserTabLocationMatches == nil {
		return nil
	}
	var input schema.ToolInputSchema
	if e := json.Unmarshal([]byte(`{"type":"object","additionalProperties":false,"required":["sessionId","tabHandle","expectedOrigin"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":256},"tabHandle":{"type":"string","minLength":1,"maxLength":512},"expectedOrigin":{"type":"string","minLength":1,"maxLength":2048},"expectedPath":{"type":"string","maxLength":2048}}}`), &input); e != nil {
		return e
	}
	var output schema.ToolOutputSchema
	if e := output.Load((*chrome.TabLocationMatch)(nil)); e != nil {
		return e
	}
	base.Registry.RegisterToolWithSchema("mechanize_browser_tab_location_matches", "Compare an exact owned opaque tab's current origin and optional public pathname, including background or credential-protected tabs. Returns match booleans and a closed reason only; never actual URL, query, fragment, title, DOM or credentials. Does not activate, navigate or grant content access.", input, &output, func(ctx context.Context, req *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		fail := func() (*schema.CallToolResult, *jsonrpc.Error) {
			return failure(errors.New("exact browser tab comparison unavailable"))
		}
		if req == nil {
			return fail()
		}
		raw, e := json.Marshal(req.Params.Arguments)
		if e != nil || len(raw) > 8192 {
			return fail()
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var in *BrowserTabLocationMatchesInput
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in == nil || len(in.SessionID) < 1 || len(in.SessionID) > 256 || len(in.TabHandle) > 512 || !model.OpaqueTabHandle(in.TabHandle) || !model.ExactHTTPOrigin(in.ExpectedOrigin) || !ValidBrowserComparisonPath(in.ExpectedPath) {
			return fail()
		}
		p, e := auth.FromContext(ctx)
		if e != nil || d.Runtime == nil || d.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
			return fail()
		}
		out, e := d.BrowserTabLocationMatches(ctx, p, *in)
		if e != nil || !tabLocationResultValid(out) || out.Available && out.PathChecked != (in.ExpectedPath != "") {
			return fail()
		}
		return result(out)
	})
	return nil
}
