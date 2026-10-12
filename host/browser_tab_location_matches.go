package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
)

type tabLocationReader interface {
	MatchTabLocation(context.Context, auth.Principal, string, string, string) (chrome.TabLocationMatch, error)
}

func (h *Host) BrowserTabLocationMatches(ctx context.Context, p auth.Principal, in gateway.BrowserTabLocationMatchesInput) (chrome.TabLocationMatch, error) {
	var reader tabLocationReader
	if h.chrome != nil {
		reader = h.chrome
	}
	return h.matchTabLocation(ctx, p, in, reader)
}

func (h *Host) matchTabLocation(ctx context.Context, requested auth.Principal, in gateway.BrowserTabLocationMatchesInput, reader tabLocationReader) (chrome.TabLocationMatch, error) {
	denied := chrome.TabLocationMatch{}
	p, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || p.Namespace != requested.Namespace || p.ClientID != requested.ClientID || !model.OpaqueTabHandle(in.TabHandle) || !model.ExactHTTPOrigin(in.ExpectedOrigin) || !gateway.ValidBrowserComparisonPath(in.ExpectedPath) || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil {
		return denied, auth.ErrUnauthorized
	}
	if _, err = h.authorize(ctx, p); err != nil {
		return denied, err
	}
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: "Compare exact browser tab location"})
	// A boolean metadata comparison cannot release private protection or grant
	// DOM, screenshot, input, or credential authority.
	lease, err := h.authorizeConsentOperation(ctx, p, model.Surface{Kind: "web", Origin: in.ExpectedOrigin, TabID: in.TabHandle}, false, consent.Observe)
	if err != nil {
		return denied, err
	}
	defer lease.Release()
	if reader == nil {
		return chrome.TabLocationMatch{Reason: "noQualifiedChannel"}, nil
	}
	out, err := reader.MatchTabLocation(lease.Context, p, in.TabHandle, in.ExpectedOrigin, in.ExpectedPath)
	if err != nil {
		return denied, err
	}
	if lease.Context.Err() != nil || h.Runtime.CheckSession(lease.Context, p, in.SessionID) != nil {
		return denied, auth.ErrUnauthorized
	}
	return out, nil
}
