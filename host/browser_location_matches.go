package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

type focusedOriginReader interface {
	MatchFocusedOrigin(context.Context, auth.Principal, string) (chrome.FocusedOriginMatch, error)
}

// BrowserLocationMatches compares the loaded active tab in the extension's
// focused window. It does not inspect the native omnibox or website content.
func (h *Host) BrowserLocationMatches(ctx context.Context, p auth.Principal, expectedOrigin string) (chrome.FocusedOriginMatch, error) {
	var reader focusedOriginReader
	if h.chrome != nil {
		reader = h.chrome
	}
	return h.matchFocusedOrigin(ctx, p, expectedOrigin, reader)
}

func (h *Host) matchFocusedOrigin(ctx context.Context, requested auth.Principal, expectedOrigin string, reader focusedOriginReader) (chrome.FocusedOriginMatch, error) {
	denied := chrome.FocusedOriginMatch{}
	p, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || requested.Namespace != p.Namespace || requested.ClientID != p.ClientID ||
		!chrome.OrdinaryWebsiteOrigin(expectedOrigin) || len(expectedOrigin) > 512 {
		return denied, auth.ErrUnauthorized
	}
	if _, err = h.authorize(ctx, p); err != nil {
		return denied, err
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, binding.SessionID) != nil {
		return denied, auth.ErrUnauthorized
	}
	// Only this closed comparison bypasses ordinary content-exposure admission.
	// Retain the normal client/session, origin policy and durable observe consent
	// checks. This consent lease grants no executor lease and cannot consume,
	// clear, or borrow any private credential authority.
	lease, err := h.authorizeConsentOperation(ctx, p, model.Surface{Kind: "web", Origin: expectedOrigin}, false, consent.Observe)
	if err != nil {
		return denied, err
	}
	defer lease.Release()
	if reader == nil {
		return chrome.FocusedOriginMatch{Reason: "noQualifiedChannel"}, lease.Context.Err()
	}
	out, err := reader.MatchFocusedOrigin(lease.Context, p, expectedOrigin)
	if err != nil {
		return denied, err
	}
	if err = lease.Context.Err(); err != nil {
		return denied, err
	}
	if h.Runtime.CheckSession(lease.Context, p, binding.SessionID) != nil {
		return denied, auth.ErrUnauthorized
	}
	return out, nil
}
