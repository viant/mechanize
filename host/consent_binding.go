package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

type ConsentBinding = auth.ConsentBinding

func WithConsentBinding(ctx context.Context, b ConsentBinding) context.Context {
	return auth.WithConsentBinding(ctx, b)
}
func ConsentBindingFromContext(ctx context.Context) (ConsentBinding, bool) {
	return auth.ConsentBindingFromContext(ctx)
}

// ConsentScope resolves only exact surface facts. Window selectors require
// backend resolution to a stable window ID; aliases/titles never confer scope.
func ConsentScope(surface model.Surface) (consent.Scope, error) {
	var s consent.Scope
	if err := surface.ValidateProcessIdentity(); err != nil {
		return s, err
	}
	switch surface.Kind {
	case "desktop":
		// Desktop recording follows app switches. Reject mixed target facts so
		// an application/origin request cannot silently broaden its scope.
		if surface.BundleID != "" || surface.Origin != "" || surface.Title != "" || surface.TabID != "" {
			return s, errors.New("desktop consent requires an unqualified desktop surface")
		}
		s = consent.Scope{Kind: "desktop"}
	case "native":
		if surface.Origin != "" || surface.TabID != "" || surface.Title != "" {
			return s, errors.New("native consent cannot include web target facts")
		}
		s = consent.Scope{Kind: "application", BundleID: surface.BundleID}
	case "web":
		if surface.BundleID != "" {
			return s, errors.New("web consent cannot include native target facts")
		}
		s = consent.Scope{Kind: "origin", Origin: surface.Origin}
	default:
		return s, errors.New("unsupported consent surface")
	}
	return s, s.Validate()
}
