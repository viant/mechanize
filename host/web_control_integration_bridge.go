//go:build mechanize_integration

package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

// WebControlProviderForIntegration exposes the real production admission and
// retirement implementation only to the tagged socket integration test build.
func WebControlProviderForIntegration(gateway *chrome.Gateway, record func(context.Context, auth.Principal) error) *WebControlOptions {
	return newProductionWebControlProvider(gateway, record)
}
