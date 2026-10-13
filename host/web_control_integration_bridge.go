//go:build mechanize_integration

package host

import (
	"github.com/viant/mechanize/backend/chrome"
)

// WebControlProviderForIntegration exposes the real production admission and
// retirement implementation only to the tagged socket integration test build.
func WebControlProviderForIntegration(gateway *chrome.Gateway) *WebControlOptions {
	return newProductionWebControlProvider(gateway)
}
