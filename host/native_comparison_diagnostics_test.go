package host

import (
	"errors"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/model"
)

func TestNativeComparisonDiagnosticsRemainReadOnlyAndRedacted(t *testing.T) {
	for _, code := range []string{"valueComparisonDenied", "valueComparisonUnavailable"} {
		for _, dispatch := range []string{"notDispatched", "unknown", "dispatched"} {
			original := &native.NativeError{Code: code, Stage: "native", DispatchState: dispatch, Message: "PRIVATE_FIELD", RetryableRead: true}
			bridged := nativePredicateError(original)
			var diagnostic *model.MechanizeError
			found := errors.As(bridged, &diagnostic)
			if dispatch != "notDispatched" {
				if found {
					t.Fatal("uncertain effect became a read diagnostic")
				}
				continue
			}
			if !found || diagnostic.Code != code || diagnostic.Message != "" || diagnostic.RetryableRead || diagnostic.DispatchState != "notDispatched" {
				t.Fatal("comparison diagnostic leaked text or gained retry authority")
			}
		}
	}
}
