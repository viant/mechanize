package host

import (
	"fmt"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
)

func TestWindowFrameFailureCodeKeepsExistingRecipientRejections(t *testing.T) {
	for _, code := range []string{"windowKeyboardUnqualified", "sessionUnqualified", "foregroundRefreshUnavailable"} {
		cause := fmt.Errorf("PRIVATE_CANARY: %w", &native.NativeError{Code: code, Message: "PRIVATE_CANARY"})
		if got := windowFrameFailureCode(cause); got != code {
			t.Fatalf("frame cause flattened: got=%q want=%q", got, code)
		}
	}
	if got := windowFrameFailureCode(&native.NativeError{Code: "PRIVATE_CANARY", Message: "PRIVATE_CANARY"}); got != "unavailable" {
		t.Fatal("unknown native code entered frame diagnostic")
	}
}
