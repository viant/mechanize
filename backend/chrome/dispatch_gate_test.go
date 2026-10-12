package chrome

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestDispatchGateFailurePreservesAbsenceAndOnlyClosedReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "dispatchGateExpired"},
		{context.Canceled, "dispatchGateCancelled"},
		{auth.ErrUnauthorized, "dispatchGateUnauthorized"},
		{browserError("staleAuthority", "Pinned document changed", "unknown"), "dispatchDocumentChanged"},
		{browserError("staleAuthority", "Connected channel evidence changed", "unknown"), "dispatchChannelChanged"},
		{errors.New("PRIVATE-CANARY"), "dispatchGateClosed"},
		{browserError("PRIVATE-CANARY", "PRIVATE-CANARY", "unknown"), "dispatchGateClosed"},
	} {
		got := dispatchGateFailure(tc.err)
		if got.Code != tc.code || got.DispatchState != "notDispatched" || strings.Contains(got.Message, "CANARY") {
			t.Fatal("gate lost absence or exposed provider details", got)
		}
	}
}
