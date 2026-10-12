package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

type permissionDoctorFixture struct {
	body       json.RawMessage
	failure    error
	replyError *native.NativeError
	calls      int
}

func (f *permissionDoctorFixture) Call(_ context.Context, r native.Request) (native.Reply, error) {
	f.calls++
	if r.Method != "doctor" || r.Lease != nil || r.DeadlineRemainingMS != 3000 {
		return native.Reply{}, errors.New("unexpected permission request")
	}
	return native.Reply{Result: f.body, Error: f.replyError}, f.failure
}
func (*permissionDoctorFixture) Close() error { return nil }
func TestNativePermissionDoctorClosedFailureAndVerifiedStates(t *testing.T) {
	for _, mode := range []string{"granted", "denied", "mixed", "missingFields", "malformed", "noHelper", "unavailable", "cleanup", "wrappedCleanup", "joinedCleanup", "fakeCleanupText", "canceled", "remoteError"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "doctor-owner", []string{"consent:admin"})
			ctx := auth.WithPrincipal(context.Background(), p)
			human, _ := auth.WithNativeHuman(ctx)
			f := &permissionDoctorFixture{body: json.RawMessage(`{"axTrusted":true,"captureGranted":true,"listenGranted":true}`)}
			expected := []string{"granted", "granted", "granted"}
			code := ""
			switch mode {
			case "denied":
				f.body = json.RawMessage(`{"axTrusted":false,"captureGranted":false,"listenGranted":false}`)
				expected = []string{"denied", "denied", "denied"}
			case "mixed":
				f.body = json.RawMessage(`{"axTrusted":true,"captureGranted":false,"listenGranted":true}`)
				expected = []string{"granted", "denied", "granted"}
			case "missingFields":
				f.body = json.RawMessage(`{}`)
				code = "observationHelperReplyInvalid"
			case "malformed":
				f.body = json.RawMessage(`{"axTrusted":"private-canary"}`)
				code = "observationHelperReplyInvalid"
			case "noHelper":
				code = "observationHelperUnavailable"
			case "cleanup":
				f.failure = errors.New("console helper teardown unconfirmed")
				code = "observationHelperCleanupUnconfirmed"
			case "wrappedCleanup":
				f.failure = fmt.Errorf("private-canary: %w", errors.New("console helper teardown unconfirmed"))
				code = "observationHelperCleanupUnconfirmed"
			case "joinedCleanup":
				f.failure = errors.Join(context.DeadlineExceeded, errors.New("helper teardown exceeded one second"))
				code = "observationHelperCleanupUnconfirmed"
			case "fakeCleanupText":
				f.failure = errors.New("console helper teardown unconfirmed private-canary")
				code = "observationHelperUnavailable"
			case "canceled":
				f.failure = &native.TransportError{Cause: context.Canceled, DispatchState: "notDispatched"}
				code = "observationHelperCheckInterrupted"
			case "remoteError":
				f.replyError = &native.NativeError{Code: "private-canary", Message: "private-canary"}
				code = "observationHelperUnavailable"
			case "unavailable":
				f.failure = errors.New("private-canary")
				code = "observationHelperUnavailable"
			}
			h := &Host{users: map[string]User{p.Namespace: {Subject: p.Subject}}, nativeClient: f}
			if mode == "noHelper" {
				h.nativeClient = nil
			}
			if _, err := h.NativeInformation(ctx, "helperPermissionDoctor", nil); !errors.Is(err, auth.ErrUnauthorized) || f.calls != 0 {
				t.Fatal("agent obtained native doctor route")
			}
			result, err := h.NativeInformation(human, "helperPermissionDoctor", nil)
			if err != nil {
				t.Fatal(err)
			}
			rows := result.([]map[string]any)
			if len(rows) != 3 {
				t.Fatal("permission rows missing")
			}
			if code != "" {
				expected = []string{"unknown", "unknown", "unknown"}
			}
			for i, row := range rows {
				if row["state"] != expected[i] {
					t.Fatal("unverified or changed permission state", row["state"])
				}
				if code != "" && !strings.HasPrefix(row["detail"].(string), code+":") {
					t.Fatal("closed actionable diagnostic missing")
				}
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "private-canary") {
				t.Fatal("private helper error leaked")
			}
			if mode != "noHelper" && f.calls != 1 {
				t.Fatal("doctor replayed")
			}
		})
	}
}
