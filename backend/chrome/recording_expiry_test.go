package chrome

import (
	"context"
	"testing"
	"time"
)

func TestRecordingConsentExpiryIsSeparateFromRPCDeadline(t *testing.T) {
	grant := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	expiry, err := recordingLeaseExpiry(WithRecordingLeaseExpiry(ctx, grant))
	if err != nil || expiry != grant.UnixMilli() {
		t.Fatalf("RPC budget changed capture grant: %d %v", expiry, err)
	}
	expiry, err = recordingLeaseExpiry(ctx)
	deadline, _ := ctx.Deadline()
	if err != nil || expiry != deadline.UnixMilli() {
		t.Fatal("fallback exceeded actual deadline")
	}
	if _, err = recordingLeaseExpiry(WithRecordingLeaseExpiry(ctx, time.Now().Add(-time.Second))); err == nil {
		t.Fatal("expired recording grant accepted")
	}
	expiry, err = recordingLeaseExpiry(WithRecordingLeaseExpiry(ctx, time.Now().Add(time.Hour)))
	if err != nil || expiry > time.Now().Add(30*time.Second).UnixMilli() {
		t.Fatal("renewal exceeded bounded transport lease")
	}
}
