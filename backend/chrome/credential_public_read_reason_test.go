package chrome

import (
	"testing"
)

func TestCredentialPublicReadV2KeepsTargetProtectionDistinctFromStaleBinding(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{{"private", "scopeTargetProtected"}, {"wrongDocument", "scopeChanged"}} {
		t.Run(tc.mode, func(t *testing.T) {
			f, c, ctx := publicReadFixture(t)
			f.g.broker.mu.Lock()
			c.credentialPublicReadVersion = 2
			f.g.broker.mu.Unlock()
			f.publicReadMode.Store(tc.mode)
			verified, e := f.g.WithVerifiedCredentialPublicRead(ctx, f.p, readTarget().Surface)
			if verified != nil || CredentialProtectionFailureReason(e) != tc.want {
				t.Fatalf("wrong closed reason: %s", CredentialProtectionFailureReason(e))
			}
			if f.mutations.Load() != 0 {
				t.Fatal("read proof dispatched input")
			}
		})
	}
}
