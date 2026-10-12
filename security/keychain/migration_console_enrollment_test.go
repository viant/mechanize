package keychain

import (
	"context"
	"errors"
	"testing"
)

func TestUpdatedConsoleEnrollmentIsOneShotAndRecoveryNeverCreates(t *testing.T) {
	for _, mode := range []string{"success", "failure", "authority", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			gate := &migrationConsoleEnrollment{}
			ctx := migrationFixtureContext(t, true)
			writes := 0
			verify := func(context.Context) error {
				if mode == "authority" {
					return errMigrationUnavailable
				}
				return nil
			}
			enroll := func(context.Context) error {
				writes++
				if mode == "failure" {
					return errors.New("synthetic unknown")
				}
				return nil
			}
			result := gate.ensure(ctx, mode != "recovery", verify, enroll)
			if mode == "failure" && result != errMigrationUnknown {
				t.Fatal("unknown enrollment not retained")
			}
			if (mode == "success" || mode == "recovery") && result != nil {
				t.Fatal(result)
			}
			_ = gate.ensure(ctx, mode != "recovery", verify, enroll)
			expected := 1
			if mode == "authority" || mode == "recovery" {
				expected = 0
			}
			if writes != expected {
				t.Fatal("enrollment repeated or bypassed authorization")
			}
		})
	}
	for _, raw := range []string{`{"enrolled":true,"code":"enrollmentAdded","credential":"synthetic"}`, `{"enrolled":false,"code":"enrollmentAdded"}`, `{"enrolled":true,"code":"existingEnrollment"}`, `{"enrolled":true,"code":"enrollmentAdded"}{}`} {
		if migrationEnrollmentSucceeded([]byte(raw)) {
			t.Fatal("unclosed enrollment response accepted")
		}
	}
	if !migrationEnrollmentSucceeded([]byte(`{"code":"enrollmentAdded","enrolled":true}`)) {
		t.Fatal("closed native receipt rejected")
	}
}
func TestUpdatedConsoleCredentialStaysPrivateAndIsCleared(t *testing.T) {
	authority, _, client, ctx := migrationAuthorityFixture(t)
	sendMigrationCredential(t, client)
	var retained []byte
	if err := authority.withEnrollmentCredential(ctx, func(value []byte) error {
		retained = value
		if len(value) == 0 {
			return errMigrationUnavailable
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatal("temporary credential not cleared")
		}
	}
	authority.close()
	called := false
	if authority.withEnrollmentCredential(ctx, func([]byte) error { called = true; return nil }) == nil || called {
		t.Fatal("closed authority dispatched credential")
	}
}
