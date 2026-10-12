package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
)

// The installer may create the new console's separate enrollment exactly once.
// It never edits the old approving console's item or the Vault master item.
// On recovery without an in-process placement, only independent readiness may
// resolve an already-created enrollment; this operation must not be replayed.
type migrationConsoleEnrollment struct {
	mu                  sync.Mutex
	attempted, complete bool
}

func (e *migrationConsoleEnrollment) ensure(ctx context.Context, placedHere bool, verify func(context.Context) error, enroll func(context.Context) error) error {
	if migrationContext(ctx) != nil || verify == nil || enroll == nil {
		return errMigrationUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if verify(ctx) != nil {
		return errMigrationUnavailable
	}
	if !placedHere {
		return nil
	} // recovery checks actual new-console readiness only
	if e.complete {
		return nil
	}
	if e.attempted {
		return errMigrationUnknown
	}
	e.attempted = true
	if enroll(ctx) != nil || verify(ctx) != nil {
		return errMigrationUnknown
	}
	e.complete = true
	return nil
}
func migrationEnrollmentSucceeded(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4096 {
		return false
	}
	var value struct {
		Enrolled bool   `json:"enrolled"`
		Code     string `json:"code"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(&value) == nil && d.Decode(new(any)) == io.EOF && value.Enrolled && value.Code == "enrollmentAdded"
}

// The already-authenticated local admin credential remains private to the
// signed native channel and the exact new console child. Never return it.
func (a *migrationNativeAuthority) withEnrollmentCredential(ctx context.Context, consume func([]byte) error) error {
	if a == nil || consume == nil {
		return errMigrationUnavailable
	}
	authorized, err := a.workerAuthority(ctx)
	if err != nil {
		return errMigrationUnavailable
	}
	a.mu.Lock()
	if a.closed || len(a.credential) == 0 || len(a.credential) > 32768 {
		a.mu.Unlock()
		return errMigrationUnavailable
	}
	credential := bytes.Clone(a.credential)
	a.mu.Unlock()
	defer clear(credential)
	if migrationContext(authorized) != nil {
		return errMigrationUnavailable
	}
	return consume(credential)
}
