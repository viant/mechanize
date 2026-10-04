package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

// holdReconciliationFence acquires no input helper and sends no input. Acquiring
// the existing supervisor fence proves old helper death/cleanup even after a
// broker restart, and excludes another broker during evidence and commit.
func (m *NativeControlManager) holdReconciliationFence(ctx context.Context, p auth.Principal) (func() error, error) {
	var scope session.Scope
	var err error
	if m.options.EnrolledScope != nil {
		scope, err = m.options.EnrolledScope(ctx, p)
	} else {
		scope.AllowedBundles, err = m.options.Enrolled(ctx, p)
	}
	if err != nil {
		return nil, err
	}
	actual, scope, err := m.actor(ctx, p, scope)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.closed || m.options.Owner.Err() != nil {
		m.mu.Unlock()
		return nil, errors.New("native control manager closed")
	}
	if m.held != nil && m.held.principal.Namespace != p.Namespace {
		m.mu.Unlock()
		return nil, auth.ErrUnauthorized
	}
	if _, err = m.closeLocked(ctx); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if _, err = m.supervisor.Acquire(ctx, actual, scope); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	var once sync.Once
	var cleanupErr error
	return func() error {
		once.Do(func() {
			bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			report, err := m.supervisor.Close(bounded)
			cleanupErr = err
			if !report.InputInhibited || !report.HelperStopped || !report.FenceReleased || report.UnknownInputs {
				cleanupErr = errors.Join(cleanupErr, ErrNativeControlCleanupUnknown)
			}
			m.mu.Unlock()
		})
		return cleanupErr
	}, nil
}

func (h *Host) effectReconciliationGuard(ctx context.Context, p auth.Principal, runID string) (func() error, error) {
	if h.Runtime == nil || h.nativeControl == nil {
		return nil, errors.New("qualified reconciliation guard unavailable")
	}
	releaseRuntime, err := h.Runtime.ReconciliationGuard(ctx, p, runID)
	if err != nil {
		return nil, err
	}
	releaseNative, err := h.nativeControl.holdReconciliationFence(ctx, p)
	if err != nil {
		releaseRuntime()
		return nil, err
	}
	return func() error { err := releaseNative(); releaseRuntime(); return err }, nil
}
