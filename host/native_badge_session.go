package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"time"
)

// Presentation release has no lease, process-control or business-effect meaning.
// Serialize it after actual helper work; it must also work for an inhibited
// input owner without clearing that inhibition or entering a new input session.
func (m *NativeControlManager) ReleasePresentationSession(ctx context.Context, p auth.Principal, id string) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || id == "" {
		return auth.ErrUnauthorized
	}
	for !m.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	held := m.held
	if m.closed || held == nil {
		return nil
	}
	if held.principal.Namespace != p.Namespace {
		return auth.ErrUnauthorized
	}
	// A temporary presentation-only Gateway uses the existing signed helper
	// connection. It is never closed here and cannot install/revoke any lease.
	gateway, err := native.NewGateway(held.helper, native.GatewayOptions{AllApplications: held.scope.AllApplications, AllowedBundles: held.scope.AllowedBundles})
	if err != nil {
		return err
	}
	_, err = gateway.ReleaseControlBadgeSession(ctx, p, id)
	return err
}
