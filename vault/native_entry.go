package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/viant/mechanize/auth"
)

// NativeEntryWindows is supplied by the trusted native host, never by MCP or
// the console's request payload. Prepare checks the enrolled console before an
// empty marked window is created. VerifyOpen checks that exact window before
// credential fields mount. VerifyClosed independently proves that window/fields
// are gone. These methods receive public routing only.
// The provider must also reconcile surviving windows at broker startup before
// exposure is admitted; constructing this controller alone is not that proof.
type NativeEntryWindows interface {
	Prepare(context.Context, string, Target) error
	VerifyOpen(context.Context, string) error
	VerifyClosed(context.Context, string) error
}

type NativeEntryController struct {
	gate    *ExposureGate
	windows NativeEntryWindows
	mu      sync.Mutex
	active  *nativeEntry
}
type nativeEntry struct {
	id        string
	namespace string
	clientID  string
	lease     *EntryLease
}

func NewNativeEntryController(gate *ExposureGate, windows NativeEntryWindows) (*NativeEntryController, error) {
	if gate == nil || windows == nil {
		return nil, ErrUnavailable
	}
	return &NativeEntryController{gate: gate, windows: windows}, nil
}
func (c *NativeEntryController) ExposureGate() *ExposureGate {
	if c == nil {
		return nil
	}
	return c.gate
}

// Begin admits protection before invoking the native window provider. A lost
// response or failed preparation never implicitly releases that protection.
func (c *NativeEntryController) Begin(ctx context.Context, target Target) (string, error) {
	if !auth.NativeHuman(ctx) {
		return "", auth.ErrUnauthorized
	}
	p, err := auth.FromContext(ctx)
	if err != nil || p.ClientID == "" {
		return "", auth.ErrUnauthorized
	}
	if target.Validate() != nil || ctx.Err() != nil || c == nil {
		return "", ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return "", ErrBusy
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return "", ErrUnavailable
	}
	id := hex.EncodeToString(entropy[:])
	lease, err := c.gate.Begin(ctx, target, func(cleanup context.Context) error { return c.windows.VerifyClosed(cleanup, id) })
	if err != nil {
		return "", err
	}
	c.active = &nativeEntry{id: id, namespace: p.Namespace, clientID: p.ClientID, lease: lease}
	lease.requireWindowConfirmation()
	if c.windows.Prepare(ctx, id, target) != nil {
		lease.Retire()
		if lease.Close(ctx) == nil {
			c.active = nil
		}
		return "", ErrUnavailable
	}
	return id, nil
}

// Confirm is called after the console creates an EMPTY marked window, before
// mounting fields. Its independent visibility check closes the restart gap
// between a Begin acknowledgement and window creation.
func (c *NativeEntryController) Confirm(ctx context.Context, id string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, err := c.owned(ctx, id)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || c.windows.VerifyOpen(ctx, id) != nil {
		entry.lease.Retire()
		return ErrUnavailable
	}
	return entry.lease.confirmWindow()
}

// BindOrigin is native-only metadata entered inside an already protected
// window. Alias stays opaque/immutable; binding cannot overlap a secret write.
func (c *NativeEntryController) BindOrigin(ctx context.Context, id, origin string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, err := c.owned(ctx, id)
	if err != nil {
		return err
	}
	if c.windows.VerifyOpen(ctx, id) != nil {
		entry.lease.Retire()
		return ErrUnavailable
	}
	return entry.lease.bindOrigin(ctx, origin)
}
func (c *NativeEntryController) owned(ctx context.Context, id string) (*nativeEntry, error) {
	if !auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	p, err := auth.FromContext(ctx)
	if err != nil || c.active == nil || id != c.active.id || p.Namespace != c.active.namespace || p.ClientID != c.active.clientID {
		return nil, auth.ErrUnauthorized
	}
	return c.active, nil
}
func (c *NativeEntryController) Authorize(ctx context.Context, id string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.owned(ctx, id)
	return err
}

// Retire is used on connection loss: it rejects new secret submission while
// retaining the exposure block. A later authenticated Close may verify cleanup.
func (c *NativeEntryController) Retire(ctx context.Context, id string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, err := c.owned(ctx, id)
	if err != nil {
		return err
	}
	entry.lease.Retire()
	return nil
}
func (c *NativeEntryController) Close(ctx context.Context, id string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, err := c.owned(ctx, id)
	if err != nil {
		return err
	}
	if err = entry.lease.Close(ctx); err != nil {
		return err
	}
	c.active = nil
	return nil
}

// Recover handles an unacknowledged Begin without requiring the lost ID. It is
// restricted to the same native console and still requires independent cleanup.
func (c *NativeEntryController) Recover(ctx context.Context) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if c.active == nil {
		if c.windows.VerifyClosed(ctx, "") != nil {
			return ErrEntryCleanup
		}
		return nil
	}
	entry, err := c.owned(ctx, c.active.id)
	if err != nil {
		return err
	}
	if err = entry.lease.Close(ctx); err != nil {
		return err
	}
	c.active = nil
	return nil
}
