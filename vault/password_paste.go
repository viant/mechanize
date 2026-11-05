package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// PasswordPasteTarget is a trusted private host adapter, never agent-supplied
// assertions. CheckEmpty must pin the focused, editable, masked password control
// to the approved recipient. SetProbe writes only PasswordPasteProbeCharacter;
// CheckProbe verifies that exact value AND masked/focused recipient identity.
// RemoveProbe removes only that verified probe from the same control. These
// must not touch an initially nonempty or unmasked field, submit, or follow focus.
// Verify receives bytes only inside the private process and returns no value.
// PasteOnce must recheck that same secure recipient at actual input dispatch;
// a generic global Command+V without a held target/physical-input fence is invalid.
type PasswordPasteTarget interface {
	CheckEmpty(context.Context, Binding) error
	SetProbe(context.Context, Binding) error
	CheckProbe(context.Context, Binding) error
	RemoveProbe(context.Context, Binding) error
	PasteOnce(context.Context, Binding) error
	Verify(context.Context, Binding, []byte) error
}

// The probe is public synthetic input, never a character from the password.
const PasswordPasteProbeCharacter = "x"

// PasswordPasteClipboard has intentionally no read method. Stage must retain
// token/revision ownership BEFORE writing, install expiration cleanup, and mark
// the item transient/concealed where supported. Clear must check ownership and
// preserve an observed newer clipboard item. Neither operation may log bytes.
type PasswordPasteClipboard interface {
	Stage(context.Context, string, []byte, time.Time) error
	VerifyOwnership(context.Context, string) error
	Clear(context.Context, string) error
}

// PasswordPasteResult contains finite metadata only. Unknown probe/paste effects
// are never replayed. CleanupConfirmed concerns our clipboard item, not whether
// another local process has copied it. The host must retain exposure protection
// until recipient and clipboard cleanup are independently reconciled.
type PasswordPasteResult struct {
	DispatchState    string `json:"dispatchState"`
	Verified         bool   `json:"verified"`
	CleanupConfirmed bool   `json:"cleanupConfirmed"`
	Reason           string `json:"reason"`
}

// PasteRecordPassword composes existing revision-bound Vault custody and the
// one-shot exposure lease. It grants no app/origin authority, does not register
// a public plaintext API, and never submits the destination form. Production
// enrollment requires a qualified recipient adapter and clipboard watchdog.
func PasteRecordPassword(ctx context.Context, delivery *RecordDelivery, manager *Manager, lease *DeliveryLease, binding Binding, target PasswordPasteTarget, clipboard PasswordPasteClipboard) (out PasswordPasteResult) {
	out = PasswordPasteResult{DispatchState: "notDispatched", Reason: "unavailable"}
	if delivery == nil || manager == nil || lease == nil || target == nil || clipboard == nil || delivery.Verify(ctx, binding) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fresh := func() error {
		if lease.Verify(ctx, binding) != nil || delivery.Verify(ctx, binding) != nil || manager.fresh(ctx, binding) != nil {
			return ErrUnavailable
		}
		return target.CheckEmpty(ctx, binding)
	}
	_ = lease.WithDelivery(ctx, binding, func() error {
		if deliveryCall(fresh) != nil {
			out.Reason = "secureTargetUnavailable"
			return ErrUnavailable
		}
		// No credential is consumed before the synthetic probe is removed.
		out.DispatchState = "unknown"
		out.Reason = "probeUnconfirmed"
		if deliveryCall(func() error { return target.SetProbe(ctx, binding) }) != nil {
			return ErrUnavailable
		}
		if lease.Verify(ctx, binding) != nil || delivery.Verify(ctx, binding) != nil || deliveryCall(func() error { return target.CheckProbe(ctx, binding) }) != nil {
			return ErrUnavailable
		}
		if deliveryCall(func() error { return target.RemoveProbe(ctx, binding) }) != nil {
			return ErrUnavailable
		}
		if deliveryCall(fresh) != nil {
			out.Reason = "secureTargetChanged"
			return ErrUnavailable
		}
		out.DispatchState = "notDispatched"
		out.Reason = "credentialUnavailable"
		return delivery.UseBinding(ctx, binding, func(ref Reference, revision string) error {
			return manager.ConsumeRevision(ctx, binding, ref, revision, func(credentials Credentials) error {
				return credentials.WithBytes(func(_, password []byte) error {
					if deliveryCall(fresh) != nil {
						out.Reason = "secureTargetChanged"
						return ErrUnavailable
					}
					var nonce [32]byte
					if _, err := rand.Read(nonce[:]); err != nil {
						return ErrUnavailable
					}
					token := hex.EncodeToString(nonce[:])
					// Cleanup must run even when Stage partially writes, panics,
					// cancellation fires, or paste/verification fails.
					defer func() {
						cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
						defer stop()
						out.CleanupConfirmed = deliveryCall(func() error { return clipboard.Clear(cleanup, token) }) == nil && cleanup.Err() == nil
						if !out.CleanupConfirmed {
							out.Verified = false
							out.Reason = "clipboardCleanupUnconfirmed"
						}
					}()
					deadline, _ := ctx.Deadline()
					out.Reason = "clipboardUnavailable"
					if deliveryCall(func() error { return clipboard.Stage(ctx, token, password, deadline) }) != nil {
						return ErrUnavailable
					}
					if deliveryCall(fresh) != nil {
						out.Reason = "secureTargetChanged"
						return ErrUnavailable
					}
					if deliveryCall(func() error { return clipboard.VerifyOwnership(ctx, token) }) != nil {
						out.Reason = "clipboardChanged"
						return ErrUnavailable
					}
					out.DispatchState = "unknown"
					out.Reason = "pasteUnconfirmed"
					if deliveryCall(func() error { return target.PasteOnce(ctx, binding) }) != nil {
						return ErrUnavailable
					}
					out.DispatchState = "dispatched"
					out.Reason = "verificationUnavailable"
					if lease.Verify(ctx, binding) != nil || delivery.Verify(ctx, binding) != nil || deliveryCall(func() error { return target.Verify(ctx, binding, password) }) != nil || ctx.Err() != nil {
						return ErrUnavailable
					}
					out.Verified = true
					out.Reason = "none"
					return nil
				})
			})
		})
	})
	return
}
