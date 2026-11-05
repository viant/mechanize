package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type pasteFixture struct {
	mode                                   string
	checks, probes, stages, pastes, clears int
	clipboard, field, borrowed             []byte
	token                                  string
	cancel                                 context.CancelFunc
	gate                                   *ExposureGate
	t                                      *testing.T
}

func (f *pasteFixture) CheckEmpty(context.Context, Binding) error {
	f.checks++
	if f.mode == "unmasked" || f.mode == "changedTarget" && f.stages > 0 || len(f.field) > 0 {
		return ErrUnavailable
	}
	return nil
}
func (f *pasteFixture) SetProbe(context.Context, Binding) error {
	f.probes++
	if f.stages != 0 {
		f.t.Fatal("secret staged before probe")
	}
	if f.mode == "probeUnknown" {
		f.field = []byte("x")
		return errors.New("PRIVATE-CANARY")
	}
	f.field = []byte(PasswordPasteProbeCharacter)
	return nil
}
func (f *pasteFixture) CheckProbe(context.Context, Binding) error {
	if f.mode == "probeMismatch" || !bytes.Equal(f.field, []byte(PasswordPasteProbeCharacter)) {
		return ErrUnavailable
	}
	return nil
}
func (f *pasteFixture) RemoveProbe(context.Context, Binding) error {
	if f.mode == "removeUnknown" {
		return ErrUnavailable
	}
	clear(f.field)
	f.field = nil
	return nil
}
func (f *pasteFixture) Stage(ctx context.Context, token string, p []byte, deadline time.Time) error {
	f.stages++
	f.token = token
	f.borrowed = p
	f.clipboard = append([]byte(nil), p...)
	if !bytes.Equal(p, []byte("password-canary")) {
		f.t.Fatal("incorrect credential field")
	}
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(5*time.Second)) {
		f.t.Fatal("unbounded clipboard lifetime")
	}
	if _, e := f.gate.AcquireExposureContext(ctx); e == nil {
		f.t.Fatal("private paste allowed public observation")
	}
	if f.mode == "stagePanic" {
		panic("PRIVATE-CANARY")
	}
	if f.mode == "stageError" {
		return errors.New("PRIVATE-CANARY")
	}
	if f.mode == "cancel" {
		f.cancel()
	}
	return nil
}
func (f *pasteFixture) VerifyOwnership(context.Context, string) error {
	if f.mode == "replaced" {
		f.clipboard = []byte("new-user-item")
		return ErrUnavailable
	}
	return nil
}
func (f *pasteFixture) PasteOnce(context.Context, Binding) error {
	f.pastes++
	if f.mode == "pasteUnknown" {
		return errors.New("PRIVATE-CANARY")
	}
	f.field = append([]byte(nil), f.clipboard...)
	return nil
}
func (f *pasteFixture) Verify(_ context.Context, _ Binding, p []byte) error {
	if f.mode == "verifyError" || !bytes.Equal(f.field, p) {
		return ErrUnavailable
	}
	return nil
}
func (f *pasteFixture) Clear(ctx context.Context, token string) error {
	f.clears++
	if ctx.Err() != nil || token != f.token {
		f.t.Fatal("cleanup lost independent deadline/ownership")
	}
	if f.mode == "cleanupError" {
		return errors.New("PRIVATE-CANARY")
	}
	if f.mode != "replaced" {
		clear(f.clipboard)
		f.clipboard = nil
	}
	return nil
}

func TestPrivatePasswordPasteFromEncryptedRecordAndFailureCleanup(t *testing.T) {
	for _, mode := range []string{"ok", "unmasked", "probeUnknown", "probeMismatch", "removeUnknown", "changedTarget", "stagePanic", "stageError", "cancel", "replaced", "pasteUnknown", "verifyError", "cleanupError"} {
		t.Run(mode, func(t *testing.T) {
			_, _, ctx, b, _, d := recordDeliveryFixture(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			g := deliveryGate(t)
			lease, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			m, e := NewRecordDeliveryManager(d, func(_ context.Context, actual Binding) (Binding, error) { return actual, nil })
			if e != nil {
				t.Fatal(e)
			}
			f := &pasteFixture{mode: mode, cancel: cancel, gate: g, t: t}
			out := PasteRecordPassword(ctx, d, m, lease, b, f, f)
			if out.Verified != (mode == "ok") {
				t.Fatalf("unexpected verification %+v", out)
			}
			if mode == "unmasked" && (f.probes != 0 || f.stages != 0) {
				t.Fatal("unmasked field received probe/secret")
			}
			if (mode == "probeUnknown" || mode == "probeMismatch" || mode == "removeUnknown") && (f.stages != 0 || f.pastes != 0 || out.DispatchState != "unknown") {
				t.Fatal("uncertain probe proceeded")
			}
			if f.stages > 0 && f.clears != 1 {
				t.Fatal("staged clipboard was not cleaned exactly once")
			}
			if mode == "replaced" && !bytes.Equal(f.clipboard, []byte("new-user-item")) {
				t.Fatal("new clipboard was erased")
			}
			if f.stages > 0 && mode != "cleanupError" && mode != "replaced" && len(f.clipboard) != 0 {
				t.Fatal("credential remained on clipboard")
			}
			for _, v := range f.borrowed {
				if v != 0 {
					t.Fatal("record buffer not erased")
				}
			}
			if mode == "cleanupError" && (out.CleanupConfirmed || out.Verified || out.Reason != "clipboardCleanupUnconfirmed") {
				t.Fatal("cleanup failure claimed success")
			}
			wire, _ := json.Marshal(out)
			if strings.Contains(string(wire), "CANARY") || strings.Contains(string(wire), "password-canary") {
				t.Fatal("private value/error leaked")
			}
			before := f.probes + f.stages + f.pastes
			PasteRecordPassword(ctx, d, m, lease, b, f, f)
			if before != f.probes+f.stages+f.pastes {
				t.Fatal("one-shot attempt replayed")
			}
		})
	}
}
