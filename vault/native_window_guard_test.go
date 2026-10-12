package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/darwin"
)

func TestNativeWindowGuardSurvivingEntryBlocksAfterRestart(t *testing.T) {
	state := nativeWindowState{consoles: 1, protected: true}
	probe := func(context.Context, string) (nativeWindowState, error) { return state, nil }
	// No in-memory entry lease is restored. Independent native window state
	// nevertheless prevents exposure and refuses a false successful recovery.
	gate, controller, err := newNativeWindowProtection(probe)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := auth.FromContext(fixtureContext("window-guard", true))
	p.ClientID = "signed-console"
	human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if release, err := gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		if release != nil {
			release()
		}
		t.Fatal("restart exposed surviving window")
	}
	if err = controller.Recover(human); !errors.Is(err, ErrEntryCleanup) {
		t.Fatal("restart recovery ignored surviving window")
	}
	state.protected = false
	if err = controller.Recover(human); err != nil {
		t.Fatal(err)
	}
	release, err := gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestNativeWindowGuardUnavailableStateCannotAdmitExposureOrPreparation(t *testing.T) {
	var unavailable = true
	probe := func(context.Context, string) (nativeWindowState, error) {
		if unavailable {
			return nativeWindowState{}, errors.New("private-probe-error-canary")
		}
		return nativeWindowState{}, nil
	}
	gate, controller, _ := newNativeWindowProtection(probe)
	if _, err := gate.AcquireExposure(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable probe admitted exposure")
	}
	p, _ := auth.FromContext(fixtureContext("window-guard", true))
	p.ClientID = "signed-console"
	human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if id, err := controller.Begin(human, fixtureBinding().Target); id != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable console admitted entry")
	}
	if _, err := gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("unverified preparation cleanup dropped protection")
	}
	unavailable = false
	if err := controller.Recover(human); err != nil {
		t.Fatal(err)
	}
	// Zero verified consoles is safe for exposure, but cannot accept new entry.
	if _, err := controller.Begin(human, fixtureBinding().Target); !errors.Is(err, ErrUnavailable) {
		t.Fatal("entry without a verified console")
	}
	release, err := gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestNativeWindowConfirmationRequiresExactEmptyWindowBeforeInput(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		state := nativeWindowState{consoles: 1}
		probe := func(context.Context, string) (nativeWindowState, error) { return state, nil }
		gate, controller, _ := newNativeWindowProtection(probe)
		p, _ := auth.FromContext(fixtureContext("window-confirmation", true))
		p.ClientID = "signed-console"
		human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
		id, err := controller.Begin(human, fixtureBinding().Target)
		if err != nil {
			t.Fatal(err)
		}
		if err = gate.WithEntry(human, fixtureBinding().Target, func() error { t.Fatal("input before empty-window confirmation"); return nil }); err == nil {
			t.Fatal("unconfirmed input admitted")
		}
		state = nativeWindowState{consoles: 1, protected: true, entries: 1, matched: 1}
		if invalid {
			state.matched = 0
		}
		err = controller.Confirm(human, id)
		if invalid {
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("wrong window confirmed")
			}
			state.matched = 1
			if err = controller.Confirm(human, id); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed confirmation replayed after retirement")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if err = gate.WithEntry(human, fixtureBinding().Target, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		// A fresh broker gate has no old lease but sees the already-created marked
		// window. Therefore it cannot expose fields mounted after confirmation.
		restarted, _, _ := newNativeWindowProtection(probe)
		if release, err := restarted.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
			if release != nil {
				release()
			}
			t.Fatal("restart exposed confirmed window")
		}
		if err = controller.Close(human, id); !errors.Is(err, ErrEntryCleanup) {
			t.Fatal("visible window cleanup accepted")
		}
		state = nativeWindowState{consoles: 1}
		if err = controller.Recover(human); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHelperOwnedGuardRetainsPrivacyAndFailsClosedWithoutFallback(t *testing.T) {
	state := darwin.PrivateConsoleWindows{Consoles: 1, Entries: 1, Matched: 1}
	unavailable := false
	calls := 0
	probe := helperWindowProbe("exact-console-pin", func(ctx context.Context, pin, id string) (darwin.PrivateConsoleWindows, error) {
		calls++
		if pin != "exact-console-pin" {
			t.Fatal("caller substituted pin")
		}
		if unavailable {
			return darwin.PrivateConsoleWindows{}, darwin.ErrPrivateProof
		}
		return state, nil
	})
	gate, entry, e := newNativeWindowProtection(probe)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = gate.AcquireExposure(); !errors.Is(e, ErrEntryProtected) {
		t.Fatal("open window exposed")
	}
	state.Entries = 0
	state.Matched = 0
	release, e := gate.AcquireExposure()
	if e != nil {
		t.Fatal(e)
	}
	release()
	unavailable = true
	if _, e = gate.AcquireExposure(); !errors.Is(e, ErrUnavailable) {
		t.Fatal("helper error bypassed privacy")
	}
	human := fixtureContext("window-helper", true)
	p, _ := auth.FromContext(human)
	p.ClientID = "console"
	human, _ = auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if e = entry.Recover(human); !errors.Is(e, ErrEntryCleanup) {
		t.Fatal("unavailable helper released cleanup")
	}
	if calls != 4 {
		t.Fatalf("unexpected retry/fallback: %d", calls)
	}
}
