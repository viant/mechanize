package vault

import (
	"context"
	"errors"
	"testing"
)

func TestNativeExposureKeepsBrowserDeliveryAndBlocksVaultEntry(t *testing.T) {
	ctx := deliveryContext()
	binding := fixtureBinding()
	gate := deliveryGate(t)
	delivery, err := gate.BeginDelivery(ctx, binding, func(context.Context) error { return nil }, func(context.Context) error { return ErrEntryCleanup })
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []bool{false, true} {
		if retired {
			delivery.Retire()
		}
		release, err := gate.AcquireNativeExposureContext(ctx)
		if err != nil {
			t.Fatal("browser protection globally blocked native exposure", err)
		}
		if _, err = gate.AcquireExposureContext(ctx); !errors.Is(err, ErrDeliveryProtected) {
			t.Fatal("native admission cleared browser DOM protection")
		}
		if _, err = gate.Begin(fixtureContext("entry", true), binding.Target, func(context.Context) error { return nil }); !errors.Is(err, ErrBusy) {
			t.Fatal("secure entry overlapped native exposure")
		}
		release()
		release()
		gate.mu.Lock()
		readers, held := gate.readers, gate.delivery
		gate.mu.Unlock()
		if readers != 0 || held != delivery {
			t.Fatal("native permit altered delivery lifecycle or leaked reservation")
		}
	}
}
func TestNativeExposureRetainsIndependentSecureWindowGuard(t *testing.T) {
	ctx := deliveryContext()
	secure := false
	probes := 0
	gate, _ := NewGuardedExposureGate(func(context.Context) error {
		probes++
		if secure {
			return ErrEntryProtected
		}
		return nil
	})
	_, err := gate.BeginDelivery(ctx, fixtureBinding(), func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	secure = true
	if release, err := gate.AcquireNativeExposureContext(ctx); release != nil || !errors.Is(err, ErrEntryProtected) {
		t.Fatal("visible native Vault window exposed", err)
	}
	secure = false
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if release, err := gate.AcquireNativeExposureContext(cancelled); release != nil || err == nil {
		t.Fatal("cancelled native exposure admitted")
	}
	release, err := gate.AcquireNativeExposureContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if probes < 3 {
		t.Fatal("native-window checks omitted")
	}
	entryGate := deliveryGate(t)
	entry, err := entryGate.Begin(fixtureContext("entry", true), fixtureBinding().Target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Retire()
	if release, err := entryGate.AcquireNativeExposureContext(ctx); release != nil || !errors.Is(err, ErrEntryProtected) {
		t.Fatal("active secure entry bypassed", err)
	}
}
