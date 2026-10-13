package host

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

type lateUnknownNativeHelper struct{ *controlFixture }

func (f *lateUnknownNativeHelper) Call(context.Context, native.Request) (native.Reply, error) {
	f.calls++
	return native.Reply{HelperEpoch: "fixture", Receipt: &native.Receipt{DispatchState: "unknown"}}, &native.NativeError{Code: "textFocusChanged", DispatchState: "unknown"}
}

func TestNativeControlLateStoppedReleaseProofRecoversSameManagerWithoutReplay(t *testing.T) {
	for _, mode := range []string{"released", "alive", "heldInput", "deathChanged", "noProof", "wrongActor", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newControlFixture(t)
			f.manager.options.SessionText = true
			helper := &lateUnknownNativeHelper{f}
			f.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) {
				f.starts++
				f.mu.Lock()
				f.alive = true
				f.mu.Unlock()
				return helper, nil
			}
			var proofs atomic.Int32
			if mode != "noProof" {
				f.manager.options.ReleasedInputProof = func(ctx context.Context, _ auth.Principal) error {
					proofs.Add(1)
					if mode == "deadline" {
						<-ctx.Done()
						return ctx.Err()
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if mode == "heldInput" {
						return errors.New("input remains held")
					}
					if mode == "deathChanged" {
						f.mu.Lock()
						f.alive = true
						f.mu.Unlock()
					}
					return nil
				}
			}
			admission := f.admit(t)
			original, err := f.caller().Call(f.ctx, native.Request{Method: "windows.typeText", Lease: &native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}, Params: []byte(`{"expectedApp":"com.fixture.app"}`)})
			if err == nil || original.Receipt == nil || original.Receipt.DispatchState != "unknown" {
				t.Fatal("missing original unknown", err)
			}
			f.stopErr = errors.New("release ack lost")
			f.unknown = true
			if _, err = f.manager.Revoke(f.ctx, f.principal); err == nil {
				t.Fatal("initial cleanup accepted")
			}
			f.mu.Lock()
			f.alive = mode == "alive"
			f.mu.Unlock()
			actor, callCtx := f.principal, f.ctx
			if mode == "wrongActor" {
				actor, _ = auth.NewPrincipal("issuer", "tenant", "other", []string{"desktop:control"})
				callCtx = auth.WithPrincipal(context.Background(), actor)
			}
			if mode == "deadline" {
				var cancel context.CancelFunc
				callCtx, cancel = context.WithTimeout(callCtx, 20*time.Millisecond)
				defer cancel()
			}
			started := time.Now()
			next, err := f.manager.Admit(callCtx, actor, f.enrolled)
			if mode == "deadline" && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second) {
				t.Fatal("late proof escaped caller deadline", err)
			}
			if mode == "released" {
				if err != nil || next.Epoch <= admission.Epoch || proofs.Load() != 1 || f.starts != 2 {
					t.Fatalf("late proof did not recover: epoch=%d proofs=%d starts=%d err=%v", next.Epoch, proofs.Load(), f.starts, err)
				}
			} else if err == nil || f.starts != 1 {
				t.Fatal("unconfirmed physical cleanup readmitted", err)
			}
			if original.Receipt.DispatchState != "unknown" || f.calls != 1 {
				t.Fatal("original receipt changed or input replayed")
			}
			if (mode == "alive" || mode == "noProof" || mode == "wrongActor") && proofs.Load() != 0 {
				t.Fatal("proof queried without exact helper death")
			}
			// Permit fixture-owned cleanup after the production barrier assertions.
			f.stopErr = nil
			f.unknown = false
		})
	}
}
