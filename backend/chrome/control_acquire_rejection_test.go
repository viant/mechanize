package chrome

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestAcquireNotInstalledRequiresExactClosedAuthenticatedShape(t *testing.T) {
	command := Command{RequestID: "request", Action: "executor.acquire", Identity: Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 7, FrameID: 0, DocumentID: "doc", Generation: 1}, ControlLease: &Lease{ID: "fresh", Generation: 3}}
	for _, mode := range []string{"valid", "request", "document", "generation", "installed", "extra", "null", "duplicate", "errorState", "noLease"} {
		t.Run(mode, func(t *testing.T) {
			c := command
			i := command.Identity
			i.Generation = 2
			err := map[string]any{"code": "staleGeneration", "message": "fixed renderer rejection", "stage": "browser", "dispatchState": "notDispatched", "effectState": "none"}
			frame := map[string]any{"requestId": "request", "identity": i, "error": err}
			switch mode {
			case "request":
				frame["requestId"] = "foreign"
			case "document":
				i.DocumentID = "foreign"
				frame["identity"] = i
			case "generation":
				frame["identity"] = command.Identity
			case "installed":
				frame["controlLease"] = command.ControlLease
			case "extra":
				frame["value"] = "PRIVATE-CANARY"
			case "null":
				err["message"] = nil
			case "errorState":
				err["dispatchState"] = "unknown"
			case "noLease":
				c.ControlLease = nil
			}
			raw, _ := json.Marshal(frame)
			if mode == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"requestId":"request"}`)...)
			}
			if acquireNotInstalled(raw, c) != (mode == "valid") {
				t.Fatal("acquire rejection classification mismatch")
			}
		})
	}
}
func TestControlAdmissionKnownStaleGenerationRetriesMetadataOnly(t *testing.T) {
	f := newReadFixture(t)
	f.staleAcquires.Store(2)
	a, e := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if e != nil || !a.Created || !a.Confirmed || a.Authority.Document.Generation != 3 || f.acquireCalls.Load() != 3 || f.reads.Load() != 0 {
		t.Fatal("metadata retry failed", e)
	}
	if okay, e := f.g.RetireControl(f.ctx, f.p, a.Authority); e != nil || !okay {
		t.Fatal(e)
	}
}
func TestControlAdmissionBoundedKnownRejectionLeavesNoAuthorityOrInhibition(t *testing.T) {
	f := newReadFixture(t)
	f.staleAcquires.Store(20)
	a, e := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if e == nil || a.Created || a.Confirmed || a.Authority.Lease.ID != "" || f.acquireCalls.Load() != 3 {
		t.Fatal("retry limit not closed")
	}
	f.g.controlMu.Lock()
	clear := testFirstControl(f.g) == nil && !testAnyControlRetiring(f.g)
	f.g.controlMu.Unlock()
	if !clear {
		t.Fatal("known rejection retained false lease")
	}
	f.staleAcquires.Store(0)
	a, e = f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if e != nil || !a.Confirmed {
		t.Fatal("later fresh admission inhibited", e)
	}
}
func TestControlAdmissionLostAcquireReplyStillRetainsExactAuthority(t *testing.T) {
	f := newReadFixture(t)
	f.loseAcquire.Store(true)
	ctx, cancel := context.WithTimeout(f.ctx, 60*time.Millisecond)
	defer cancel()
	a, e := f.g.AdmitControlWithStatus(ctx, f.p, readTarget().Surface)
	if e == nil || !a.Created || a.Confirmed || f.acquireCalls.Load() != 1 {
		t.Fatal("lost acquisition retried or classified safe")
	}
	f.g.controlMu.Lock()
	held := testFirstControl(f.g) != nil && sameControl(*testFirstControl(f.g), a.Authority)
	f.g.controlMu.Unlock()
	if !held {
		t.Fatal("lost acquired lease discarded")
	}
}
func TestRejectedAcquisitionCannotClearConcurrentAuthorityOrReceipt(t *testing.T) {
	for _, mode := range []string{"otherLease", "retiring", "unknown", "usedLease", "fence"} {
		t.Run(mode, func(t *testing.T) {
			f := newReadFixture(t)
			a, e := f.g.AdmitControl(f.ctx, f.p, readTarget().Surface)
			if e != nil {
				t.Fatal(e)
			}
			c := f.g.controlChannel(a)
			f.g.broker.mu.Lock()
			conn := c.conn
			if mode == "unknown" {
				c.unknown["prior"] = true
			}
			if mode == "usedLease" {
				c.attempts["prior"] = Command{ControlLease: &a.Lease}
			}
			if mode == "fence" {
				c.epoch = "changed"
			}
			f.g.broker.mu.Unlock()
			f.g.controlMu.Lock()
			if mode == "otherLease" {
				copy := a
				copy.Lease.ID = "other"
				f.g.setControlLocked(copy)
			}
			if mode == "retiring" {
				testMarkControlRetiring(f.g)
			}
			f.g.controlMu.Unlock()
			if f.g.releaseRejectedAcquisition(f.ctx, f.p, a, c, conn, Reply{acquireNotInstalled: true, Identity: a.Document.Identity}) {
				t.Fatal("concurrent authority cleared")
			}
			f.g.controlMu.Lock()
			retained := testFirstControl(f.g) != nil
			f.g.controlMu.Unlock()
			if !retained {
				t.Fatal("authority removed")
			}
			f.g.broker.mu.Lock()
			if mode == "unknown" && !c.unknown["prior"] || mode == "usedLease" && c.attempts["prior"].ControlLease == nil {
				t.Fatal("history removed")
			}
			f.g.broker.mu.Unlock()
		})
	}
}

func TestReusedAcquisitionRejectionCanRetireOriginalLeaseWithoutChangingReceipts(t *testing.T) {
	f := newReadFixture(t)
	original, e := f.g.AdmitControl(f.ctx, f.p, readTarget().Surface)
	if e != nil {
		t.Fatal(e)
	}
	c := f.g.controlChannel(original)
	saved := Reply{AttemptID: "original-known", DispatchState: "dispatched", EffectState: "unverified"}
	f.g.broker.mu.Lock()
	c.receipts[saved.AttemptID] = saved
	f.g.broker.mu.Unlock()
	f.staleAcquires.Store(1)
	admission, e := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if e == nil || admission.Created || admission.Confirmed || admission.Authority.Lease != original.Lease {
		t.Fatal("reused rejection changed ownership", e)
	}
	if retired, e := f.g.RetireControl(f.ctx, f.p, original); e != nil || !retired {
		t.Fatal("original pin could not retire after generation change", e)
	}
	next, e := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if e != nil || !next.Created || !next.Confirmed || next.Authority.Lease == original.Lease {
		t.Fatal("new metadata admission remained busy", e)
	}
	f.g.broker.mu.Lock()
	same := c.receipts[saved.AttemptID].DispatchState == saved.DispatchState && c.receipts[saved.AttemptID].EffectState == saved.EffectState
	f.g.broker.mu.Unlock()
	if !same || f.reads.Load() != 0 {
		t.Fatal("receipt changed or input executed")
	}
}
