package chrome

import "testing"

func TestControlAdmissionReportsActualCreationAndReuse(t *testing.T) {
	f := newReadFixture(t)
	created, err := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if err != nil || !created.Created || !created.Confirmed || created.Authority.Lease.ID == "" {
		t.Fatalf("actual new admission missing %+v %v", created, err)
	}
	reused, err := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if err != nil || reused.Created || !reused.Confirmed || !sameControl(created.Authority, reused.Authority) {
		t.Fatalf("reuse falsely claimed lease ownership %+v %v", reused, err)
	}
	if _, err := f.g.PinControlRead(f.ctx, f.p, created.Authority); err != nil {
		t.Fatal("reuse revoked original prepared authority")
	}
	retired, err := f.g.RetireControl(f.ctx, f.p, created.Authority)
	if err != nil || !retired {
		t.Fatal(err)
	}
	after, err := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if err != nil || !after.Created || after.Authority.Lease == created.Authority.Lease {
		t.Fatal("confirmed retirement did not permit fresh actual admission")
	}
}

func TestControlAdmissionUnacknowledgedAcquireRetainsOwnershipWithoutConfirmation(t *testing.T) {
	f := newReadFixture(t)
	f.rejectAcquire.Store(true)
	result, err := f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if err == nil || !result.Created || result.Confirmed || result.Authority.Lease.ID == "" {
		t.Fatalf("ambiguous acquire claimed confirmation or lost identity: %+v %v", result, err)
	}
	f.g.controlMu.Lock()
	held := f.g.control
	retiring := f.g.controlRetiring
	f.g.controlMu.Unlock()
	if held == nil || retiring || !sameControl(*held, result.Authority) {
		t.Fatal("unconfirmed acquired authority was discarded")
	}
	f.rejectAcquire.Store(false)
	result, err = f.g.AdmitControlWithStatus(f.ctx, f.p, readTarget().Surface)
	if err != nil || result.Created || !result.Confirmed {
		t.Fatalf("retry falsely claimed ownership of retained admission %+v %v", result, err)
	}
}
