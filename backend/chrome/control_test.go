package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func controlFixture(t *testing.T) (*Gateway, auth.Principal, context.Context, *atomic.Int64) {
	return controlFixtureVersion(t, 0)
}
func controlFixtureVersion(t *testing.T, version int) (*Gateway, auth.Principal, context.Context, *atomic.Int64) {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "control-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p, _ := auth.NewPrincipal("fixture:issuer", "", "owner", []string{"desktop:control"})
	p.ClientID = "verified-client"
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), StartToken: "chrome-start", Executable: "/fixture/Chrome"}
	leaf := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), StartToken: "host-start", Executable: "/fixture/host"}
	check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: leaf, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	}
	grant := Enrollment{Principal: p, ProfileChannel: "p1", BrowserInstance: "b1", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, ProfileDirectory: dir}
	credential := strings.Repeat("fixture", 8)
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("p1", "b1"): credential}, check)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": "p1", "browserInstance": "b1", "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "profileDirectory": dir, "profileLaunchQualified": true})
	raw, _ := ReadFrame(conn)
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"], "mutationFingerprintVersion": version})
	d := Document{MutationFingerprintVersion: version, Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, FrameID: 0, DocumentID: "doc1", Generation: 1}, Origin: "https://fixture.test"}
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{d}})
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.channels[channelKey("p1", "b1")].inventoryComplete
	})
	count := &atomic.Int64{}
	go func() {
		for {
			raw, err := ReadFrame(conn)
			if err != nil {
				return
			}
			var cmd Command
			json.Unmarshal(raw, &cmd)
			r := Reply{RequestID: cmd.RequestID, Identity: cmd.Identity, ControlLease: cmd.ControlLease}
			switch cmd.Action {
			case "executor.acquire":
				r.Validated = true
			case "executor.retire":
				r.RetiredAuthorityQuiesced = true
			case "element.press", "element.fill":
				count.Add(1)
				r.FingerprintVersion = cmd.FingerprintVersion
				r.FingerprintSHA256 = cmd.FingerprintSHA256
				r.AttemptID = cmd.AttemptID
				r.DispatchState = "dispatched"
				r.EffectState = "unverified"
			}
			if WriteFrame(conn, r) != nil {
				return
			}
		}
	}()
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), p)
	captured := make(chan context.Context, 1)
	release := make(chan struct{})
	runtime, err := integration.New(func(runCtx context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		captured <- runCtx
		<-release
		return integration.StepResult{DispatchState: "notDispatched"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtime.Open(ctx, "control-fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.StartPlan(ctx, opened.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{controlStep(t)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ctx = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("Endly metadata callback timeout")
	}
	t.Cleanup(func() { close(release); runtime.Close(ctx, opened.SessionID) })
	return g, p, ctx, count
}
func waitControl(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bounded condition timeout")
}
func controlStep(t *testing.T) model.Step {
	t.Helper()
	plan, err := script.Compile(`web.tab(origin: "https://fixture.test").getById("save", exact: true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Steps[0]
}
func TestControlProductionLeaseSequentialRetirementAndRevocation(t *testing.T) {
	g, p, ctx, count := controlFixture(t)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	r, err := g.ExecuteControl(ctx, p, step, nil, a)
	if err != nil || r.DispatchState != "dispatched" {
		t.Fatalf("dispatch: %v %+v", err, r)
	}
	ok, err := g.RetireControl(ctx, p, a)
	if err != nil || !ok {
		t.Fatalf("retire: %v", err)
	}
	if _, err = g.ExecuteControl(ctx, p, step, nil, a); err == nil {
		t.Fatal("retired authority accepted")
	}
	a2, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil || a2.Lease == a.Lease {
		t.Fatalf("fresh authority: %v", err)
	}
	step.ID = "second-step"
	r, err = g.ExecuteControl(ctx, p, step, nil, a2)
	if err != nil || r.DispatchState != "dispatched" {
		t.Fatalf("second dispatch: %v %+v", err, r)
	}
	revoked, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = g.ExecuteControl(revoked, p, step, nil, a2); err == nil {
		t.Fatal("revoked context accepted")
	}
	ok, err = g.RetireControl(ctx, p, a2)
	if !ok || err != nil {
		t.Fatal(err)
	}
	if count.Load() != 2 {
		t.Fatalf("dispatch count: %d", count.Load())
	}
}
func TestControlDelayedWireGateAndUnknownRetirement(t *testing.T) {
	g, p, ctx, count := controlFixture(t)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	c.writeMu.Lock()
	done := make(chan error, 1)
	go func() { _, err := g.ExecuteControl(ctx, p, step, nil, a); done <- err }()
	waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return len(c.pending) == 1 })
	if ok, err := g.RetireControl(ctx, p, a); ok || err == nil {
		t.Fatal("in-flight authority falsely retired")
	}
	c.writeMu.Unlock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("delayed retired dispatch allowed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delayed gate timeout")
	}
	if count.Load() != 0 {
		t.Fatal("old command reached renderer")
	}
	if ok, err := g.RetireControl(ctx, p, a); !ok || err != nil {
		t.Fatalf("settled retirement: %v", err)
	}
	a, err = g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	g.broker.mu.Lock()
	c.unknown["lost"] = true
	g.broker.mu.Unlock()
	if ok, err := g.RetireControl(ctx, p, a); ok || err == nil {
		t.Fatal("unknown effect falsely retired")
	}
}
func TestControlNavigationAndFixtureCannotQualify(t *testing.T) {
	g, p, ctx, _ := controlFixture(t)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	c.documents[0].DocumentID = "replacement"
	g.broker.mu.Unlock()
	if err = g.VerifyControl(ctx, p, a); err == nil {
		t.Fatal("navigation retained old authority")
	}
	g.broker.mu.Lock()
	c.fixtureOnly = true
	g.broker.mu.Unlock()
	if _, err = g.AdmitControl(ctx, p, step.Target.Surface); err == nil {
		t.Fatal("fixture qualified production authority")
	}
}

func TestControlConcurrentAdmissionDispatchRetirementAndCancellationNoLockInversion(t *testing.T) {
	g, p, ctx, count := controlFixture(t)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	c.writeMu.Lock()
	locked := true
	defer func() {
		if locked {
			c.writeMu.Unlock()
		}
	}()
	admissionCtx, cancelAdmission := context.WithCancel(ctx)
	defer cancelAdmission()
	admitted := make(chan error, 1)
	go func() { _, err := g.AdmitControl(admissionCtx, p, step.Target.Surface); admitted <- err }()
	waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return len(c.pending) == 1 })
	// Admission is now waiting for the channel writer. The dispatch callback must
	// still be able to read authority state without taking admission's RPC lock.
	if !g.controlMu.TryLock() {
		t.Fatal("admission held authority mutex across network/write wait")
	}
	g.controlMu.Unlock()
	dispatched := make(chan error, 1)
	go func() { _, err := g.ExecuteControl(ctx, p, step, nil, a); dispatched <- err }()
	waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return len(c.pending) == 2 })
	waitingCtx, cancelWaiting := context.WithCancel(ctx)
	cancelWaiting()
	waiting := make(chan error, 1)
	go func() { _, err := g.AdmitControl(waitingCtx, p, step.Target.Surface); waiting <- err }()
	select {
	case err := <-waiting:
		if err == nil {
			t.Fatal("canceled admission lane wait accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled admission blocked behind RPC")
	}
	if retired, err := g.RetireControl(ctx, p, a); retired || err == nil {
		t.Fatal("in-flight authority falsely retired")
	}
	cancelAdmission()
	c.writeMu.Unlock()
	locked = false
	for label, result := range map[string]<-chan error{"admission": admitted, "dispatch": dispatched} {
		select {
		case err := <-result:
			if err == nil {
				t.Errorf("%s ignored retirement/cancellation", label)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s deadlocked", label)
		}
	}
	if count.Load() != 0 {
		t.Fatal("retired delayed input reached endpoint")
	}
	g.controlMu.Lock()
	retained := g.control != nil && g.control.Lease == a.Lease && g.controlRetiring
	g.controlMu.Unlock()
	if !retained {
		t.Fatal("ambiguous canceled authority was silently replaced")
	}
}
