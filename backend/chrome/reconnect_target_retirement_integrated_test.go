package chrome

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
)

// Actual linked Datly plan/intent/binding/outcome + held snapshot, real Broker
// socket, shipped worker reload/census/adoption and a separately leased fresh
// action. Signed OS peer and Chrome APIs/renderer are inert fixture boundaries.
func TestHistoricalUnknownReloadDatlyBrokerWorkerAndFreshAction(t *testing.T) {
	f := newReconnectDatlyFixture(t, false)
	before := f.read()
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	grant := enrollment(f.p, "p1")
	grant.BrowserInstance = "b1"
	grant.Origins = []string{"https://fixture.example.test"}
	grant.TrustScope = TrustScopeDesktop
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), StartToken: "browser", Executable: "/fixture/Chrome"}
	leaf := session.ProcessIdentity{PID: 20, UID: parent.UID, StartToken: "host", Executable: "/fixture/host"}
	providerDone := make(chan error, 1)
	provider := func(callCtx context.Context, p auth.Principal, scope ReconnectBindingScope, check func(context.Context) error, consume func([]ReconnectBinding) error) error {
		err := f.builder.WithChromeRetirementComponents(callCtx, p, func(held context.Context, _ durable.RetirementComponentInvoker) error {
			bound, e := data.WithChromeReconnectBindingReadAuthority(held, data.ChromeReconnectBindingReadScope{ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, ScopeHash: scope.ScopeHash}, check)
			if e != nil {
				return e
			}
			rows, e := f.builder.ChromeReconnectBindingSnapshot(bound, p)
			if e != nil {
				return e
			}
			if len(rows) != 1 {
				return fmt.Errorf("complete fixture snapshot unavailable")
			}
			r := rows[0]
			if r.BrowserAttemptId == nil || *r.BrowserAttemptId != f.descriptor.BrowserAttemptID || r.FingerprintDigest == nil || *r.FingerprintDigest != f.descriptor.Fingerprint.SHA256 || r.RendererLeaseId == nil || *r.RendererLeaseId != f.descriptor.ControlLease.ID || r.RendererLeaseGeneration == nil || uint64(*r.RendererLeaseGeneration) != f.descriptor.ControlLease.Generation {
				return fmt.Errorf("original immutable binding changed")
			}
			var original integration.StepResult
			for _, o := range r.Outcomes {
				if o.Kind != nil && *o.Kind == "outcome" && o.PayloadJson != nil {
					_ = json.Unmarshal([]byte(*o.PayloadJson), &original)
				}
			}
			if original.DispatchState != "unknown" {
				return fmt.Errorf("original outcome not UNKNOWN")
			}
			row := ReconnectBinding{Identity: f.descriptor.Identity, Fence: ReconnectFence{f.descriptor.BrokerEpoch, f.descriptor.ChannelEpoch, f.descriptor.ScopeHash}, AttemptID: *r.BrowserAttemptId, Fingerprint: *r.FingerprintDigest, DispatchState: original.DispatchState, ControlLease: &Lease{ID: *r.RendererLeaseId, Generation: uint64(*r.RendererLeaseGeneration)}}
			if e = consume([]ReconnectBinding{row}); e != nil {
				return e
			}
			return check(bound)
		})
		providerDone <- err
		return err
	}
	b, e := newBrokerWithPeer(Config{SocketPath: filepath.Join(trustScopeTestDirectory(t), "joined.sock"), Grants: []Enrollment{grant}, ReconnectBindings: provider}, map[string]string{channelKey("p1", "b1"): strings.Repeat("synthetic", 8)}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: leaf, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	// Both the historical inert store and worker fixture use this same scoped
	// hash; production computes it from the configured enrollment.
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	c.scopeHash = f.descriptor.ScopeHash
	b.mu.Unlock()
	g, e := NewGateway(b, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	recoverConsent := historicalConsentRecoveryFixture(t, f, g)
	conn, e := net.Dial("unix", b.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	child := exec.CommandContext(ctx, "node", "testdata/reconnect_target_retirement.cjs")
	input, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	child.Stderr = os.Stderr
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { input.Close(); child.Process.Kill(); child.Wait() })
	var writeMu sync.Mutex
	write := func(v any) error {
		raw, e := json.Marshal(v)
		if e != nil {
			return e
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, e = input.Write(append(raw, 10))
		return e
	}
	ready := make(chan struct {
		Original Command
		Hello    map[string]any
	}, 1)
	finished := make(chan map[string]any, 1)
	failed := make(chan error, 2)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), MaxFrameBytes+1)
		for scanner.Scan() {
			var frame map[string]any
			if json.Unmarshal(scanner.Bytes(), &frame) != nil {
				failed <- fmt.Errorf("fixture frame invalid")
				return
			}
			switch frame["type"] {
			case "fixture.ready":
				var r struct {
					Original Command
					Hello    map[string]any
				}
				_ = json.Unmarshal(scanner.Bytes(), &r)
				ready <- r
			case "fixture.finished":
				finished <- frame
			case "fixture.failed":
				failed <- fmt.Errorf("shipped worker fixture failed")
				return
			default:
				if e := WriteFrame(conn, json.RawMessage(append([]byte(nil), scanner.Bytes()...))); e != nil {
					failed <- e
					return
				}
			}
		}
	}()
	go func() {
		for {
			raw, e := ReadFrame(conn)
			if e != nil {
				select {
				case failed <- fmt.Errorf("native fixture channel closed"):
				default:
				}
				return
			}
			var frame any
			if json.Unmarshal(raw, &frame) != nil {
				return
			}
			if write(raw) != nil {
				return
			}
		}
	}()
	if e = write(map[string]any{"type": "fixture.start", "attemptId": f.descriptor.BrowserAttemptID}); e != nil {
		t.Fatal(e)
	}
	select {
	case r := <-ready:
		if r.Original.FingerprintSHA256 != f.descriptor.Fingerprint.SHA256 || r.Hello["playwrightTargetRetirementVersion"] != float64(1) {
			t.Fatal("real journal or negotiated feature mismatch")
		}

		r.Hello["credential"] = strings.Repeat("synthetic", 8)
		// The synthetic Chrome API runtime has no installed extension identity;
		// the signed-peer adapter uses this fixture's configured enrollment.
		r.Hello["extensionOrigin"] = grant.ExtensionOrigin
		r.Hello["trustScope"] = TrustScopeDesktop
		if e = WriteFrame(conn, r.Hello); e != nil {
			t.Fatal(e)
		}
	case e := <-failed:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case e = <-providerDone:
		if e != nil {
			t.Fatal("held Datly reconnect/retirement failed", e)
		}
	case e = <-failed:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal("joined protocol timed out", ctx.Err())
	}
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.executorQualified && c.inventoryComplete })
	b.mu.Lock()
	audit := c.receipts[f.descriptor.BrowserAttemptID]
	active := c.unknown[f.descriptor.BrowserAttemptID]
	b.mu.Unlock()
	if audit.DispatchState != "unknown" || audit.EffectState != "unknown" || active || string(before) != string(f.read()) {
		t.Fatal("operational recovery changed original audit")
	}
	if err := recoverConsent(); err != nil {

		t.Fatal("retired historical audit blocked existing consent recovery CAS", err)
	}
	if string(before) != string(f.read()) {
		t.Fatal("consent cleanup altered original UNKNOWN")
	}
	f.setExecute(func(runCtx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
		a, e := g.AdmitControl(runCtx, p, step.Target.Surface)
		if e != nil {
			return integration.StepResult{}, e
		}
		intent, e := data.RequireCommittedStepIntent(runCtx, p)
		if e != nil {
			return integration.StepResult{}, e
		}
		id := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
		result, err := g.ExecuteControlBound(runCtx, p, step, values, a, id, func(commitCtx context.Context, actor auth.Principal, descriptor BoundMutation) (BindingCommit, error) {
			return commitReconnectDatlyBinding(commitCtx, actor, step, a, descriptor, f.builder.InvokeCommittedComponent)
		})
		var detail *model.MechanizeError
		if errors.As(err, &detail) {
			t.Logf("fresh_executor code=%s dispatch=%s", detail.Code, detail.DispatchState)
		}
		return result, err
	})
	opened, e := f.runtime.Open(ctx, "fresh independently leased fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer f.runtime.Close(ctx, opened.SessionID)
	plan, e := script.Compile(`web.tab(origin:"https://fixture.example.test").getById("color",exact:true).select("blue",timeout:3s)`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixture": {Kind: model.StringValue, String: "fresh-action"}}
	op, e := f.runtime.StartPlan(ctx, opened.SessionID, *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	result, e := f.runtime.Wait(ctx, opened.SessionID, op.ID)
	if e != nil || result.Status != "succeeded" {
		t.Logf("fresh_failure hasPostcondition=%v needsReconciliation=%v bindingFailure=%v verificationFailure=%v errorPresent=%v", plan.Steps[0].Postcondition != nil, strings.Contains(result.Error, "reconciliation"), strings.Contains(result.Error, "bindingUnconfirmed"), strings.Contains(result.Error, "verification"), result.Error != "")
		if failure, err := f.runtime.ExecutionFailure(ctx, opened.SessionID, op.ID); err == nil && failure != nil {
			t.Logf("fresh_failure code=%s dispatch=%s", failure.Code, failure.DispatchState)
		}
		t.Fatal("fresh independently authorized action failed", e, result.Status)
	}
	if e = write(map[string]any{"type": "fixture.finish"}); e != nil {
		t.Fatal(e)
	}
	select {
	case out := <-finished:
		if out["journalUnchanged"] != true || out["freshInputs"] != float64(1) {
			t.Fatal("original journal changed or fresh input duplicated")
		}
	case e = <-failed:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if string(before) != string(f.read()) || f.dispatches.Load() != 1 {
		t.Fatal("retirement replayed original action or changed durable UNKNOWN")
	}
}
