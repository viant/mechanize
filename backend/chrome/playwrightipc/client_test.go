package playwrightipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ipcFixture(t *testing.T, script string) Config {
	t.Helper()
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node runtime unavailable")
	}
	node, e = filepath.EvalSymlinks(node)
	if e != nil {
		t.Fatal(e)
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"engine.mjs", "relay.mjs", "fingerprint.cjs", "target.cjs", "package-lock.json", "node_modules/playwright-core/package.json"} {
		path := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(path), 0700)
		if e = os.WriteFile(path, []byte("{}"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(root, "sidecar.mjs"), []byte(script), 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := safeFile(node)
	if e != nil {
		t.Fatal(e)
	}
	tree, e := RuntimeDigest(root)
	if e != nil {
		t.Fatal(e)
	}
	return Config{node, digest(raw), root, tree}
}
func newTestClient(t testing.TB, config Config) (*Client, error) {
	t.Helper()
	client, err := New(config)
	if client != nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}
func TestIPCRealChildCallbacksAreBoundedAndProviderErrorsPrivate(t *testing.T) {
	script := `import {createInterface} from 'node:readline';const lines=createInterface({input:process.stdin});let execution;lines.on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){execution=m;console.log(JSON.stringify({type:'callback',id:'cb',executionId:m.id,method:'admit',params:{command:m.command}}));}else if(m.type==='callbackResult'){if(m.result!==true)process.exit(2);console.log(JSON.stringify({type:'result',id:execution.id,result:{requestId:execution.command.requestId,dispatchState:'notDispatched',effectState:'none'}}));}});`
	config := ipcFixture(t, script)
	client, e := newTestClient(t, config)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	calls := 0
	result, e := client.Execute(ctx, "run", map[string]any{"requestId": "request"}, func(_ context.Context, cb Callback) (any, error) {
		calls++
		if cb.Method != "admit" || !json.Valid(cb.Params) {
			t.Fatal("callback altered")
		}
		return true, nil
	}, nil)
	if e != nil || result.RequestID != "request" || calls != 1 {
		t.Fatal("real child IPC failed", e)
	}
	// A loaded, qualified process survives disk changes. Any replacement must
	// validate the original enrolled pins before executing the changed runtime.
	if err := os.WriteFile(filepath.Join(config.RuntimeRoot, "engine.mjs"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, e = client.Execute(ctx, "warm", map[string]any{"requestId": "warm"}, func(context.Context, Callback) (any, error) { return true, nil }, nil); e != nil {
		t.Fatal("loaded runtime was discarded", e)
	}
	client.mu.Lock()
	child := client.child
	client.mu.Unlock()
	child.terminate()
	if e = child.await(); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Execute(ctx, "new", nil, func(context.Context, Callback) (any, error) {
		t.Fatal("unqualified replacement reached callback")
		return nil, nil
	}, nil); FailureCode(e) != "playwrightRuntimeQualification" {
		t.Fatal("runtime substitution accepted by replacement", e)
	}

}
func TestIPCRejectsWrongExecutionReplayAndOversizedFrames(t *testing.T) {
	for _, mode := range []string{"wrongOwner", "replay", "oversized", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			script := `import {createInterface} from 'node:readline';const lines=createInterface({input:process.stdin});lines.on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){`
			switch mode {
			case "wrongOwner":
				script += `console.log(JSON.stringify({type:'callback',id:'cb',executionId:'foreign',method:'admit',params:{}}));`
			case "replay":
				script += `let message={type:'callback',id:'cb',executionId:m.id,method:'admit',params:{}};console.log(JSON.stringify(message));console.log(JSON.stringify(message));`
			case "oversized":
				script += `console.log('x'.repeat(300000));`
			}
			script += `}});`
			config := ipcFixture(t, script)
			client, e := newTestClient(t, config)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			calls := 0
			if _, e = client.Execute(ctx, "run", nil, func(context.Context, Callback) (any, error) { calls++; return true, nil }, nil); e == nil {
				t.Fatal("invalid child protocol accepted")
			}
			if mode != "replay" && calls != 0 || calls > 1 {
				t.Fatal("untrusted callback/replay reached host")
			}
		})
	}
}
func TestIPCQualificationRequiresExactCodeAndNoSymlinks(t *testing.T) {
	c := ipcFixture(t, `process.exit(0)`)
	for _, mode := range []string{"nodeHash", "runtimeHash", "symlink", "publicScript"} {
		t.Run(mode, func(t *testing.T) {
			bad := c
			switch mode {
			case "nodeHash":
				bad.NodeSHA256 = ""
			case "runtimeHash":
				bad.RuntimeSHA256 = ""
			case "symlink":
				link := filepath.Join(c.RuntimeRoot, "linked")
				os.Symlink(c.NodePath, link)
				defer os.Remove(link)
				bad.NodePath = link
			case "publicScript":
				os.Chmod(filepath.Join(c.RuntimeRoot, "sidecar.mjs"), 0666)
				defer os.Chmod(filepath.Join(c.RuntimeRoot, "sidecar.mjs"), 0600)
			}
			if _, e := New(bad); e == nil {
				t.Fatal("unqualified runtime accepted")
			}
		})
	}
}

func TestIPCTrustedInjectedScriptFrameExceedsPublicBudgetOnlyInternally(t *testing.T) {
	script := `import{createInterface}from'node:readline';let execute;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){execute=m;console.log(JSON.stringify({type:'callback',id:'large',executionId:m.id,method:'relay.send',params:{relayId:'relay',method:'Runtime.evaluate',params:{expression:'x'.repeat(343078)},deadlineUnixMs:Date.now()+1000}}));}else if(m.type==='callbackResult'){console.log(JSON.stringify({type:'result',id:execute.id,result:{requestId:'request',dispatchState:'notDispatched',effectState:'none'}}));}});`
	client, e := newTestClient(t, ipcFixture(t, script))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	calls := 0
	result, e := client.Execute(ctx, "run", map[string]string{"requestId": "request"}, func(_ context.Context, c Callback) (any, error) {
		calls++
		if c.Method != "relay.send" || len(c.Params) <= 256*1024 || len(c.Params) > Limit {
			t.Fatal("trusted script frame unavailable")
		}
		return map[string]any{}, nil
	}, nil)
	if e != nil || calls != 1 || result.RequestID != "request" {
		t.Fatal("real child internal frame failed", e)
	}
	if _, e = client.Execute(ctx, "oversize", map[string]string{"requestId": "request", "value": string(make([]byte, 256*1024))}, func(context.Context, Callback) (any, error) {
		t.Fatal("oversize public command executed")
		return nil, nil
	}, nil); e == nil {
		t.Fatal("public command budget widened")
	}
}

func TestIPCMissingCanonicalPinnedTargetGuardNeverQualifies(t *testing.T) {
	config := ipcFixture(t, "process.exit(0)")
	if err := os.Remove(filepath.Join(config.RuntimeRoot, "target.cjs")); err != nil {
		t.Fatal(err)
	}
	// Even a newly enrolled digest cannot qualify an incomplete trusted runtime.
	var err error
	config.RuntimeSHA256, err = RuntimeDigest(config.RuntimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(config); err == nil {
		t.Fatal("runtime without canonical pinned-target guard qualified")
	}
}

func TestIPCReportsOnlyClosedFailurePhaseWithoutProviderOutput(t *testing.T) {
	for _, test := range []struct {
		name, script, code string
		budget             time.Duration
	}{
		{"exit", "process.stderr.write('PRIVATE_CANARY');process.exit(1)", "playwrightChildExited", time.Second},
		{"protocol", "console.log(JSON.stringify({type:'providerPrivateMessage',id:'r',privateCanary:'PRIVATE_CANARY'}))", "playwrightIPCProtocol", time.Second},
		{"deadline", "setInterval(()=>{},1000)", "playwrightDeadline", 300 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := ipcFixture(t, test.script)
			client, e := newTestClient(t, config)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), test.budget)
			defer cancel()
			_, e = client.Execute(ctx, "r", map[string]any{"requestId": "r"}, func(context.Context, Callback) (any, error) { return nil, nil }, nil)
			if !errors.Is(e, ErrUnavailable) || FailureCode(e) != test.code || strings.Contains(e.Error(), "PRIVATE_CANARY") {
				t.Fatal("closed transport failure phase unavailable", FailureCode(e))
			}
		})
	}
}

func TestIPCClosedCallbackDiagnosticPreservesBoundaryAndExcludesPrivateValues(t *testing.T) {
	script := `import{createInterface}from'node:readline';let run;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){run=m;console.log(JSON.stringify({type:'callback',id:'callback',executionId:m.id,method:'relay.open',params:{}}));}else if(m.type==='callbackResult'){console.log(JSON.stringify({type:'result',id:run.id,result:{requestId:'request',dispatchState:m.dispatchState,effectState:m.dispatchState==='unknown'?'unknown':'none',errorCode:m.errorCode}}));}});`
	config := ipcFixture(t, script)
	client, e := newTestClient(t, config)
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range []string{"notDispatched", "unknown"} {
		for _, code := range []string{"playwrightDocumentChanged", "playwrightCDPDenied", "playwrightInputSequenceDenied", "playwrightPRIVATE_CANARY", "https://PRIVATE/value", ""} {
			t.Run(state+code, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				result, e := client.Execute(ctx, "execution", map[string]string{"requestId": "request"}, func(context.Context, Callback) (any, error) {
					return nil, &CallbackError{DispatchState: state, Code: code}
				}, nil)
				expected := code
				if strings.Contains(code, "PRIVATE") || code == "" {
					expected = "playwrightHostDenied"
				}
				raw, _ := json.Marshal(result)
				if e != nil || result.DispatchState != state || result.ErrorCode != expected || strings.Contains(string(raw), "PRIVATE") {
					t.Fatal("diagnostic changed boundary/leaked values", result, e)
				}
			})
		}
	}
}

const reusableFixture = `import{createInterface}from'node:readline';let execution;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){execution=m;if(m.command?.hang)return;console.log(JSON.stringify({type:'callback',id:'admission',executionId:m.id,method:'admit',params:{command:m.command,executionId:m.executionId}}));}else if(m.type==='callbackResult'){console.log(JSON.stringify({type:'result',id:execution.id,result:{requestId:execution.command.requestId,dispatchState:'notDispatched',effectState:'none',value:String(m.result)}}));}});`

func TestIPCReuseRetainsProcessButNeverHandlerCommandOrResults(t *testing.T) {
	client, err := newTestClient(t, ipcFixture(t, reusableFixture))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var original *process
	for i := 0; i < 20; i++ {
		calls := 0
		value := fmt.Sprintf("value-%d", i)
		result, err := client.Execute(ctx, "same-caller-id", map[string]string{"requestId": "request", "value": value}, func(_ context.Context, cb Callback) (any, error) {
			calls++
			var params struct {
				Command     map[string]string
				ExecutionID string
			}
			if json.Unmarshal(cb.Params, &params) != nil || params.Command["value"] != value || params.ExecutionID != "same-caller-id" {
				t.Fatal("invocation contents or caller identity changed")
			}
			return value, nil
		}, nil)
		if err != nil || calls != 1 || result.Value == nil || *result.Value != value {
			t.Fatal("invocation reused another handler/result", result, err)
		}
		client.mu.Lock()
		child := client.child
		client.mu.Unlock()
		if i == 0 {
			original = child
		} else if child != original {
			t.Fatal("warm invocation relaunched runtime")
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan struct{}{original.readDone, original.exited} {
		select {
		case <-done:
		default:
			t.Fatal("Close left transport goroutines or process alive")
		}
	}
	if _, err := client.Execute(ctx, "closed", nil, func(context.Context, Callback) (any, error) {
		t.Fatal("closed client reached handler")
		return nil, nil
	}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed client accepted work")
	}
	if err := client.Close(); err != nil {
		t.Fatal("second Close failed", err)
	}
}

func TestIPCCanceledInflightDiscardsChildAndNeverReplays(t *testing.T) {
	client, err := newTestClient(t, ipcFixture(t, reusableFixture))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handler := func(context.Context, Callback) (any, error) { return "ready", nil }
	if _, err = client.Execute(ctx, "initial", map[string]string{"requestId": "initial"}, handler, nil); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	original := client.child
	client.mu.Unlock()
	deadline, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err = client.Execute(deadline, "hang", map[string]any{"hang": true}, func(context.Context, Callback) (any, error) { t.Fatal("hung input replayed"); return nil, nil }, nil); FailureCode(err) != "playwrightDeadline" {
		t.Fatal("cancellation classification changed", err)
	}
	select {
	case <-original.exited:
	default:
		t.Fatal("canceled child survived")
	}
	if _, err = client.Execute(ctx, "replacement", map[string]string{"requestId": "replacement"}, handler, nil); err != nil {
		t.Fatal("fresh explicit invocation unavailable", err)
	}
	client.mu.Lock()
	replacement := client.child
	client.mu.Unlock()
	if replacement == original {
		t.Fatal("canceled child reused")
	}
}

func TestIPCWaiterDeadlineDoesNotCancelOwnerAndCloseCancelsHandler(t *testing.T) {
	client, err := newTestClient(t, ipcFixture(t, reusableFixture))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entered, release, ownerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := client.Execute(ctx, "owner", map[string]string{"requestId": "owner"}, func(ctx context.Context, _ Callback) (any, error) {
			close(entered)
			select {
			case <-release:
				return "owner", nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, nil)
		ownerDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("owner failed to enter")
	}
	waitCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := client.Execute(waitCtx, "waiter", nil, func(context.Context, Callback) (any, error) {
		t.Fatal("expired waiter reached handler")
		return nil, nil
	}, nil); FailureCode(err) != "playwrightDeadline" {
		t.Fatal("waiting deadline lost", err)
	}
	select {
	case err := <-ownerDone:
		t.Fatal("waiter canceled owner", err)
	default:
	}
	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatal("owner failed", err)
	}
	entered = make(chan struct{})
	go func() {
		_, err := client.Execute(ctx, "close-active", map[string]string{"requestId": "close-active"}, func(ctx context.Context, _ Callback) (any, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}, nil)
		ownerDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("second owner failed to enter")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ownerDone:
		if FailureCode(err) != "playwrightChildExited" {
			t.Fatal("close classification changed", err)
		}
	case <-ctx.Done():
		t.Fatal("Close left handler running")
	}
}

func TestIPCLateTerminalFrameCannotReachRepeatedCallerHandler(t *testing.T) {
	script := `import{createInterface}from'node:readline';let runs=0;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type!=='execute')return;const r={type:'result',id:m.id,result:{requestId:'request',dispatchState:'notDispatched',effectState:'none'}};console.log(JSON.stringify(r));if(++runs===1)console.log(JSON.stringify(r));});`
	client, err := newTestClient(t, ipcFixture(t, script))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handler := func(context.Context, Callback) (any, error) {
		t.Fatal("late frame reached current handler")
		return nil, nil
	}
	if _, err = client.Execute(ctx, "same-id", nil, handler, nil); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	original := client.child
	client.mu.Unlock()
	if _, err = client.Execute(ctx, "same-id", nil, handler, nil); FailureCode(err) != "playwrightIPCProtocol" {
		t.Fatal("late terminal result accepted", err)
	}
	select {
	case <-original.exited:
	default:
		t.Fatal("corrupt child survived")
	}
}

func TestIPCEventsBelongOnlyToCurrentInvocation(t *testing.T) {
	script := `import{createInterface}from'node:readline';let execution;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type==='execute')execution=m;else if(m.type==='relayEvent'){if(m.executionId!==execution.id)process.exit(2);console.log(JSON.stringify({type:'result',id:execution.id,result:{requestId:execution.command.requestId,dispatchState:'notDispatched',effectState:'none',value:m.method}}));}});`
	client, err := newTestClient(t, ipcFixture(t, script))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	oldEvents, newEvents := make(chan Event, 2), make(chan Event, 1)
	oldEvents <- Event{RelayID: "old", Method: "old-event", Params: json.RawMessage(`{}`)}
	handler := func(context.Context, Callback) (any, error) { t.Fatal("unexpected callback"); return nil, nil }
	if r, err := client.Execute(ctx, "old", map[string]string{"requestId": "old"}, handler, oldEvents); err != nil || r.Value == nil || *r.Value != "old-event" {
		t.Fatal("old event lost", r, err)
	}
	oldEvents <- Event{RelayID: "old", Method: "late-old-event", Params: json.RawMessage(`{}`)}
	newEvents <- Event{RelayID: "new", Method: "new-event", Params: json.RawMessage(`{}`)}
	if r, err := client.Execute(ctx, "new", map[string]string{"requestId": "new"}, handler, newEvents); err != nil || r.Value == nil || *r.Value != "new-event" {
		t.Fatal("cross-invocation event delivered", r, err)
	}
	if len(oldEvents) != 1 {
		t.Fatal("old event forwarder remained alive")
	}
}

func TestIPCColdWarmLatency(t *testing.T) {
	client, err := newTestClient(t, ipcFixture(t, reusableFixture))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handler := func(context.Context, Callback) (any, error) { return "ok", nil }
	events := make(chan Event)
	began := time.Now()
	if _, err = client.Execute(ctx, "cold", map[string]string{"requestId": "cold"}, handler, events); err != nil {
		t.Fatal(err)
	}
	cold := time.Since(began)
	var warm []time.Duration
	for i := 0; i < 30; i++ {
		began = time.Now()
		if _, err = client.Execute(ctx, "warm", map[string]string{"requestId": "warm"}, handler, events); err != nil {
			t.Fatal(err)
		}
		warm = append(warm, time.Since(began))
	}
	sort.Slice(warm, func(i, j int) bool { return warm[i] < warm[j] })
	t.Logf("real Node IPC only (generic local fixture, no browser): cold=%s warm median=%s warm p95=%s", cold, warm[len(warm)/2], warm[28])
}

func TestIPCProductionSidecarClearsStateAndRejectsLateBoundCallbacks(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source unavailable")
	}
	sidecar, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../browser/playwright/sidecar.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	config := ipcFixture(t, string(sidecar))
	// Exercise the production sidecar's lifetime boundary with a deterministic
	// adapter; actual Playwright/CDP is covered by the browser engine fixtures.
	engine := `let instances=0;export class PlaywrightEngine{constructor(host){this.host=host;this.instance=++instances;}async execute(command){await this.host.admit(command);await this.host.current();const relay=await this.host.openRelay({origin:'https://fixture.example'});if(command.late)setTimeout(()=>{this.host.current().catch(()=>{});},30);if(command.delay)await new Promise(r=>setTimeout(r,80));await relay.close();return{requestId:command.requestId,dispatchState:'notDispatched',effectState:'none',value:String(this.instance)};}}`
	if err = os.WriteFile(filepath.Join(config.RuntimeRoot, "engine.mjs"), []byte(engine), 0600); err != nil {
		t.Fatal(err)
	}
	config.RuntimeSHA256, err = RuntimeDigest(config.RuntimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newTestClient(t, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 1; i <= 3; i++ {
		calls := map[string]int{}
		id := fmt.Sprintf("original-%d", i)
		result, err := client.Execute(ctx, id, map[string]any{"requestId": id, "deadlineUnixMs": time.Now().Add(time.Second).UnixMilli(), "late": i == 1, "delay": i == 2}, func(_ context.Context, cb Callback) (any, error) {
			calls[cb.Method]++
			if cb.Method == "current" || cb.Method == "relay.open" {
				var params struct{ ExecutionID string }
				if json.Unmarshal(cb.Params, &params) != nil || params.ExecutionID != id {
					t.Fatal("original caller identity changed")
				}
			}
			if cb.Method == "relay.open" {
				return map[string]string{"relayId": "relay-" + id}, nil
			}
			return true, nil
		}, nil)
		if err != nil || result.Value == nil || *result.Value != strconv.Itoa(i) || calls["admit"] != 1 || calls["current"] != 1 || calls["relay.open"] != 1 || calls["relay.close"] != 1 {
			t.Fatal("sidecar state crossed invocation", result, calls, err)
		}
	}
}

func TestIPCCancellationUnblocksFullChildInputPipe(t *testing.T) {
	client, err := newTestClient(t, ipcFixture(t, `setInterval(()=>{},1000)`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err = client.Execute(ctx, "blocked-write", map[string]string{"value": strings.Repeat("x", 200000)}, func(context.Context, Callback) (any, error) {
		t.Fatal("unread command reached handler")
		return nil, nil
	}, nil)
	if FailureCode(err) != "playwrightDeadline" || time.Since(began) > time.Second {
		t.Fatal("cancellation left input writer blocked", err)
	}
	client.mu.Lock()
	child := client.child
	client.mu.Unlock()
	if child != nil {
		t.Fatal("write cancellation retained child")
	}
}

func TestIPCEventsProgressDuringInlineCallback(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "event-forwarded")
	// The child acknowledges an event while Go is inside the broker callback;
	// this reproduces providers whose reply depends on concurrent CDP progress.
	script := `import{createInterface}from'node:readline';import{writeFileSync}from'node:fs';let execution;createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){execution=m;console.log(JSON.stringify({type:'callback',id:'callback',executionId:m.id,method:'admit',params:{}}));}else if(m.type==='relayEvent'){writeFileSync(execution.command.marker,'forwarded');}else if(m.type==='callbackResult'){console.log(JSON.stringify({type:'result',id:execution.id,result:{requestId:'request',dispatchState:'notDispatched',effectState:'none'}}));}});`
	client, err := newTestClient(t, ipcFixture(t, script))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	events := make(chan Event, 1)
	_, err = client.Execute(ctx, "event-owner", map[string]string{"marker": marker}, func(ctx context.Context, _ Callback) (any, error) {
		events <- Event{RelayID: "relay", Method: "event", Params: json.RawMessage(`{}`)}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
				if _, err := os.Stat(marker); err == nil {
					return true, nil
				}
			}
		}
	}, events)
	if err != nil {
		t.Fatal("inline callback prevented CDP event progress", err)
	}
}
