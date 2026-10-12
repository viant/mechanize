package playwrightipc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
func TestIPCRealChildCallbacksAreBoundedAndProviderErrorsPrivate(t *testing.T) {
	script := `import {createInterface} from 'node:readline';const lines=createInterface({input:process.stdin});let execution;lines.on('line',line=>{const m=JSON.parse(line);if(m.type==='execute'){execution=m;console.log(JSON.stringify({type:'callback',id:'cb',executionId:m.id,method:'admit',params:{command:m.command}}));}else if(m.type==='callbackResult'){if(m.result!==true)process.exit(2);console.log(JSON.stringify({type:'result',id:execution.id,result:{requestId:execution.command.requestId,dispatchState:'notDispatched',effectState:'none'}}));}});`
	config := ipcFixture(t, script)
	client, e := New(config)
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
	// Package substitution after qualification is refused before process launch.
	os.WriteFile(filepath.Join(config.RuntimeRoot, "engine.mjs"), []byte("changed"), 0600)
	if _, e = client.Execute(ctx, "new", nil, func(context.Context, Callback) (any, error) {
		t.Fatal("unqualified code reached callback")
		return nil, nil
	}, nil); e == nil {
		t.Fatal("runtime substitution accepted")
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
			client, e := New(config)
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
	client, e := New(ipcFixture(t, script))
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
			client, e := New(config)
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
	client, e := New(config)
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
