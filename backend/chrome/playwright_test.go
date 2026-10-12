package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome/playwrightipc"
	"github.com/viant/mechanize/model"
)

func playwrightTestClient(t *testing.T, mode string) *playwrightipc.Client {
	t.Helper()
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node unavailable")
	}
	node, _ = filepath.EvalSymlinks(node)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	script := `import{createInterface}from'node:readline';let seq=0,command,run;const pending=new Map();const emit=m=>console.log(JSON.stringify(m));const cb=(method,params)=>new Promise((resolve,reject)=>{const id='cb'+(++seq);pending.set(id,{resolve,reject});emit({type:'callback',id,executionId:run,method,params});});createInterface({input:process.stdin}).on('line',async line=>{let m=JSON.parse(line);if(m.type==='callbackResult'){let p=pending.get(m.id);pending.delete(m.id);if(m.errorCode)p.reject(Error());else p.resolve(m.result);return;}if(m.type!=='execute')return;command=m.command;run=m.id;try{await cb('admit',{command});let{relayId}=await cb('relay.open',{executionId:run});await cb('intent.confirm',{attemptId:command.attemptId,identity:command.identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:command.controlLease,fingerprintSHA256:command.fingerprintSHA256});await cb('relay.send',{relayId,method:'Input.dispatchMouseEvent',params:{type:'mouseMoved'},deadlineUnixMs:command.deadlineUnixMs});`
	if mode != "preInput" {
		script += `await cb('relay.send',{relayId,method:'Input.dispatchMouseEvent',params:{type:'mousePressed'},deadlineUnixMs:command.deadlineUnixMs});`
	}
	script += `let state=` + `'dispatched'` + `;await cb('receipt.persist',{attemptId:command.attemptId,fingerprintSHA256:command.fingerprintSHA256,dispatchState:state,effectState:'unverified'});await cb('relay.close',{relayId});emit({type:'result',id:run,result:{requestId:command.requestId,dispatchState:state,effectState:'unverified'}});}catch{emit({type:'result',id:run,result:{requestId:command.requestId,dispatchState:'unknown',effectState:'unknown',errorCode:'playwrightUnavailable'}});}});`

	if mode == "readKnown" || mode == "readDenied" {
		script = `import{createInterface}from'node:readline';let seq=0,command,run;const pending=new Map();const emit=m=>console.log(JSON.stringify(m));const cb=(method,params)=>new Promise((resolve,reject)=>{const id='cb'+(++seq);pending.set(id,{resolve,reject});emit({type:'callback',id,executionId:run,method,params});});createInterface({input:process.stdin}).on('line',async line=>{let m=JSON.parse(line);if(m.type==='callbackResult'){let p=pending.get(m.id);pending.delete(m.id);if(m.errorCode)p.reject(Error());else p.resolve(m.result);return;}if(m.type!=='execute')return;command=m.command;run=m.id;try{await cb('admit',{command});let{relayId}=await cb('relay.open',{executionId:run});for(let i=0;i<20;i++)await cb('current',{executionId:run});await cb('relay.send',{relayId,method:'Runtime.evaluate',params:{expression:'fixture-public-code'},deadlineUnixMs:command.deadlineUnixMs});const value=await cb('relay.redact',{relayId,value:'public ready'});await cb('relay.close',{relayId});emit({type:'result',id:run,result:{requestId:command.requestId,dispatchState:'notDispatched',effectState:'none',value}});}catch{emit({type:'result',id:run,result:{requestId:command.requestId,dispatchState:'notDispatched',effectState:'none',errorCode:'playwrightUnavailable'}});}});`
	}
	if mode == "readDenied" {
		script = strings.ReplaceAll(script, "p.reject(Error())", "p.reject(Object.assign(Error('closed fixture'),{code:m.errorCode,dispatchState:m.dispatchState}))")
		script = strings.ReplaceAll(script, "catch{emit", "catch(error){emit")
		script = strings.ReplaceAll(script, "errorCode:'playwrightUnavailable'", "errorCode:error.code||'playwrightUnavailable'")
	}
	for _, name := range []string{"sidecar.mjs", "engine.mjs", "relay.mjs", "fingerprint.cjs", "target.cjs", "package-lock.json", "node_modules/playwright-core/package.json"} {
		file := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(file), 0700)
		value := "{}"
		if name == "sidecar.mjs" {
			value = script
		}
		os.WriteFile(file, []byte(value), 0600)
	}
	raw, _ := os.ReadFile(node)
	sum := sha256.Sum256(raw)
	tree, e := playwrightipc.RuntimeDigest(root)
	if e != nil {
		t.Fatal(e)
	}
	client, e := playwrightipc.New(playwrightipc.Config{NodePath: node, NodeSHA256: hex.EncodeToString(sum[:]), RuntimeRoot: root, RuntimeSHA256: tree})
	if e != nil {
		t.Fatal(e)
	}
	return client
}
func TestPlaywrightPreparedSeamRetainsOriginalIntentAndInputBoundary(t *testing.T) {
	for _, mode := range []string{"known", "preInput", "lostInput", "deniedInput", "unqualified"} {
		t.Run(mode, func(t *testing.T) {
			p := principal(t, "playwright-fixture")
			p.ClientID = "actor"
			grant := enrollment(p, "pw")
			b := fixtureBroker(t, grant)
			conn := connectHost(t, b, grant)
			d := document(grant, 7)
			publish(t, b, conn, grant, d)
			b.mu.Lock()
			c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
			c.fixtureOnly = false
			c.grant.TrustScope = TrustScopeProfile
			c.profileQualified = true
			c.scopeQualified = true
			c.executorQualified = true
			c.playwrightRelayVersion = 1
			c.mutationFingerprintVersion = 2
			proof := &nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
			c.processEvidence = proof
			b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return *proof, nil }
			b.mu.Unlock()
			b.playwright = playwrightTestClient(t, mode)
			if mode == "unqualified" {
				c.playwrightRelayVersion = 0
			}
			var sends atomic.Int32
			var sealed Command
			go func() {
				for {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var frame map[string]json.RawMessage
					json.Unmarshal(raw, &frame)
					var kind, request, relay string
					json.Unmarshal(frame["type"], &kind)
					json.Unmarshal(frame["requestId"], &request)
					json.Unmarshal(frame["relayId"], &relay)
					result := any(map[string]bool{"opened": true})
					response := map[string]any{"type": "playwright.result", "requestId": request, "relayId": relay}
					switch kind {
					case "playwright.open":
						var original Command
						json.Unmarshal(frame["command"], &original)
						sealed = original
						if original.FingerprintVersion != 2 || original.AttemptID == "" {
							return
						}
					case "playwright.send":
						sends.Add(1)
						var params struct {
							Type string `json:"type"`
						}
						json.Unmarshal(frame["params"], &params)
						if params.Type == "mousePressed" && mode == "lostInput" {
							conn.Close()
							return
						}
						if params.Type == "mousePressed" && mode == "deniedInput" {
							response["errorCode"] = "playwrightTargetChanged"
							response["dispatchState"] = "notDispatched"
							response["result"] = map[string]any{"receipt": map[string]any{"requestId": sealed.RequestID, "attemptId": sealed.AttemptID, "identity": sealed.Identity, "controlLease": sealed.ControlLease, "fingerprintVersion": 2, "fingerprintSHA256": sealed.FingerprintSHA256, "dispatchState": "notDispatched", "effectState": "none", "error": map[string]string{"code": "playwrightTargetChanged", "message": "PRIVATE-CANARY", "stage": "browser", "dispatchState": "notDispatched", "effectState": "none"}}}
						} else {
							result = map[string]any{}
						}
					case "playwright.receipt":
						result = map[string]bool{"persisted": true}
					case "playwright.close":
						result = map[string]bool{"closed": true}
					default:
						return
					}
					if response["errorCode"] == nil {
						response["result"] = result
					}
					WriteFrame(conn, response)
				}
			}()
			ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 2*time.Second)
			defer cancel()
			command := Command{Action: "element.press", Identity: d.Identity, Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, AttemptID: strings.Repeat("a", 64), FingerprintVersion: 2, ControlLease: &Lease{ID: "lease", Generation: 1}}
			commits := 0
			reply, err := b.callPrepared(ctx, c, command, true, func(Command) (BindingCommit, error) {
				commits++
				return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
			})
			expected := "dispatched"
			if mode == "preInput" || mode == "deniedInput" || mode == "unqualified" {
				expected = "notDispatched"
			}
			if mode == "lostInput" {
				expected = "unknown"
			}
			actual := reply.DispatchState
			if actual == "" && err != nil {
				if detail, ok := err.(interface{ Error() string }); ok {
					_ = detail
				}
				actual = "notDispatched"
			}
			if actual != expected || commits != 1 {
				t.Fatal("original binding/boundary lost", actual, expected, commits, err)
			}
			if mode == "deniedInput" && (reply.Error == nil || reply.Error.Code != "playwrightTargetChanged" || strings.Contains(reply.Error.Message, "CANARY")) {
				t.Fatal("terminal worker receipt masked", reply.Error)
			}
			if mode == "unqualified" && sends.Load() != 0 {
				t.Fatal("unsupported relay wrote input")
			}
			if mode != "unqualified" {
				b.mu.Lock()
				unknown := c.unknown[command.AttemptID]
				_, retained := c.attempts[command.AttemptID]
				_, receipt := c.receipts[command.AttemptID]
				b.mu.Unlock()
				if !retained || unknown != (mode == "lostInput") || receipt == (mode == "lostInput") {
					t.Fatal("canonical history/uncertainty changed")
				}
			}
			if mode == "known" || mode == "preInput" {
				if _, e := b.callPrepared(ctx, c, command, true, func(Command) (BindingCommit, error) { t.Fatal("same attempt recommitted"); return BindingCommit{}, nil }); e != nil {
					t.Fatal(e)
				}
				if commits != 1 {
					t.Fatal("replayed intent")
				}
			}
		})
	}
}
func TestPlaywrightInputClassificationNeverCountsMovementOrActionability(t *testing.T) {
	for _, test := range []struct {
		method, params string
		want           bool
	}{{"Input.dispatchMouseEvent", `{"type":"mouseMoved"}`, false}, {"Input.dispatchMouseEvent", `{"type":"mousePressed"}`, true}, {"Input.dispatchKeyEvent", `{"type":"keyUp"}`, false}, {"Input.dispatchKeyEvent", `{"type":"rawKeyDown"}`, true}, {"Input.insertText", `{}`, true}, {"Runtime.callFunctionOn", `{}`, false}} {
		if playwrightInput(test.method, json.RawMessage(test.params)) != test.want {
			t.Fatal("input boundary classification changed")
		}
	}
	if safePlaywrightError("playwrightPrivateCanary") != "playwrightUnavailable" {
		t.Fatal("provider code leaked")
	}
}

func TestPlaywrightPrivateDOMGuardAllowsOnlyOwnAdmittedInFlightOperation(t *testing.T) {
	identity := Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 7, DocumentID: "document", Generation: 1}
	actor := principal(t, "privacy-owner")
	actor.ClientID = "actor"
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "fixture"}
	command := Command{Action: "element.press", Locator: &Locator{Strategy: "id", Value: "stable", Exact: true}, RequestID: "request", AttemptID: "attempt", Identity: identity, FingerprintSHA256: strings.Repeat("a", 64), BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: "scope", ControlLease: &Lease{ID: "lease", Generation: 1}}
	e := &playwrightExecution{command: command, actor: actor, consent: binding}
	c := &channel{epoch: "channel", scopeHash: "scope", playwright: e, pending: map[string]*pending{"request": {playwright: true, command: command}}, unknown: map[string]bool{}}
	ctx := context.WithValue(auth.WithConsentBinding(auth.WithPrincipal(context.Background(), actor), binding), playwrightPrivacyKey{}, e)
	if privacyOperationIdleLocked(context.Background(), c) {
		t.Fatal("ordinary context bypassed in-flight privacy barrier")
	}
	if !privacyOperationIdleLocked(ctx, c) {
		t.Fatal("own admitted operation blocked privacy revalidation")
	}
	c.unknown["attempt"] = true
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("unknown without actual boundary granted privacy continuation")
	}
	e.inputPossible = true
	if !privacyOperationIdleLocked(ctx, c) {
		t.Fatal("own input receipt cannot complete privacy revalidation")
	}
	c.unknown["foreign"] = true
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("foreign unknown effect bypassed")
	}
	delete(c.unknown, "foreign")
	c.pending["foreign"] = &pending{}
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("foreign pending operation bypassed")
	}
	delete(c.pending, "foreign")
	next := identity
	next.Generation++
	if !playwrightOwnEffectIdentityLocked(ctx, c, identity, next, command.ControlLease) {
		t.Fatal("own DOM generation advance prevents receipt cleanup")
	}
	changedDocument := next
	changedDocument.DocumentID = "foreign"
	if playwrightOwnEffectIdentityLocked(ctx, c, identity, changedDocument, command.ControlLease) {
		t.Fatal("own effect tag followed replacement document")
	}
	older := identity
	older.Generation = 0
	if playwrightOwnEffectIdentityLocked(ctx, c, identity, older, command.ControlLease) {
		t.Fatal("generation rollback accepted")
	}
	if playwrightOwnEffectIdentityLocked(ctx, c, identity, next, &Lease{ID: "other", Generation: 2}) {
		t.Fatal("own effect changed original lease")
	}
	e.inputPossible = false
	delete(c.unknown, "attempt")
	if !playwrightOwnEffectIdentityLocked(ctx, c, identity, next, command.ControlLease) {
		t.Fatal("fresh semantic locator blocked by unrelated pre-input DOM drift")
	}
	originalLocator := e.command.Locator
	e.command.Locator = nil
	if playwrightOwnEffectIdentityLocked(ctx, c, identity, next, command.ControlLease) {
		t.Fatal("opaque snapshot reference accepted generation drift")
	}
	e.command.Locator = originalLocator
	retainedPending := c.pending["request"]
	delete(c.pending, "request")
	if playwrightOwnEffectIdentityLocked(ctx, c, identity, next, command.ControlLease) {
		t.Fatal("completed execution context retained authority")
	}
	c.pending["request"] = retainedPending
	e.inputPossible = true
	c.playwright = &playwrightExecution{command: command}
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("substituted operation bypassed")
	}
	c.playwright = e
	pendingOriginal := c.pending["request"].command
	for _, field := range []string{"attempt", "fingerprint", "lease", "epoch"} {
		bad := pendingOriginal
		switch field {
		case "attempt":
			bad.AttemptID = "foreign"
		case "fingerprint":
			bad.FingerprintSHA256 = strings.Repeat("b", 64)
		case "lease":
			bad.ControlLease = &Lease{ID: "other", Generation: 2}
		case "epoch":
			bad.ChannelEpoch = "other"
		}
		c.pending["request"].command = bad
		if privacyOperationIdleLocked(ctx, c) {
			t.Fatal("changed original receipt authority bypassed", field)
		}
	}
	c.pending["request"].command = pendingOriginal
	foreign := actor
	foreign.ClientID = "foreign"
	if privacyOperationIdleLocked(auth.WithPrincipal(ctx, foreign), c) {
		t.Fatal("foreign client in-flight context accepted")
	}
	changed := binding
	changed.SessionID = "other"
	if privacyOperationIdleLocked(auth.WithConsentBinding(ctx, changed), c) {
		t.Fatal("foreign session accepted")
	}
	e.revoked = true
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("revoked input bypassed privacy")
	}
}

func TestPlaywrightCDPPoliciesMatchCanonicalExtension(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	path, err := filepath.Abs("../../extension/chrome/playwright-relay.js")
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, "-e", `console.log(JSON.stringify([...require(process.argv[1]).methods].sort()))`, path).CombinedOutput()
	if err != nil {
		t.Fatal("canonical relay method policy unavailable")
	}
	var methods []string
	if json.Unmarshal(output, &methods) != nil {
		t.Fatal("canonical relay method list invalid")
	}
	for _, method := range methods {
		if !playwrightCDPMethod(method) {
			t.Fatalf("actual canonical relay method missing in Go: %s", method)
		}
	}
	for _, denied := range []string{"DOM.setFileInputFiles", "Browser.close", "Browser.getHistograms", "Target.createTarget", "Runtime.compileScript", "future.anything"} {
		if playwrightCDPMethod(denied) {
			t.Fatal("unexpected privateCDP policy widening", denied)
		}
	}
}

func TestPlaywrightSemanticControlContinuationPreservesExactAuthority(t *testing.T) {
	g, p, ctx, _ := controlFixtureVersion(t, 2)
	a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	binding, _ := auth.ConsentBindingFromContext(ctx)
	command := Command{Action: "element.press", Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, RequestID: "own-request", AttemptID: "own-attempt", Identity: a.Document.Identity, ControlLease: &a.Lease, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, FingerprintSHA256: strings.Repeat("a", 64)}
	e := &playwrightExecution{command: command, actor: p, consent: binding, conn: c.conn}
	g.broker.mu.Lock()
	c.playwright = e
	c.pending[command.RequestID] = &pending{playwright: true, command: command}
	c.documents[0].Generation++
	g.broker.mu.Unlock()
	semanticCtx := context.WithValue(ctx, playwrightPrivacyKey{}, e)
	if g.VerifyControl(ctx, p, a) == nil {
		t.Fatal("legacy context accepted generation drift")
	}
	if err = g.VerifyControl(semanticCtx, p, a); err != nil {
		t.Fatal("admitted semantic locator blocked by decorative inventory drift", err)
	}
	g.broker.mu.Lock()
	c.documents[0].Origin = "https://foreign.test"
	g.broker.mu.Unlock()
	if g.VerifyControl(semanticCtx, p, a) == nil {
		t.Fatal("semantic continuation changed origin")
	}
	g.broker.mu.Lock()
	c.documents[0].Origin = a.Document.Origin
	delete(c.pending, command.RequestID)
	c.playwright = nil
	g.broker.mu.Unlock()
	if g.VerifyControl(semanticCtx, p, a) == nil {
		t.Fatal("completed semantic execution retained authority")
	}
}

func TestPlaywrightFailureDetailsCannotExposeProviderOrCallbackContents(t *testing.T) {
	e := &playwrightExecution{started: time.Now(), callbackCount: 7, verifyCount: 3, verifyMS: 12, lastCallback: "PRIVATE_CALLBACK_CANARY", lastMethod: "PRIVATE_CDP_CANARY"}
	detail := e.failureDetails("PRIVATE_ERROR_CANARY")
	if strings.Contains(detail, "PRIVATE_") || !strings.Contains(detail, "phase=playwrightUnavailable") || !strings.Contains(detail, "callbacks=7; peerChecks=3; peerMs=12") || !strings.Contains(detail, "lastCallback=none; lastMethod=none") {
		t.Fatal("failure diagnostic is not closed/static")
	}
	e.lastCallback = "relay.send"
	e.lastMethod = "Runtime.enable"
	if detail = e.failureDetails("playwrightDeadline"); !strings.Contains(detail, "phase=playwrightDeadline") || !strings.Contains(detail, "lastCallback=relay.send; lastMethod=Runtime.enable") {
		t.Fatal("closed actionable failure phase missing")
	}
}

func TestPlaywrightScopedProcessProofChecksIdentityEveryCallbackAndFullTrustAtInput(t *testing.T) {
	p := principal(t, "scoped-cost")
	p.ClientID = "actor"
	grant := enrollment(p, "cost")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.fixtureOnly = false
	c.grant.TrustScope = TrustScopeProfile
	c.profileQualified = true
	c.scopeQualified = true
	c.executorQualified = true
	c.playwrightRelayVersion = 1
	c.mutationFingerprintVersion = 2
	c.processEvidence = &nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
	b.mu.Unlock()
	var full, identity, inputSeen atomic.Int32
	b.verifyPeer = func(ctx context.Context, _ *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		select {
		case <-time.After(30 * time.Millisecond):
			return *c.processEvidence, nil
		case <-ctx.Done():
			return nativepeer.ChromeProcessEvidence{}, ctx.Err()
		}
	}
	b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		identity.Add(1)
		return nil
	}
	b.playwright = playwrightTestClient(t, "known")
	go func() {
		for {
			raw, e := ReadFrame(conn)
			if e != nil {
				return
			}
			var in struct {
				Type, RequestID, RelayID, Method string
				Params                           json.RawMessage
			}
			json.Unmarshal(raw, &in)
			result := any(map[string]any{})
			switch in.Type {
			case "playwright.open":
				result = map[string]bool{"opened": true}
			case "playwright.receipt":
				result = map[string]bool{"persisted": true}
			case "playwright.close":
				result = map[string]bool{"closed": true}
			case "playwright.send":
				if playwrightInput(in.Method, in.Params) {
					inputSeen.Store(full.Load())
				}
			}
			WriteFrame(conn, map[string]any{"type": "playwright.result", "requestId": in.RequestID, "relayId": in.RelayID, "result": result})
		}
	}()
	ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 3*time.Second)
	defer cancel()
	lease := Lease{ID: "cost-lease", Generation: 1}
	command := Command{Action: "element.press", Identity: d.Identity, Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, AttemptID: strings.Repeat("a", 64), FingerprintVersion: 2, ControlLease: &lease}
	ctx = context.WithValue(ctx, playwrightControlCheckKey{}, func(checkCtx context.Context) error { return b.verifyChannelProcess(checkCtx, c) })
	started := time.Now()
	reply, err := b.callPrepared(ctx, c, command, true, func(Command) (BindingCommit, error) {
		return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	}, func() error { return b.verifyChannelProcess(ctx, c) })
	if err != nil || reply.DispatchState != "dispatched" {
		t.Fatal("scoped slow verifier operation failed", err)
	}
	if full.Load() != 5 || inputSeen.Load() != 5 || identity.Load() != 12 {
		t.Fatalf("full/identity boundary split changed: full=%d input=%d identity=%d", full.Load(), inputSeen.Load(), identity.Load())
	}
	t.Logf("fullChecks=%d fullCostMs>=150 identityChecks=%d elapsedMs=%d", full.Load(), identity.Load(), time.Since(started).Milliseconds())
}

func TestPlaywrightScopedProcessProofCannotSurviveEpochRevocationOrCompletion(t *testing.T) {
	for _, mode := range []string{"current", "epoch", "revoked", "completed", "noPending", "actor", "consent", "connection", "evidence", "foreignPending", "changedDuringProbe", "identityChanged"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, _ := controlFixtureVersion(t, 2)
			a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if err != nil {
				t.Fatal(err)
			}
			b := g.broker
			c := g.controlChannel(a)
			binding, _ := auth.ConsentBindingFromContext(ctx)
			command := Command{Action: "element.press", Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, RequestID: "scope-request", AttemptID: "scope-attempt", Identity: a.Document.Identity, ControlLease: &a.Lease, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}
			e := &playwrightExecution{command: command, actor: p, consent: binding, conn: c.conn, processEvidence: c.processEvidence}
			b.mu.Lock()
			c.playwright = e
			c.pending[command.RequestID] = &pending{playwright: true, command: command}
			switch mode {
			case "epoch":
				c.epoch = "replacement-epoch"
			case "noPending":
				delete(c.pending, command.RequestID)
			case "connection":
				e.conn = nil
			case "completed":
				c.playwright = nil
				delete(c.pending, command.RequestID)
			case "evidence":
				copy := *c.processEvidence
				c.processEvidence = &copy
			case "foreignPending":
				c.pending["foreign"] = &pending{}
			}
			b.mu.Unlock()
			if mode == "revoked" {
				e.revoked = true
			}
			probes := 0
			b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
				probes++
				if mode == "changedDuringProbe" {
					b.mu.Lock()
					c.scopeHash = "replaced-scope"
					b.mu.Unlock()
				}
				if mode == "identityChanged" {
					return errors.New("changed kernel identity")
				}
				return nil
			}
			scoped := context.WithValue(ctx, playwrightPrivacyKey{}, e)
			if mode == "actor" {
				other := p
				other.ClientID = "other-client"
				scoped = auth.WithPrincipal(scoped, other)
			}
			if mode == "consent" {
				other := binding
				other.SessionID = "other-session"
				scoped = auth.WithConsentBinding(scoped, other)
			}
			err = b.verifyChannelProcess(scoped, c)
			if mode == "current" {
				if err != nil || probes != 1 {
					t.Fatal("current scoped identity unavailable", err)
				}
			} else if err == nil {
				t.Fatal("stale private proof inherited authority", mode)
			}
			if mode != "current" && mode != "changedDuringProbe" && mode != "identityChanged" && probes != 0 {
				t.Fatal("invalid scope reached identity probe", mode)
			}
		})
	}
}

func TestPlaywrightReadPinnedScopedProofAvoidsPerCallbackFullSignatures(t *testing.T) {
	p := principal(t, "scoped-read-cost")
	p.ClientID = "actor"
	grant := enrollment(p, "read-cost")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.fixtureOnly = false
	c.grant.TrustScope = TrustScopeProfile
	c.profileQualified = true
	c.scopeQualified = true
	c.executorQualified = true
	c.playwrightRelayVersion = 1
	c.mutationFingerprintVersion = 2
	c.processEvidence = &nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
	b.mu.Unlock()
	var full, identity atomic.Int32
	b.verifyPeer = func(ctx context.Context, _ *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		select {
		case <-time.After(80 * time.Millisecond):
			return *c.processEvidence, nil
		case <-ctx.Done():
			return nativepeer.ChromeProcessEvidence{}, ctx.Err()
		}
	}
	b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		identity.Add(1)
		return nil
	}
	b.playwright = playwrightTestClient(t, "readKnown")
	go func() {
		for {
			raw, e := ReadFrame(conn)
			if e != nil {
				return
			}
			var in struct {
				Type, RequestID, RelayID, Method string
				Action                           string
				Identity                         Identity
			}
			json.Unmarshal(raw, &in)
			if in.Type == "" {
				WriteFrame(conn, Reply{RequestID: in.RequestID, Identity: in.Identity})
				continue
			}
			result := any(map[string]any{})
			switch in.Type {
			case "playwright.open":
				result = map[string]bool{"opened": true}
			case "playwright.redact":
				result = map[string]string{"value": "public ready"}
			case "playwright.close":
				result = map[string]bool{"closed": true}
			}
			WriteFrame(conn, map[string]any{"type": "playwright.result", "requestId": in.RequestID, "relayId": in.RelayID, "result": result})
		}
	}()
	g, e := NewGateway(b, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 3*time.Second)
	defer cancel()
	pin, e := g.captureReadBinding(ctx, p, c, d)
	if e != nil {
		t.Fatal(e)
	}
	target := model.Selector{Surface: model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()}, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "result"}, Exact: true}, Cardinality: "one"}
	start := time.Now()
	value, _, e := g.ReadPinned(ctx, p, pin, target, "text", nil)
	if e != nil || value.String != "public ready" {
		t.Fatal("actual readonly pin pipeline unavailable", e)
	}
	if identity.Load() != 50 {
		t.Fatalf("readonly pin callback did not use scoped identities: full=%d identity=%d", full.Load(), identity.Load())
	}
	if full.Load() != 11 {
		t.Fatalf("readonly initial/final full trust count changed: full=%d", full.Load())
	}
	t.Logf("readPinFullChecks=%d fixedFullCostMs>=%d identityChecks=%d elapsedMs=%d", full.Load(), full.Load()*80, identity.Load(), time.Since(start).Milliseconds())
}

func TestPlaywrightWorkerDenialSurvivesExchangeAndPrivateChild(t *testing.T) {
	for _, code := range []string{"playwrightDocumentChanged", "playwrightCDPDenied", "playwrightPRIVATE_CANARY"} {
		t.Run(code, func(t *testing.T) {
			p := principal(t, "closed-worker-denial")
			p.ClientID = "actor"
			grant := enrollment(p, "closed-denial")
			b := fixtureBroker(t, grant)
			conn := connectHost(t, b, grant)
			d := document(grant, 7)
			publish(t, b, conn, grant, d)
			proof := nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
			b.mu.Lock()
			c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
			c.fixtureOnly = false
			c.grant.TrustScope = TrustScopeProfile
			c.profileQualified = true
			c.scopeQualified = true
			c.executorQualified = true
			c.playwrightRelayVersion = 1
			c.mutationFingerprintVersion = 2
			c.processEvidence = &proof
			b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return proof, nil }
			b.mu.Unlock()
			b.playwright = playwrightTestClient(t, "readDenied")
			var opens atomic.Int32
			go func() {
				for {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var in struct{ Type, RequestID, RelayID string }
					if json.Unmarshal(raw, &in) != nil {
						return
					}
					if in.Type != "playwright.open" {
						return
					}
					opens.Add(1)
					WriteFrame(conn, map[string]any{"type": "playwright.result", "requestId": in.RequestID, "relayId": in.RelayID, "errorCode": code, "dispatchState": "notDispatched"})
				}
			}()
			ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 2*time.Second)
			defer cancel()
			reply, e := b.callPrepared(ctx, c, Command{Action: "read", Identity: d.Identity, Locator: &Locator{Strategy: "id", Value: "public-result", Exact: true}, Args: map[string]any{"attribute": "text"}}, false, nil)
			expected := code
			if strings.Contains(code, "PRIVATE") {
				expected = "playwrightHostDenied"
			}
			raw, _ := json.Marshal(reply)
			if e == nil || reply.Error == nil || reply.Error.Code != expected || reply.DispatchState != "notDispatched" || strings.Contains(string(raw), "PRIVATE") || opens.Load() != 1 {
				t.Fatal("worker denial masked or private value leaked", reply.Error, e)
			}
		})
	}
}
