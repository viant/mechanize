package chrome

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome/playwrightipc"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// Opt-in isolated HTTPS/headless fixture: actual Go sealed dispatch, hashed Node
// sidecar/Playwright and canonical worker/CDP relay execute together. ChromeAPI
// identity/storage and signed-peer facts are test adapters, not installed proof.
func TestIntegratedPlaywrightGoWorkerAndActualCDP(t *testing.T) {
	if os.Getenv("MECHANIZE_INTEGRATED_PW_FIXTURE") != "1" {
		t.Skip("isolated actual Playwright fixture explicitly enabled only")
	}
	node, e := exec.LookPath("node")
	if e != nil {
		t.Fatal(e)
	}
	node, e = filepath.EvalSymlinks(node)
	if e != nil {
		t.Fatal(e)
	}
	source, e := filepath.Abs("../../browser/playwright")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	packageCmd := exec.CommandContext(ctx, node, filepath.Join(source, "package-runtime.mjs"), runtimeRoot)
	if output, e := packageCmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture runtime packaging failed: %v (%d output bytes)", e, len(output))
	}
	runtimeRoot, e = filepath.EvalSymlinks(runtimeRoot)
	if e != nil {
		t.Fatal(e)
	}
	nodeBytes, e := os.ReadFile(node)
	if e != nil {
		t.Fatal(e)
	}
	nodeSum := sha256.Sum256(nodeBytes)
	tree, e := playwrightipc.RuntimeDigest(runtimeRoot)
	if e != nil {
		t.Fatal(e)
	}
	local, e := playwrightipc.New(playwrightipc.Config{NodePath: node, NodeSHA256: hex.EncodeToString(nodeSum[:]), RuntimeRoot: runtimeRoot, RuntimeSHA256: tree})
	if e != nil {
		t.Fatal(e)
	}
	driver := exec.CommandContext(ctx, node, filepath.Join(source, "test/native-fixture-peer.mjs"))
	driver.Dir = source
	input, e := driver.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := driver.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	driver.Stderr = os.Stderr
	if e = driver.Start(); e != nil {
		t.Fatal(e)
	}
	var inputMu sync.Mutex
	var maxNativeOutbound atomic.Int64
	writeDriver := func(value any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			return e
		}
		inputMu.Lock()
		defer inputMu.Unlock()
		if int64(len(raw)) > maxNativeOutbound.Load() {
			maxNativeOutbound.Store(int64(len(raw)))
		}
		_, e = input.Write(append(raw, 10))
		return e
	}
	defer func() { _ = writeDriver(map[string]string{"type": "fixture.stop"}); input.Close(); driver.Wait() }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 512*1024+1)
	readFixture := func(expected string) Document {
		t.Helper()
		if !scanner.Scan() {
			t.Fatal("fixture readiness frame unavailable")
		}
		var frame struct {
			Type         string   `json:"type"`
			Document     Document `json:"document"`
			PrivacyReady bool     `json:"privacyReady"`
		}
		if json.Unmarshal(scanner.Bytes(), &frame) != nil || frame.Type != expected || expected == "fixture.private-ready" && !frame.PrivacyReady {
			t.Fatal("independent fixture privacy readiness unavailable")
		}
		return frame.Document
	}
	document := readFixture("fixture.ready")
	if e = writeDriver(map[string]string{"type": "fixture.private-login"}); e != nil {
		t.Fatal(e)
	}
	document = readFixture("fixture.private-ready")
	p := principal(t, "integrated-playwright")
	p.ClientID = "fixture-client"
	consent := auth.ConsentBinding{SessionID: "fixture-session", GrantID: "fixture-grant", Purpose: "isolated integration"}
	held := auth.WithConsentBinding(auth.WithPrincipal(ctx, p), consent)
	grant := enrollment(p, document.ProfileChannel)
	grant.BrowserInstance = document.BrowserInstance
	grant.Origins = []string{document.Origin}
	broker := fixtureBroker(t, grant)
	peer := connectHost(t, broker, grant)
	initial := document
	initial.MutationFingerprintVersion = 0
	publish(t, broker, peer, grant, initial)
	gateway, e := NewGateway(broker, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	broker.mu.Lock()
	channel := broker.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	channel.fixtureOnly = false
	channel.grant.TrustScope = TrustScopeProfile
	channel.profileQualified = true
	channel.scopeQualified = true
	channel.executorQualified = true
	channel.playwrightRelayVersion = 1
	channel.playwrightLocatorVersion = 1
	channel.controlBadgeVersion = 1
	var badgesStarted, badgesEnded atomic.Int64
	broker.controlBadge = func(ctx context.Context, actor auth.Principal, process session.ProcessIdentity, window ControlBadgeWindow) func() {
		if actor.ClientID != p.ClientID || !window.valid() {
			t.Error("badge did not retain admitted actor and bounded geometry")
		}
		badgesStarted.Add(1)
		return func() { badgesEnded.Add(1) }
	}
	channel.mutationFingerprintVersion = 2
	evidence := &nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
	channel.processEvidence = evidence
	broker.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return *evidence, nil }
	broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error { return nil }
	broker.playwright = local
	channel.documents[0].MutationFingerprintVersion = 2
	document = channel.documents[0]
	authority := ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, Document: document, ExtensionOrigin: grant.ExtensionOrigin, BrokerEpoch: broker.epoch, ChannelEpoch: channel.epoch, ScopeHash: channel.scopeHash, TrustScope: TrustScopeProfile, ScopeQualified: true, ProfileQualified: true, MutationFingerprintVersion: 2, Evidence: *evidence, Lease: Lease{ID: "fixture-lease", Generation: 1}}
	channel.privacy = &credentialPrivacyState{gateway: gateway, channel: channel, conn: channel.conn, source: authority, authority: authority, binding: consent, identity: document.Identity, permitID: "fixture-privacy-revision", active: true, published: true, admit: func(context.Context) error { return nil }}
	channel.privacy.published = false
	broker.mu.Unlock()
	deniedCommand := Command{Action: "element.fill", Identity: document.Identity, Locator: &Locator{Strategy: "id", Value: "filter", Exact: true}, Args: map[string]any{"value": "group-blue"}, AttemptID: strings.Repeat("z", 64), FingerprintVersion: 2, ControlLease: &authority.Lease}
	if _, err := broker.callPrepared(held, channel, deniedCommand, true, func(Command) (BindingCommit, error) {
		t.Fatal("unpublished privacy reached intent commit")
		return BindingCommit{}, nil
	}); err == nil {
		t.Fatal("fixture claimed readiness bypassed independent Go privacy publication")
	}
	broker.mu.Lock()
	channel.privacy.published = true
	broker.mu.Unlock()
	fixtureFrames := make(chan json.RawMessage, 8)
	var traceMu sync.Mutex
	trace := []string{}
	go func() {
		for scanner.Scan() {
			raw := append(json.RawMessage(nil), scanner.Bytes()...)
			var frame struct {
				Type string `json:"type"`
			}
			json.Unmarshal(raw, &frame)
			var diagnostic struct {
				ErrorCode string `json:"errorCode"`
			}
			json.Unmarshal(raw, &diagnostic)
			traceMu.Lock()
			trace = append(trace, "response:"+frame.Type+":"+safePlaywrightError(diagnostic.ErrorCode))
			traceMu.Unlock()
			if strings.HasPrefix(frame.Type, "fixture.") {
				fixtureFrames <- raw
			} else {
				if WriteFrame(peer, json.RawMessage(raw)) != nil {
					return
				}
			}
		}
		close(fixtureFrames)
	}()
	go func() {
		for {
			raw, e := ReadFrame(peer)
			if e != nil {
				return
			}
			var diagnostic struct {
				Type   string `json:"type"`
				Method string `json:"method"`
			}
			json.Unmarshal(raw, &diagnostic)
			traceMu.Lock()
			trace = append(trace, "request:"+diagnostic.Type+":"+diagnostic.Method)
			traceMu.Unlock()
			var value any
			if json.Unmarshal(raw, &value) != nil {
				return
			}
			if writeDriver(value) != nil {
				return
			}
		}
	}()
	control := func(kind string) json.RawMessage {
		t.Helper()
		if writeDriver(map[string]string{"type": kind}) != nil {
			t.Fatal("fixture control unavailable")
		}
		select {
		case raw := <-fixtureFrames:
			return raw
		case <-ctx.Done():
			t.Fatal("fixture control timed out")
		}
		return nil
	}
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
	opened, err := runtime.Open(held, "actual-playwright-fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.StartPlan(held, opened.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{controlStep(t)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case runCtx := <-captured:
		held = auth.WithConsentBinding(auth.WithPrincipal(runCtx, p), consent)
	case <-ctx.Done():
		t.Fatal("Endly fixture context unavailable")
	}
	defer func() { close(release); runtime.Close(ctx, opened.SessionID) }()
	var lastPin ReadBinding
	call := func(action, target string, args map[string]any, attempt string, indices ...int) Reply {
		t.Helper()
		operationCtx, operationCancel := context.WithTimeout(held, 8*time.Second)
		defer operationCancel()
		selector := model.Selector{Surface: model.Surface{Kind: "web", Origin: document.Origin, TabID: document.QualifiedTabID()}, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: target}, Exact: true}, Cardinality: "one"}
		if len(indices) == 1 {
			index := indices[0]
			role := "button"
			if action == "read" {
				role = "region"
			}
			name := model.Value{Kind: model.StringValue, String: target}
			selector.Locator = &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: role}, Name: &name, Exact: true}
			selector.Cardinality = "nth"
			selector.Index = &index
			selector.Order = "document"
		}
		fail := func(e error) {
			traceMu.Lock()
			start := len(trace) - 20
			if start < 0 {
				start = 0
			}
			t.Logf("last closed integration phases: %v", trace[start:])
			traceMu.Unlock()
			t.Fatalf("combined typed %s failed: %v", action, e)
		}
		if action == "read" {
			value, _, e := gateway.ReadPinned(operationCtx, p, lastPin, selector, "text", nil)
			if e != nil {
				if target == "review-result" && strings.HasPrefix(e.Error(), "attributeUnavailable:") {
					redacted := "[redacted]"
					return Reply{Value: &redacted}
				}
				fail(e)
			}
			return Reply{Value: &value.String}
		}
		admission, e := gateway.AdmitControlWithStatus(operationCtx, p, selector.Surface)
		if e != nil {
			fail(e)
		}
		pin, e := gateway.PinControlRead(operationCtx, p, admission.Authority)
		if e != nil {
			fail(e)
		}
		lastPin = pin
		step := model.Step{ID: "actual-" + attempt[:4], Action: action, Target: selector, TimeoutMs: 8000, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Arguments: map[string]model.Value{}}
		if action == "element.fill" {
			step.Arguments["value"] = model.Value{Kind: model.StringValue, String: args["value"].(string)}
		}
		reply, e := gateway.ExecuteControlBound(operationCtx, p, step, nil, admission.Authority, attempt, func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
			return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
		})
		if e != nil {
			fail(e)
		}
		if reply.DispatchState != "dispatched" {
			t.Fatal("actual input receipt unavailable")
		}
		retired, e := gateway.RetireControl(operationCtx, p, admission.Authority)
		if e != nil || !retired {
			fail(e)
		}
		return Reply{DispatchState: reply.DispatchState}
	}
	control("fixture.arm-timer")
	call("element.fill", "filter", map[string]any{"value": "group-blue"}, strings.Repeat("a", 64))
	timerRaw := control("fixture.stop-timer")
	var timerState struct {
		Type         string `json:"type"`
		Publications int    `json:"timerPublications"`
	}
	if json.Unmarshal(timerRaw, &timerState) != nil || timerState.Publications < 1 {
		t.Fatalf("decorative timer publications unavailable: type=%s count=%d", timerState.Type, timerState.Publications)
	}
	control("fixture.arm-delayed-target")
	call("element.press", "Expand current row", nil, strings.Repeat("c", 64), 0)
	control("fixture.stop-timer")
	detailsA := call("read", "Expanded record", map[string]any{"attribute": "text"}, "", 0)
	if detailsA.Value == nil || !strings.Contains(*detailsA.Value, "Record A group-blue") {
		t.Fatal("fresh first expanded record did not match expected row")
	}
	call("element.press", "Select current row", nil, strings.Repeat("d", 64), 0)
	call("element.press", "Expand current row", nil, strings.Repeat("e", 64), 1)
	detailsB := call("read", "Expanded record", map[string]any{"attribute": "text"}, "", 1)
	if detailsB.Value == nil || !strings.Contains(*detailsB.Value, "Record B group-blue") {
		t.Fatal("fresh second expanded record did not match expected row")
	}
	call("element.press", "Select current row", nil, strings.Repeat("f", 64), 1)
	call("element.press", "Expand current row", nil, strings.Repeat("1", 64), 0)
	call("element.press", "Expand current row", nil, strings.Repeat("2", 64), 0)
	call("element.press", "review", nil, strings.Repeat("3", 64))
	ready := call("read", "ready", map[string]any{"attribute": "text"}, "")
	if ready.Value == nil || *ready.Value != "SPA ready" {
		t.Fatal("real Playwright text read failed")
	}

	reflected := control("fixture.reflect")
	var reflection struct {
		Identity Identity `json:"identity"`
	}
	if json.Unmarshal(reflected, &reflection) != nil || reflection.Identity.DocumentID != document.DocumentID || reflection.Identity.TabID != document.TabID || reflection.Identity.Generation < document.Generation {
		t.Fatal("fixture reflection identity unavailable")
	}
	// The test driver's output pipe and the broker's framed reader are separate
	// lanes. A driver acknowledgment alone does not prove inventory application.
	waitControl(t, func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		for _, d := range channel.documents {
			if sameReadDocument(d, document) && d.Generation >= reflection.Identity.Generation {
				return true
			}
		}
		return false
	})
	review := call("read", "review-result", map[string]any{"attribute": "text"}, "")
	if review.Value == nil || *review.Value != "[redacted]" {
		t.Fatal("reflected private value was not denied by protected read")
	}

	raw := control("fixture.peek")
	var state struct {
		ReviewMatched       bool `json:"reviewMatched"`
		InputCount          int  `json:"inputCount"`
		MaxNativeFrameBytes int  `json:"maxNativeFrameBytes"`
		UnknownCount        int  `json:"unknownCount"`
	}
	if json.Unmarshal(raw, &state) != nil || !state.ReviewMatched || state.InputCount != 8 || state.UnknownCount != 0 || state.MaxNativeFrameBytes > 512*1024 || maxNativeOutbound.Load() <= 256*1024 || maxNativeOutbound.Load() > 512*1024 {
		t.Fatal("combined fixture outcome or receipt changed")
	}
	broker.mu.Lock()
	receipts := len(channel.receipts)
	unknown := len(channel.unknown)
	broker.mu.Unlock()
	if receipts != 8 || unknown != 0 {
		t.Fatal("Go canonical original-attempt receipt history unavailable")
	}
	// A lost actual input acknowledgement must remain unknown at the original
	// durable attempt. The same attempt is never replayed to obtain a receipt.
	control("fixture.lose-next-input")
	failureTarget := model.Selector{Surface: model.Surface{Kind: "web", Origin: document.Origin, TabID: document.QualifiedTabID()}, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "review"}, Exact: true}, Cardinality: "one"}
	failureAdmission, e := gateway.AdmitControlWithStatus(held, p, failureTarget.Surface)
	if e != nil {
		t.Fatal(e)
	}
	failureStep := model.Step{ID: "lost-original", Action: "element.press", Target: failureTarget, TimeoutMs: 3000, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Arguments: map[string]model.Value{}}
	commit := func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	}
	lostAttempt := strings.Repeat("9", 64)
	lost, e := gateway.ExecuteControlBound(held, p, failureStep, nil, failureAdmission.Authority, lostAttempt, commit)
	if e == nil || lost.DispatchState != "unknown" {
		t.Fatalf("lost actual input not retained as unknown: %s", lost.DispatchState)
	}
	broker.mu.Lock()
	retainedUnknown := channel.unknown[lostAttempt]
	broker.mu.Unlock()
	if !retainedUnknown {
		t.Fatal("original lost input history erased")
	}
	_, e = gateway.ExecuteControlBound(held, p, failureStep, nil, failureAdmission.Authority, lostAttempt, commit)
	if e == nil {
		t.Fatal("unknown original attempt replayed")
	}
	raw = control("fixture.peek")
	if json.Unmarshal(raw, &state) != nil || state.InputCount != 9 || state.UnknownCount != 1 {
		t.Fatal("lost input was replayed or uncertainty erased")
	}
	if badgesStarted.Load() == 0 || badgesStarted.Load() != badgesEnded.Load() {
		t.Fatalf("badge lifecycle mismatch: start=%d end=%d", badgesStarted.Load(), badgesEnded.Load())
	}
	t.Logf("actual Go↔sidecar↔worker↔CDP fixture:8 original mutation receipts, post-login redaction verified, native envelopes request %d/response %d bytes; ninth lost input not replayed", maxNativeOutbound.Load(), state.MaxNativeFrameBytes)
}
