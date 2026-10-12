package chrome

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
)

// Opt-in fixture: a disposable full Chrome profile loads the actual extension
// worker and isolated content scripts. Only native transport and process trust
// are fixture adapters; private handoff, Vault, and ordinary admission are real.
func TestRealChromeClassifiedPublicReadRetainsPrivateSource(t *testing.T) {
	t.Setenv("MECHANIZE_CLASSIFIED_PUBLIC_READ", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}

func TestRealChromeVisibilityUnknownAllowsFreshDOM(t *testing.T) {
	t.Setenv("MECHANIZE_VISIBILITY_UNKNOWN", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}

func TestRealChromeLegacyExecutorInspectionDiagnostic(t *testing.T) {
	t.Setenv("MECHANIZE_PRIVATE_DIAGNOSTIC_FIXTURE", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}

func TestRealChromeScopedProtectionIndependentTabAndNewLogin(t *testing.T) {
	t.Setenv("MECHANIZE_PRIVATE_SCOPED_RECOVERY", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}

func TestRealChromeOrdinaryLeaseAdmissionGenerationRetry(t *testing.T) {
	t.Setenv("MECHANIZE_ORDINARY_ACQUIRE_DRIFT", "2")
	testRealChromeCredentialPrivacyHandoff(t, false)
}

func TestRealChromeCredentialPrivacyHandoffWithoutSpeculativeLease(t *testing.T) {
	testRealChromeCredentialPrivacyHandoff(t, false)
}
func TestRealChromeManualPrivacyAfterDisconnect(t *testing.T) {
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_RECOVERY", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}
func TestRealChromeManualPrivacySameTabNewDocument(t *testing.T) {
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_RECOVERY", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_SAME_TAB", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}
func TestRealChromeManualPrivacyAllWebsitesSameTabNewDocument(t *testing.T) {
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_ALL_WEBSITES", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_RECOVERY", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_SAME_TAB", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}
func TestRealChromeManualSuccessorRetirement(t *testing.T) {
	t.Setenv("MECHANIZE_MANUAL_SUCCESSOR_RECOVERY", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_ALL_WEBSITES", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_RECOVERY", "1")
	t.Setenv("MECHANIZE_PRIVATE_MANUAL_SAME_TAB", "1")
	testRealChromeCredentialPrivacyHandoff(t, false)
}
func TestRealChromeArchivedCredentialPreflight(t *testing.T) {
	for _, mode := range []string{"", "decoration", "replacement", "route", "challenge", "expired", "always"} {
		t.Run("drift-"+mode, func(t *testing.T) {
			t.Setenv("MECHANIZE_PRIVATE_GENERATION_RACE", mode)
			testRealChromeCredentialPrivacyHandoff(t, true)
		})
	}
}
func testRealChromeCredentialPrivacyHandoff(t *testing.T, archived bool) {
	if os.Getenv("MECHANIZE_PRIVACY_CHROME_FIXTURE") != "1" {
		t.Skip("isolated real-Chrome privacy fixture requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	driver := exec.CommandContext(ctx, "node", "../../browser/playwright/test/privacy-handoff-peer.mjs")
	if archived {
		driver.Env = append(os.Environ(), "MECHANIZE_PRIVATE_ARCHIVE_FIXTURE=1")
	}
	driver.Stderr = os.Stderr
	input, err := driver.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := driver.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = driver.Start(); err != nil {
		t.Fatal(err)
	}
	var writes sync.Mutex
	send := func(value any) error {
		writes.Lock()
		defer writes.Unlock()
		return json.NewEncoder(input).Encode(value)
	}
	defer func() { _ = send(map[string]string{"type": "fixture.stop"}); input.Close(); driver.Wait() }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 512*1024)
	if !scanner.Scan() {
		t.Fatal("isolated extension did not start")
	}
	var ready struct {
		Type, Origin, ExtensionOrigin string
		Diagnostic                    json.RawMessage
	}
	if json.Unmarshal(scanner.Bytes(), &ready) != nil || ready.Type != "fixture.ready" {
		t.Fatal("fixture metadata unavailable")
	}
	t.Logf("fixture startup closed metadata: %s", ready.Diagnostic)
	p := principal(t, "privacy-real-chrome")
	p.ClientID = "privacy-fixture-client"
	consent := auth.ConsentBinding{SessionID: "privacy-fixture-session", GrantID: "privacy-fixture-grant", Purpose: "credential"}
	held := auth.WithConsentBinding(auth.WithPrincipal(ctx, p), consent)
	directory, err := os.MkdirTemp("/private/tmp", "privacy-chrome-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := nativepeer.ChromeProcessEvidence{NativeHost: session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/native", StartToken: "host"}, ChromeParent: session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/fixture/chrome", StartToken: "browser"}, KernelPeerQualified: true}
	evidence.Ancestors = []session.ProcessIdentity{evidence.ChromeParent}
	grant := Enrollment{Principal: p, ProfileChannel: "fixture", BrowserInstance: "isolated", ExtensionOrigin: ready.ExtensionOrigin, Origins: []string{ready.Origin}, ProfileDirectory: directory}
	if os.Getenv("MECHANIZE_PRIVATE_MANUAL_ALL_WEBSITES") == "1" {
		grant.AllWebsites, grant.Origins = true, nil
	}

	var badgeStarts, badgeEnds atomic.Int64
	credential := strings.Repeat("x", 64)
	broker, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(directory, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("fixture", "isolated"): credential}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return evidence, nil })
	if err != nil {
		t.Fatal(err)
	}
	broker.controlBadge = func(_ context.Context, actor auth.Principal, _ session.ProcessIdentity, window ControlBadgeWindow) func() {
		if actor.ClientID != p.ClientID || !window.valid() {
			t.Error("private badge authority unavailable")
		}
		badgeStarts.Add(1)
		return func() { badgeEnds.Add(1) }
	}
	defer func() { broker.Close() }()
	peer, err := net.Dial("unix", broker.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if peer != nil {
			peer.Close()
		}
	}()
	var peerMu sync.Mutex
	if !scanner.Scan() {
		t.Fatal("worker hello unavailable")
	}
	var hello map[string]any
	if json.Unmarshal(scanner.Bytes(), &hello) != nil || hello["type"] != "hello" {
		t.Fatal("worker hello invalid")
	}
	hello["extensionOrigin"] = ready.ExtensionOrigin
	hello["credential"] = credential
	hello["profileDirectory"] = directory
	hello["profileLaunchQualified"] = true
	if err = WriteFrame(peer, hello); err != nil {
		t.Fatal(err)
	}
	states := make(chan json.RawMessage, 4)
	faults := make(chan struct{}, 1)
	hellos := make(chan json.RawMessage, 2)
	readPeer := func(connection net.Conn) {
		go func() {
			for {
				raw, e := ReadFrame(connection)
				if e != nil {
					return
				}
				if send(json.RawMessage(raw)) != nil {
					return
				}
			}
		}()
	}
	readPeer(peer)
	go func() {
		for scanner.Scan() {
			raw := append(json.RawMessage(nil), scanner.Bytes()...)
			var kind struct{ Type string }
			if json.Unmarshal(raw, &kind) != nil {
				return
			}
			if kind.Type == "hello" {
				hellos <- raw
				continue
			}
			if kind.Type == "fixture.state" {
				states <- raw
				continue
			}
			if kind.Type == "fixture.failure" {
				select {
				case faults <- struct{}{}:
				default:
				}
				return
			}
			peerMu.Lock()
			var e error
			if peer != nil {
				e = WriteFrame(peer, json.RawMessage(raw))
			}
			peerMu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	var c *channel
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		broker.mu.Lock()
		c = broker.channels[channelKey("fixture", "isolated")]
		qualified := c != nil && c.executorQualified && c.inventoryComplete && (len(c.documents) == 1 || archived && len(c.credentialCandidates) == 1)
		broker.mu.Unlock()
		if qualified {
			break
		}
		select {
		case <-faults:
			t.Fatal("isolated worker exchange unavailable")
		case <-time.After(10 * time.Millisecond):
		}
	}
	broker.mu.Lock()
	qualified := c != nil && c.executorQualified && c.inventoryComplete && (len(c.documents) == 1 || archived && len(c.credentialCandidates) == 1)
	broker.mu.Unlock()
	if !qualified {
		t.Fatal("actual worker executor qualification unavailable")
	}
	gateway, err := NewGateway(broker, GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allow := func(context.Context) error { return nil }
	surface := model.Surface{Kind: "web", Origin: ready.Origin}
	admitted, err := gateway.AdmitCredentialControl(held, p, surface, allow)
	if os.Getenv("MECHANIZE_PRIVATE_DIAGNOSTIC_FIXTURE") == "1" {
		if err == nil || admitted.Confirmed || admitted.FailureStage != "inspection" || admitted.FailureReason != "ambiguousSubmitter" {
			t.Fatalf("legacy executor diagnostic failed: phase=%s reason=%s", admitted.FailureStage, admitted.FailureReason)
		}
		if send(map[string]string{"type": "fixture.state"}) != nil {
			t.Fatal("diagnostic counters unavailable")
		}
		select {
		case raw := <-states:
			var counts map[string]any
			json.Unmarshal(raw, &counts)
			if counts["privateFill"] != float64(0) || counts["privateSubmit"] != float64(0) || counts["submits"] != float64(0) {
				t.Fatal("diagnostic dispatched input")
			}
		case <-ctx.Done():
			t.Fatal("diagnostic fixture expired")
		}
		t.Log("actual Chrome: old injected executor retained, new helper loaded, exact ambiguousSubmitter cause reached broker, zero fill/submit")
		return
	}
	if archived {
		mode := os.Getenv("MECHANIZE_PRIVATE_GENERATION_RACE")
		deny := mode != "" && mode != "decoration"
		if deny {
			if err == nil || admitted.Confirmed {
				t.Fatal("changed or unstable private recipient admitted")
			}
		} else if err != nil || !admitted.Confirmed {
			t.Fatalf("private admission failed at %s", admitted.FailureStage)
		}
		if send(map[string]string{"type": "fixture.state"}) != nil {
			t.Fatal("fixture counters unavailable")
		}
		select {
		case raw := <-states:
			var counts map[string]any
			if json.Unmarshal(raw, &counts) != nil || counts["privateFill"] != float64(0) || counts["privateSubmit"] != float64(0) || counts["submits"] != float64(0) {
				t.Fatal("preflight caused credential input")
			}
			expectedAcquires := float64(1)
			if mode == "decoration" {
				expectedAcquires = 2
			}
			if mode == "always" {
				expectedAcquires = 3
			}
			if counts["acquire"] != expectedAcquires {
				t.Fatal("private acquisition did not retain its exact retry budget")
			}

		case <-ctx.Done():
			t.Fatal("fixture counters timed out")
		}
		t.Logf("archive rollover → new quarantined login preflight: drift=%q denied=%t; zero credential input", mode, deny)
		return
	}
	if err != nil || !admitted.Confirmed {
		t.Fatalf("private admission failed at %s", admitted.FailureStage)
	}
	authority := admitted.Authority
	capturedScope, captureError := gateway.CaptureCredentialProtectionScope(held, p, authority, strings.Repeat("e", 64))
	if captureError != nil || capturedScope.LoginRouteSHA256 == "" {
		t.Fatalf("exact private source scope capture failed: %v", captureError)
	}
	store, err := vault.NewStore(filepath.Join(directory, "vault"), "fixture-v1", &vault.Cipher{Keys: credentialFixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	humanPrincipal := p
	humanPrincipal.Scopes = append(append([]string(nil), p.Scopes...), "consent:admin")
	human, err := auth.WithNativeHuman(auth.WithPrincipal(held, humanPrincipal))
	if err != nil {
		t.Fatal(err)
	}
	target := vault.Target{Origin: ready.Origin, Account: "synthetic-account"}
	ref, err := store.Create(human, target, []byte("fixture-user-canary"), []byte("fixture-password-canary"))
	if err != nil {
		t.Fatal("synthetic Vault setup unavailable")
	}
	selected, err := store.Metadata(human, target)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := vault.NewManager(store, vault.Hooks{Present: func(context.Context, vault.Request) error { return errors.New("unexpected fixture presentation") }, Resume: func(context.Context, vault.Binding, vault.Reference) error {
		return errors.New("unexpected fixture resume")
	}, Fresh: func(ctx context.Context, value vault.Binding) (vault.Binding, error) {
		return gateway.FreshCredentialBinding(ctx, p, authority, value, allow)
	}})
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.Binding{SessionID: consent.SessionID, DocumentID: authority.Document.DocumentID, NavigationID: CredentialNavigationID(authority), Target: target}
	fill, submit := strings.Repeat("b", 64), strings.Repeat("c", 64)
	beforeFillBadge := badgeStarts.Load()
	result, err := gateway.DeliverVaultCredential(held, p, authority, fill, manager, binding, ref, selected.Revision, allow)
	if err != nil || result.DispatchState != "dispatched" {
		t.Fatalf("private fill failed at %s", result.FailureStage)
	}
	if badgeStarts.Load() <= beforeFillBadge {
		t.Fatal("private fill badge missing")
	}
	if os.Getenv("MECHANIZE_CLASSIFIED_PUBLIC_READ") == "1" {
		change := func(kind string) {
			t.Helper()
			if send(map[string]string{"type": kind}) != nil {
				t.Fatal("fixture command unavailable")
			}
			select {
			case <-states:
			case <-ctx.Done():
				t.Fatal("fixture command expired")
			}
		}
		change("fixture.publicReadSPA")
		surface := model.Surface{Kind: "web", Origin: ready.Origin, TabID: authority.Document.QualifiedTabID()}
		readCtx, e := gateway.WithVerifiedCredentialPublicRead(held, p, surface)
		if e != nil {
			t.Fatalf("same-document public classification: %v", e)
		}
		observed, e := gateway.Observe(readCtx, p, surface)
		if e != nil {
			t.Fatalf("classified public observe: %v", e)
		}
		payload, _ := json.Marshal(observed)
		if strings.Contains(string(payload), "fixture-password-canary") || strings.Contains(string(payload), "fixture-user-canary") {
			t.Fatal("private value reached public observation")
		}
		pin, e := gateway.PinReadDocument(readCtx, p, surface)
		if e != nil {
			t.Fatal(e)
		}
		selector := model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "public-result"}, Exact: true}}
		value, _, e := gateway.ReadPinned(readCtx, p, pin, selector, "text", nil)
		if e != nil {
			t.Fatalf("classified public read: %v", e)
		}
		if value.String != "Public ready" {
			t.Fatal("public text read mismatch")
		}
		selector.Locator.Value.String = "public-canary"
		hidden, _, hiddenErr := gateway.ReadPinned(readCtx, p, pin, selector, "text", nil)
		if strings.Contains(hidden.String, "fixture-password-canary") || hiddenErr == nil && hidden.String != "[redacted]" {
			t.Fatal("reflected private canary reached public read")
		}
		broker.mu.Lock()
		retained := broker.channels[channelKey("fixture", "isolated")].privateFlow != nil
		broker.mu.Unlock()
		if !retained {
			t.Fatal("read classification erased private source")
		}
		change("fixture.publicReadLogin")
		if _, e = gateway.WithVerifiedCredentialPublicRead(held, p, surface); e == nil {
			t.Fatal("login return classified public")
		}
		if e = send(map[string]string{"type": "fixture.state"}); e != nil {
			t.Fatal(e)
		}
		select {
		case raw := <-states:
			var counts map[string]any
			json.Unmarshal(raw, &counts)
			if counts["privateFill"] != float64(1) || counts["privateSubmit"] != float64(0) || counts["submits"] != float64(0) {
				t.Fatal("classified read replayed private input")
			}
		case <-ctx.Done():
			t.Fatal("fixture state expired")
		}
		t.Log("actual worker/broker: private fill retained; same-document public observe/read redact canary; login return denies; zero submit or replay")
		return
	}
	beforeSubmitBadge := badgeStarts.Load()
	result, err = gateway.SubmitVaultCredential(held, p, authority, fill, submit, allow)
	if err != nil || result.DispatchState != "dispatched" {
		t.Fatal("private submit unavailable")
	}
	if badgeStarts.Load() <= beforeSubmitBadge {
		t.Fatal("private submit badge missing")
	}
	_, err = gateway.AdvanceVaultCredential(held, p, authority, submit, allow)
	if !errors.Is(err, ErrCredentialPrivacyCandidate) {
		t.Fatal("same-document privacy candidate unavailable")
	}
	state := func() map[string]int {
		t.Helper()
		if send(map[string]string{"type": "fixture.state"}) != nil {
			t.Fatal("fixture state unavailable")
		}
		select {
		case raw := <-states:
			var result map[string]json.RawMessage
			json.Unmarshal(raw, &result)
			counts := map[string]int{}
			for _, key := range []string{"acquire", "retire", "validate", "privateFill", "privateSubmit", "submits", "activation", "ordinaryClicks"} {
				var count int
				json.Unmarshal(result[key], &count)
				counts[key] = count
			}
			return counts
		case <-ctx.Done():
			t.Fatal("fixture state expired")
			return nil
		}
	}
	before := state()
	proof, err := gateway.QualifyCredentialPrivacy(held, p, authority, submit, allow)
	if err != nil {
		t.Fatalf("private handoff failed: %s", CredentialPrivacyFailureCode(err))
	}
	routing, ok := proof.Authority()
	if !ok || routing.Lease != (Lease{}) {
		t.Fatal("privacy proof must not grant a dispatch lease")
	}
	after := state()
	if after["acquire"] != before["acquire"] || after["retire"] != before["retire"] || after["validate"] != before["validate"] {
		t.Fatal("privacy handoff speculatively acquired ordinary control")
	}
	if os.Getenv("MECHANIZE_PRIVATE_MANUAL_RECOVERY") == "1" {
		commandState := func(kind string) map[string]json.RawMessage {
			t.Helper()
			if send(map[string]string{"type": kind}) != nil {
				t.Fatal("fixture command unavailable")
			}
			select {
			case raw := <-states:
				var v map[string]json.RawMessage
				if json.Unmarshal(raw, &v) != nil {
					t.Fatal("fixture state unavailable")
				}
				return v
			case <-faults:
				t.Fatal("fixture command failed: " + kind)
				return nil
			case <-time.After(12 * time.Second):
				t.Fatal("fixture command timeout: " + kind)
				return nil
			case <-ctx.Done():
				t.Fatal("fixture state expired")
				return nil
			}
		}
		originalSource := ManualCredentialSource{Identity: authority.Document.Identity, Origin: ready.Origin, ChromeBirth: evidence.ChromeParent.StartToken}
		unexpected, e := gateway.BeginManualCredentialPrivacy(held, p, originalSource, allow)
		if unexpected != nil {
			unexpected.Abort()
		}
		if e == nil {
			t.Fatal("present original tab was falsely retired")
		}
		if gateway.VerifyCredentialPrivacy(held, p, proof, surface, false) != nil {
			t.Fatal("safe original-present refusal destroyed previous redactor/channel")
		}
		replacementCommand := "fixture.manualReplacement"
		sameTab := os.Getenv("MECHANIZE_PRIVATE_MANUAL_SAME_TAB") == "1"
		if sameTab {
			replacementCommand = "fixture.manualSameTab"
		}
		replaced := commandState(replacementCommand)
		if string(replaced["manualTabOpen"]) != "true" {
			t.Fatal("new manual tab not retained")
		}
		peerMu.Lock()
		peer.Close()
		peerMu.Unlock()
		waitControl(t, func() bool { broker.mu.Lock(); defer broker.mu.Unlock(); return c.conn == nil })
		broker.Close()
		broker, err = newBrokerWithPeer(Config{SocketPath: filepath.Join(directory, "manual-broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("fixture", "isolated"): credential}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return evidence, nil })
		if err != nil {
			t.Fatal(err)
		}
		c = broker.channels[channelKey("fixture", "isolated")]
		gateway, err = NewGateway(broker, GatewayOptions{})
		if err != nil {
			t.Fatal(err)
		}
		held = auth.WithConsentBinding(auth.WithPrincipal(ctx, p), auth.ConsentBinding{SessionID: "manual-new-session", GrantID: consent.GrantID, Purpose: "Manual document privacy"})
		reset := commandState("fixture.restartWorker")
		if string(reset["privateMaterialPresent"]) != "false" || string(reset["manualTabOpen"]) != "true" {
			t.Fatal("worker reset did not lose old redactions while preserving manual tab")
		}
		var freshHello map[string]any
		select {
		case raw := <-hellos:
			if json.Unmarshal(raw, &freshHello) != nil {
				t.Fatal("fresh worker hello unavailable")
			}
		case <-ctx.Done():
			t.Fatal("fresh worker hello timed out")
		}
		nextPeer, e := net.Dial("unix", broker.listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		peerMu.Lock()
		peer = nextPeer
		peerMu.Unlock()
		freshHello["extensionOrigin"] = ready.ExtensionOrigin
		freshHello["credential"] = credential
		freshHello["profileDirectory"] = directory
		freshHello["profileLaunchQualified"] = true
		if WriteFrame(nextPeer, freshHello) != nil {
			t.Fatal("fresh native enrollment unavailable")
		}
		readPeer(nextPeer)
		waitControl(t, func() bool {
			broker.mu.Lock()
			defer broker.mu.Unlock()
			return c.conn != nil && c.executorQualified && c.inventoryComplete
		})
		source := ManualCredentialSource{Identity: authority.Document.Identity, Origin: ready.Origin, ChromeBirth: evidence.ChromeParent.StartToken}
		manualBinding := binding
		manualBinding.SessionID = "manual-new-session"
		freshStore, e := vault.NewStore(filepath.Join(directory, "vault"), "fixture-v1", &vault.Cipher{Keys: credentialFixtureKeys{}})
		if e != nil {
			t.Fatal("fresh vault store unavailable")
		}
		defer freshStore.Close()
		freshRef, e := freshStore.Lookup(held, target)
		if e != nil {
			t.Fatal("fresh vault revision selection unavailable")
		}
		manualManager, e := vault.NewManager(freshStore, vault.Hooks{Present: func(context.Context, vault.Request) error { return errors.New("unexpected manual presentation") }, Resume: func(context.Context, vault.Binding, vault.Reference) error {
			return errors.New("unexpected manual input resume")
		}, Fresh: func(context.Context, vault.Binding) (vault.Binding, error) { return manualBinding, nil }})
		if e != nil {
			t.Fatal(e)
		}
		negativeCases := []string{"fixture.manualDuplicate", "fixture.expire", "fixture.manualChallenge"}
		if sameTab {
			negativeCases = negativeCases[1:]
		}
		for _, unavailable := range negativeCases {
			commandState(unavailable)
			trial, e := gateway.BeginManualCredentialPrivacy(held, p, source, allow)
			if e != nil {
				t.Fatal("negative fixture source proof unavailable")
			}
			_, e = trial.Qualify(held, p, manualManager, manualBinding, freshRef, selected.Revision)
			trial.Abort()
			if e == nil {
				t.Fatal("unsafe manual candidate qualified")
			}
			broker.mu.Lock()
			connected := c.conn != nil
			broker.mu.Unlock()
			if !connected {
				t.Fatal("safe manual availability refusal closed channel")
			}
			if unavailable == "fixture.manualDuplicate" {
				commandState("fixture.manualUnique")
			} else {
				commandState("fixture.navigate")
			}
		}
		for cycle := 0; cycle < 2; cycle++ {
			if cycle == 1 {
				commandState("fixture.navigate")
			}
			transition, e := gateway.BeginManualCredentialPrivacy(held, p, source, allow)
			if e != nil {
				t.Fatalf("manual source absence unavailable at cycle%d", cycle)
			}
			manualProof, e := transition.Qualify(held, p, manualManager, manualBinding, freshRef, selected.Revision)
			if e != nil {
				transition.Abort()
				t.Fatalf("manual redactor qualification unavailable at cycle%d", cycle)
			}
			fresh, valid := manualProof.Authority()
			if !valid || fresh.Lease != (Lease{}) || (fresh.Document.TabID == source.Identity.TabID) != sameTab || fresh.Document.DocumentID == source.Identity.DocumentID {
				t.Fatal("manual proof violated replacement identity or inherited a dispatch lease")
			}
			// Host cleanup invokes this verifier before its first generated
			// write. Prove it without borrowing a fresh renderer input lease.
			if e := gateway.VerifyCredentialPrivacy(held, p, manualProof, model.Surface{Kind: "web", Origin: ready.Origin, TabID: fresh.Document.QualifiedTabID()}, false); e != nil {
				t.Fatalf("manual cleanup guard rejected scope: authorityAllWebsites=%v enrollmentAllWebsites=%v code=%s", fresh.AllWebsites, grant.AllWebsites, CredentialPrivacyFailureCode(e))
			}
			if fresh.AllWebsites != grant.AllWebsites || fresh.TrustScope != c.grant.TrustScope || fresh.ScopeHash != c.scopeHash || fresh.ClientID != p.ClientID || !fresh.ScopeQualified || fresh.Lease != (Lease{}) {
				t.Fatal("manual trusted authority provenance changed")
			}
			admitted, e := gateway.AdmitControlWithStatus(held, p, surface)
			if e != nil || !admitted.Created || !admitted.Confirmed {
				t.Fatal("manual first-use admission unavailable")
			}
			reply, e := broker.call(held, c, Command{Action: "observe", Identity: admitted.Authority.Document.Identity}, false)
			if e != nil || reply.Error != nil {
				t.Fatal("manual redacted observation unavailable")
			}
			payload, _ := json.Marshal(reply)
			if bytesContainsCanary(payload) || !strings.Contains(string(payload), "Fixture records") {
				t.Fatal("manual redaction/read failed")
			}
			retired, e := gateway.RetireControl(held, p, admitted.Authority)
			if e != nil || !retired {
				t.Fatal("manual own lease retirement unavailable")
			}
		}
		if os.Getenv("MECHANIZE_MANUAL_SUCCESSOR_RECOVERY") == "1" {
			assertRetainedRedaction := func() {
				raw := commandState("fixture.redactionState")
				value, present := raw["privateMaterialPresent"]
				var retained bool
				if !present || json.Unmarshal(value, &retained) != nil || !retained {
					t.Fatal("explicit worker redaction metadata absent, mistyped or false")
				}
			}
			assertRetainedRedaction()
			broker.mu.Lock()
			successorAuthority := c.privacy.authority
			broker.mu.Unlock()
			successor := CredentialProtectionScope{PreparationID: capturedScope.PreparationID, Identity: successorAuthority.Document.Identity, Origin: ready.Origin, ChromeStartToken: successorAuthority.Evidence.ChromeParent.StartToken, BrokerEpoch: successorAuthority.BrokerEpoch, ChannelEpoch: successorAuthority.ChannelEpoch, ScopeHash: successorAuthority.ScopeHash}
			if e := gateway.VerifyCredentialScopeAbsent(held, p, successor); e == nil {
				t.Fatal("present promoted B was accepted absent")
			}
			commandState("fixture.freshLogin")
			waitControl(t, func() bool {
				broker.mu.Lock()
				defer broker.mu.Unlock()
				for _, candidate := range c.credentialCandidates {
					if candidate.TabID == successor.Identity.TabID && candidate.DocumentID != successor.Identity.DocumentID {
						return true
					}
				}
				return false
			})
			// Reproduce the live lifecycle: retiring A cannot remove B's privacy.
			if e := gateway.RetireAbsentCredentialScope(held, p, capturedScope); e != nil {
				t.Fatal("original A retirement", e)
			}
			if e := gateway.CredentialCandidateAvailable(held, p, surface); !errors.Is(e, ErrCredentialChannelBusy) {
				t.Fatal("baseline stale successor busy not reproduced", e)
			}
			if e := gateway.VerifyCredentialScopeAbsent(held, p, successor); e != nil {
				t.Fatal("gone promoted B absence", e)
			}
			if e := gateway.RetireAbsentCredentialScope(held, p, successor); e != nil {
				t.Fatal("exact B retirement", e)
			}
			broker.mu.Lock()
			stale := c.privacy != nil
			broker.mu.Unlock()
			if stale {
				t.Fatal("exact absent B remained retained")
			}
			assertRetainedRedaction()
			freshLogin, e := gateway.AdmitCredentialControl(held, p, surface, allow)
			if e != nil || !freshLogin.Confirmed {
				t.Fatalf("A→B→login C failed private admission: phase=%s reason=%s err=%v", freshLogin.FailureStage, freshLogin.FailureReason, e)
			}
			t.Log("A→B→login C: B present refused; A-only retirement reproduced stale busy; exact absent B retirement enabled fresh private preflight without replay")
		}
		ending := state()
		if ending["privateFill"] != after["privateFill"] || ending["privateSubmit"] != after["privateSubmit"] || ending["submits"] != after["submits"] {
			t.Fatal("manual qualification replayed credential input")
		}
		t.Logf("real Chrome: same-tab replacement=%v; original document absent, fresh broker/gateway/session and restarted worker lost old variants, reopened Vault privately seeded same revision redactor, zero-lease proof, own admission/read, full-navigation requalification; manual tab preserved and no new fill/submit", sameTab)
		return
	}
	visibilityFixture := os.Getenv("MECHANIZE_VISIBILITY_UNKNOWN") == "1"
	if visibilityFixture {
		activationCtx, cancelActivation := context.WithTimeout(held, time.Second)
		activationHeld, _, e := gateway.PrepareActivateTab(activationCtx, p, ready.Origin, routing.Document.QualifiedTabID())
		if e != nil {
			t.Fatal("activation admission unavailable", e)
		}
		result, e := gateway.ExecuteActivateTab(activationHeld, p, ready.Origin, routing.Document.QualifiedTabID(), strings.Repeat("9", 64), allow)
		cancelActivation()
		if e == nil || result.DispatchState != "unknown" {
			t.Fatal("lost activation result not retained unknown")
		}
		broker.mu.Lock()
		retained := c.unknown[strings.Repeat("9", 64)] && domUnknownBlockedLocked(c)
		broker.mu.Unlock()
		if !retained {
			t.Fatal("unknown lacked initial quarantine")
		}
	}
	foreign := auth.WithConsentBinding(held, auth.ConsentBinding{SessionID: "foreign-session", GrantID: consent.GrantID, Purpose: consent.Purpose})
	if _, err = gateway.AdmitControlWithStatus(foreign, p, surface); err == nil {
		t.Fatal("foreign session borrowed first-use control")
	}
	if denied := state(); denied["acquire"] != after["acquire"] {
		t.Fatal("foreign session reached renderer lease acquisition")
	}
	first, err := gateway.AdmitControlWithStatus(held, p, surface)
	if err != nil || !first.Created || !first.Confirmed || first.Authority.Lease.ID == "" {
		t.Fatal("first ordinary operation did not admit its own fresh lease")
	}
	stale := first.Authority
	stale.BrokerEpoch = "foreign-epoch"
	if gateway.VerifyControl(held, p, stale) == nil {
		t.Fatal("stale first-use control was accepted")
	}
	beforeObserveBadge := badgeStarts.Load()
	reply, err := broker.call(held, c, Command{Action: "observe", Identity: first.Authority.Document.Identity}, false)
	if err != nil || reply.Error != nil {
		t.Fatal("ordinary redacted observation unavailable")
	}
	if badgeStarts.Load() <= beforeObserveBadge {
		t.Fatal("legacy observe badge missing")
	}
	public, _ := json.Marshal(reply)
	if !strings.Contains(string(public), "Fixture records") {
		t.Fatal("ordinary observation did not reach the committed document")
	}
	if bytesContainsCanary(public) {
		t.Fatal("credential canary escaped committed redaction")
	}
	if visibilityFixture {
		command := Command{Action: "element.press", Identity: first.Authority.Document.Identity, AttemptID: strings.Repeat("8", 64), FingerprintVersion: 2, ControlLease: &first.Authority.Lease, Locator: &Locator{Strategy: "id", Value: "ordinary", Exact: true}}
		collision := command
		collision.AttemptID = strings.Repeat("9", 64)
		if _, e := broker.callBound(held, c, collision, p, func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
			t.Fatal("reused activation identity reached commit")
			return BindingCommit{}, nil
		}); e == nil {
			t.Fatal("activation identity reused for renderer input")
		}
		clicked, e := broker.callBound(held, c, command, p, func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
			return BindingCommit{BindingID: strings.Repeat("7", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
		})
		if e != nil || clicked.Error != nil || clicked.DispatchState != "dispatched" {
			t.Fatalf("fresh DOM click blocked after visibility classification: %v %v", e, clicked.Error)
		}
	}
	if retired, err := gateway.RetireControl(held, p, first.Authority); err != nil || !retired {
		t.Fatal("first ordinary lease did not retire")
	}
	final := state()
	extraAcquire := 0
	if os.Getenv("MECHANIZE_ORDINARY_ACQUIRE_DRIFT") == "2" {
		extraAcquire = 2
	}
	if final["privateFill"] != 1 || final["privateSubmit"] != 1 || final["submits"] != 1 || final["acquire"] != before["acquire"]+1+extraAcquire || final["retire"] != before["retire"]+1 {
		t.Fatal("handoff replayed input or skipped first-use lease ownership")
	}

	if visibilityFixture {
		broker.mu.Lock()
		retained := c.unknown[strings.Repeat("9", 64)] && !domUnknownBlockedLocked(c)
		broker.mu.Unlock()
		if !retained || final["activation"] != 1 || final["ordinaryClicks"] != 1 {
			t.Fatal("visibility proof cleared history or replayed activation")
		}
		if _, _, e := gateway.PrepareActivateTab(held, p, ready.Origin, routing.Document.QualifiedTabID()); e == nil {
			t.Fatal("visibility action allowed around retained unknown")
		}
		t.Log("actual Chrome: one activation, lost result, authenticated terminal receipt and drained worker lane, fresh admitted redacted DOM read and one exact ordinary click, original UNKNOWN retained, activation repeat denied")
		return
	}

	if os.Getenv("MECHANIZE_PRIVATE_SCOPED_RECOVERY") == "1" {
		commandState := func(kind string) string {
			t.Helper()
			if send(map[string]string{"type": kind}) != nil {
				t.Fatal("scoped fixture command failed")
			}
			select {
			case raw := <-states:
				var value struct {
					DocumentID string `json:"documentId"`
				}
				json.Unmarshal(raw, &value)
				return value.DocumentID
			case <-ctx.Done():
				t.Fatal("scoped fixture timed out")
			}
			return ""
		}
		commandState("fixture.independent")
		var independent Document
		waitControl(t, func() bool {
			broker.mu.Lock()
			defer broker.mu.Unlock()
			for _, d := range c.documents {
				if d.TabID != capturedScope.Identity.TabID && d.Origin == ready.Origin {
					independent = d
					return true
				}
			}
			return false
		})
		if e := gateway.VerifyProtectionDisjoint(held, p, capturedScope, model.Surface{Kind: "web", Origin: ready.Origin, TabID: independent.QualifiedTabID()}); e != nil {
			t.Fatalf("independent scope proof failed: %v", e)
		}
		observed, e := broker.call(held, c, Command{Action: "observe", Identity: independent.Identity}, false)
		encoded, _ := json.Marshal(observed)
		if e != nil || observed.Error != nil || bytesContainsCanary(encoded) || !strings.Contains(string(encoded), "Fixture records") {
			t.Fatalf("independent filtered observation failed: %v", e)
		}
		commandState("fixture.manualReplacement")
		// Real Chrome absence IPC on every guard; only the signed peer adapter
		// has a synthetic 90ms cost to reproduce the live verifier budget.
		originalPeer, originalIdentity := broker.verifyPeer, broker.verifyPeerIdentity
		fullChecks, kernelChecks := 0, 0
		broker.verifyPeer = func(ctx context.Context, conn *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
			fullChecks++
			select {
			case <-time.After(90 * time.Millisecond):
			case <-ctx.Done():
				return nativepeer.ChromeProcessEvidence{}, ctx.Err()
			}
			return originalPeer(ctx, conn)
		}
		broker.verifyPeerIdentity = func(ctx context.Context, conn *net.UnixConn, e nativepeer.ChromeProcessEvidence) error {
			kernelChecks++
			if c.conn != conn || c.processEvidence == nil || e.ChromeParent != c.processEvidence.ChromeParent {
				return errors.New("fixture identity drift")
			}
			return ctx.Err()
		}
		pinStarted := time.Now()
		pinned, finish, pinError := gateway.PinCredentialScopeProcesses(held, p, []CredentialProtectionScope{capturedScope})
		if pinError != nil {
			t.Fatal("scope process pin unavailable", pinError)
		}
		for i := 0; i < 59; i++ {
			if e := gateway.VerifyCredentialScopeAbsent(pinned, p, capturedScope); e != nil {
				t.Fatalf("fresh absence check %d failed: %v", i, e)
			}
		}
		if e := finish(pinned); e != nil {
			t.Fatal("final scope process check failed", e)
		}
		elapsed := time.Since(pinStarted)
		broker.verifyPeer, broker.verifyPeerIdentity = originalPeer, originalIdentity
		if fullChecks != 2 || kernelChecks != 118 || elapsed > 3*time.Second {
			t.Fatalf("cleanup process verification budget exceeded: full=%d kernel=%d elapsed=%s", fullChecks, kernelChecks, elapsed)
		}
		t.Logf("59 real Chrome absence exchanges: %s; full signature adapter checks=%d (90ms each), identity checks=%d; no cached absence", elapsed, fullChecks, kernelChecks)
		if e := gateway.RetireAbsentCredentialScope(held, p, capturedScope); e != nil {
			t.Fatalf("absent source retirement failed: %v", e)
		}
		newDocumentID := commandState("fixture.freshLogin")
		waitControl(t, func() bool {
			broker.mu.Lock()
			defer broker.mu.Unlock()
			return len(c.documents) == 1 && c.documents[0].TabID != capturedScope.Identity.TabID && c.documents[0].DocumentID == newDocumentID
		})
		fresh, e := gateway.AdmitCredentialControl(held, p, surface, allow)
		if e != nil || !fresh.Confirmed {
			t.Fatalf("fresh private admission after source absence failed: %s %v", fresh.FailureStage, e)
		}
		authority = fresh.Authority
		if _, e = gateway.CaptureCredentialProtectionScope(held, p, authority, strings.Repeat("f", 64)); e != nil {
			t.Fatalf("fresh source capture failed: %v", e)
		}
		binding = vault.Binding{SessionID: consent.SessionID, DocumentID: authority.Document.DocumentID, NavigationID: CredentialNavigationID(authority), Target: target}
		nextFill, e := gateway.DeliverVaultCredential(held, p, authority, strings.Repeat("a", 64), manager, binding, ref, selected.Revision, allow)
		if e != nil || nextFill.DispatchState != "dispatched" {
			t.Fatalf("new original fill failed after absence: %v", e)
		}
		counts := state()
		if counts["privateFill"] != 2 || counts["privateSubmit"] != 1 {
			t.Fatal("new fill replayed old submit or skipped new intent")
		}
		t.Log("actual Chrome: captured original scope, independent same-origin tab read redacted both canaries, exact old-source absence retired only live exposure, new login admitted and one new fill dispatched")
		return
	}
	// Requalification of an already committed public document must refresh only
	// its redactor, including after a full navigation loses the isolated world.
	for _, mode := range []string{"sameDocument", "fullNavigation", "sameDocumentAfterNavigation"} {
		if mode == "fullNavigation" {
			if send(map[string]string{"type": "fixture.navigate"}) != nil {
				t.Fatal("fixture navigation unavailable")
			}
			select {
			case <-states:
			case <-ctx.Done():
				t.Fatal("fixture navigation expired")
			}
		}
		routing, ok = proof.Authority()
		if !ok {
			t.Fatal("prior public proof unavailable")
		}
		proof, err = gateway.QualifyCredentialPrivacy(held, p, routing, submit, allow)
		if err != nil {
			t.Fatalf("public redactor refresh failed at %s: %s", mode, CredentialPrivacyFailureCode(err))
		}
		routing, ok = proof.Authority()
		if !ok || routing.Lease != (Lease{}) {
			t.Fatal("refresh granted input authority")
		}
		refreshed, e := broker.call(held, c, Command{Action: "observe", Identity: routing.Document.Identity}, false)
		if e != nil || refreshed.Error != nil {
			t.Fatal("refreshed public observation unavailable")
		}
		encoded, _ := json.Marshal(refreshed)
		if bytesContainsCanary(encoded) || !strings.Contains(string(encoded), "Fixture records") {
			t.Fatal("fresh document redactor failed")
		}
	}
	for _, refusal := range []string{"fixture.expire", "fixture.privacyChallenge", "fixture.blockedNavigation", "fixture.commitRefusal"} {
		previousRouting := routing
		broker.mu.Lock()
		originalConnection := c.conn
		broker.mu.Unlock()
		if send(map[string]string{"type": refusal}) != nil {
			t.Fatal("fixture refusal unavailable")
		}
		select {
		case <-states:
		case <-ctx.Done():
			t.Fatal("fixture refusal expired")
		}
		if _, err = gateway.QualifyCredentialPrivacy(held, p, previousRouting, submit, allow); CredentialPrivacyFailureCode(err) != "postSubmitPrivacyNotReady" {
			t.Fatalf("expected typed protected negative for %s: %s", refusal, CredentialPrivacyFailureCode(err))
		}
		if _, valid := proof.Authority(); valid {
			t.Fatal("nonready public proof remained active")
		}
		broker.mu.Lock()
		retained := c.conn == originalConnection && c.privacy == proof.state && c.privacyPending == nil
		broker.mu.Unlock()
		if !retained {
			t.Fatal("safe negative discarded authenticated privacy state")
		}
		if !errors.Is(gateway.VerifyCredentialPrivacy(held, p, proof, model.Surface{Kind: "web", Origin: previousRouting.Document.Origin, TabID: previousRouting.Document.QualifiedTabID()}, false), ErrCredentialPrivacyDocumentChanged) {
			t.Fatal("protected proof cannot request fresh qualification")
		}
		if send(map[string]string{"type": "fixture.recoverPrivacy"}) != nil {
			t.Fatal("fixture recovery unavailable")
		}
		select {
		case <-states:
		case <-ctx.Done():
			t.Fatal("fixture recovery expired")
		}
		proof, err = gateway.QualifyCredentialPrivacy(held, p, previousRouting, submit, allow)
		if err != nil {
			t.Fatalf("safe recovery failed for %s: %s", refusal, CredentialPrivacyFailureCode(err))
		}
		routing, _ = proof.Authority()
		observed, e := broker.call(held, c, Command{Action: "observe", Identity: routing.Document.Identity}, false)
		if e != nil || observed.Error != nil {
			t.Fatal("safe recovery read unavailable")
		}
		encoded, _ := json.Marshal(observed)
		if bytesContainsCanary(encoded) || !strings.Contains(string(encoded), "Fixture records") {
			t.Fatal("recovered redactor unavailable")
		}
	}
	ending := state()
	if ending["privateFill"] != 1 || ending["privateSubmit"] != 1 || ending["submits"] != 1 || ending["acquire"] != final["acquire"] || ending["retire"] != final["retire"] {
		t.Fatal("public refresh or expiration replayed input")
	}
	if badgeStarts.Load() == 0 || badgeStarts.Load() != badgeEnds.Load() {
		t.Fatalf("private/legacy badge lifetimes unbalanced: %d/%d", badgeStarts.Load(), badgeEnds.Load())
	}
	t.Log("actual Chrome worker/Vault/broker: one fill+submit, lease-free handoff, first-use admission, same-document refresh, full-navigation redactor, and safe-negative login/challenge/new-document recovery with redaction and no replay")
}
func bytesContainsCanary(value []byte) bool {
	return strings.Contains(string(value), "fixture-user-canary") || strings.Contains(string(value), "fixture-password-canary")
}
