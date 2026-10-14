package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome/playwrightipc"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/internal/chromeframe"
	"github.com/viant/mechanize/model"
)

type playwrightPrivacyKey struct{}

// Package-private authority callback receives only the broker-created execution
// context; legacy dispatch keeps its original strict before-write callback.
type playwrightControlCheckKey struct{}

type playwrightExecution struct {
	mu                                                sync.Mutex
	command                                           Command
	actor                                             auth.Principal
	consent                                           auth.ConsentBinding
	relayID                                           string
	origin                                            string
	conn                                              net.Conn
	pending                                           map[string]chan json.RawMessage
	events                                            chan playwrightipc.Event
	inputPossible, finished, revoked, intentConfirmed bool
	inputRequests                                     int
	redacted                                          *string
	receipt                                           *Reply
	started                                           time.Time
	callbackCount, verifyCount                        int
	verifyMS                                          int64
	processEvidence                                   *nativepeer.ChromeProcessEvidence
	identityChecks                                    int
	lastCallback, lastMethod                          string
}

func playwrightSupported(command Command) bool {
	return command.Locator != nil && (command.Action == "element.press" || command.Action == "element.fill" || command.Action == "read" && command.Args["attribute"] == "text")
}
func (b *Broker) playwrightReady(c *channel) bool {
	return b.playwright != nil && c.playwrightRelayVersion == 1 && !c.fixtureOnly
}

// Called only after the normal principal/consent/lane/fingerprint/seal gates.
func (b *Broker) callPlaywright(ctx context.Context, c *channel, command Command, mutation bool, committed bool, checks ...func() error) (Reply, error) {
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(command.DeadlineUnixMS))
	defer cancel()
	var endBadge func()
	defer func() {
		if endBadge != nil {
			endBadge()
		}
	}()
	e := &playwrightExecution{started: time.Now(), command: command, relayID: newID(), pending: map[string]chan json.RawMessage{}, events: make(chan playwrightipc.Event, 128)}
	actor, actorErr := auth.FromContext(ctx)
	if actorErr != nil {
		return Reply{}, auth.ErrUnauthorized
	}
	e.actor = actor
	e.consent, _ = auth.ConsentBindingFromContext(ctx)

	b.mu.Lock()
	if !b.playwrightReady(c) || c.playwright != nil || c.conn == nil || b.closed {
		b.mu.Unlock()
		return Reply{}, browserError("playwrightUnavailable", "Qualified local Playwright relay unavailable", "notDispatched")
	}
	for _, d := range c.documents {
		if d.Identity == command.Identity {
			e.origin = d.Origin
		}
	}
	if e.origin == "" {
		b.mu.Unlock()
		return Reply{}, browserError("playwrightDocumentChanged", "Exact original Playwright document unavailable", "notDispatched")
	}
	e.conn = c.conn
	c.playwright = e
	c.pending[command.RequestID] = &pending{playwright: true, command: command, mutation: mutation}
	if mutation {
		retained := command
		retained.Args = nil
		retained.Locator = nil
		c.attempts[command.AttemptID] = retained
	}
	b.mu.Unlock()
	ctx = context.WithValue(ctx, playwrightPrivacyKey{}, e)
	// One full signature/resource check qualifies only this exact operation.
	// The private proof is discarded with its original pending entry.
	if err := b.checkChannelProcess(ctx, c, true); err != nil {
		b.mu.Lock()
		if c.playwright == e {
			c.playwright = nil
			delete(c.pending, command.RequestID)
		}
		b.mu.Unlock()
		reply := playwrightReply(command, "notDispatched", "none", "playwrightAuthorityChanged", nil)
		if mutation {
			b.mu.Lock()
			c.receipts[command.AttemptID] = reply
			delete(c.unknown, command.AttemptID)
			b.mu.Unlock()
		}
		return reply, reply.Error
	}
	b.mu.Lock()
	e.processEvidence = c.processEvidence
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		if c.playwright == e {
			c.playwright = nil
			delete(c.pending, command.RequestID)
		}
		b.mu.Unlock()
	}()
	current := func() error {
		if ctx.Err() != nil {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightDeadline"}
		}
		if contextual, ok := ctx.Value(playwrightControlCheckKey{}).(func(context.Context) error); ok && contextual != nil && (mutation || command.Action == "read") && command.Locator != nil && len(checks) == 1 {
			if contextual(ctx) != nil {
				return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightAuthorityChanged"}
			}
		} else {
			for _, check := range checks {
				if check() != nil {
					return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightAuthorityChanged"}
				}
			}
		}
		if b.guardPrivacyCommand(ctx, c, command, mutation) != nil {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightPrivateDOMDenied"}
		}
		if b.verifyChannelProcess(ctx, c) != nil {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightAuthorityDenied"}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if c.conn != e.conn || b.closed || c.lifecycleInhibited || !channelScopeQualified(c) || !c.executorQualified || (!scopeDisjointLocked(c, e.command.Identity) && (c.privateInspection != nil || c.privateFlow != nil || c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil)) {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightAuthorityChanged"}
		}
		found := false
		for _, d := range c.documents {
			if d.Origin == e.origin && (d.Identity == command.Identity || playwrightOwnEffectIdentityLocked(ctx, c, command.Identity, d.Identity, command.ControlLease)) {
				found = true
				break
			}
		}
		if !found || command.BrokerEpoch != b.epoch || command.ChannelEpoch != c.epoch || command.ScopeHash != c.scopeHash {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightDocumentChanged"}
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.revoked {
			return &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightRelayDenied"}
		}
		return nil
	}
	exchange := func(ctx context.Context, kind string, extra map[string]any) (json.RawMessage, error) {
		request := newID()
		done := make(chan json.RawMessage, 1)
		e.mu.Lock()
		if e.revoked {
			e.mu.Unlock()
			return nil, errors.New("playwright relay revoked")
		}
		e.pending[request] = done
		e.mu.Unlock()
		defer func() { e.mu.Lock(); delete(e.pending, request); e.mu.Unlock() }()
		frame := map[string]any{"type": kind, "requestId": request, "relayId": e.relayID, "deadlineUnixMs": command.DeadlineUnixMS}
		for k, v := range extra {
			frame[k] = v
		}
		input := false
		if kind == "playwright.send" {
			method, _ := extra["method"].(string)
			raw, _ := extra["params"].(json.RawMessage)
			input = playwrightInput(method, raw)
		}
		c.writeMu.Lock()
		b.mu.Lock()
		valid := c.conn == e.conn && !b.closed && !c.lifecycleInhibited
		b.mu.Unlock()
		if !valid || ctx.Err() != nil {
			c.writeMu.Unlock()
			return nil, &playwrightipc.CallbackError{DispatchState: "notDispatched"}
		}
		if input {
			e.mu.Lock()
			e.inputRequests++
			e.inputPossible = true
			e.mu.Unlock()
			b.mu.Lock()
			c.unknown[command.AttemptID] = true
			b.mu.Unlock()
		}
		_ = e.conn.SetWriteDeadline(time.UnixMilli(command.DeadlineUnixMS))
		err := WriteFrame(e.conn, frame)
		_ = e.conn.SetWriteDeadline(time.Time{})
		c.writeMu.Unlock()
		if err != nil {
			state := "notDispatched"
			if input {
				state = "unknown"
			}
			return nil, &playwrightipc.CallbackError{DispatchState: state}
		}
		select {
		case raw := <-done:
			var response struct {
				Result        json.RawMessage `json:"result"`
				ErrorCode     string          `json:"errorCode"`
				DispatchState string          `json:"dispatchState"`
			}
			if json.Unmarshal(raw, &response) != nil {
				return nil, &playwrightipc.CallbackError{DispatchState: "unknown"}
			}
			if response.ErrorCode != "" {
				state := "notDispatched"
				if input && response.DispatchState == "notDispatched" {
					e.mu.Lock()
					e.inputRequests--
					e.inputPossible = e.inputRequests > 0
					stillPossible := e.inputPossible
					e.mu.Unlock()
					if !stillPossible {
						b.mu.Lock()
						delete(c.unknown, command.AttemptID)
						b.mu.Unlock()
					}
				} else if input {
					state = "unknown"
				}
				// A failed send may already have finalized the worker journal.
				// Retain only exact read-back evidence, never the sidecar's claim.
				e.mu.Lock()
				if retained := playwrightTerminalReceipt(response.Result, command, e.inputPossible); retained != nil && e.receipt == nil {
					e.receipt = retained
					e.finished = true
				}
				e.mu.Unlock()
				return nil, &playwrightipc.CallbackError{DispatchState: state, Code: playwrightipc.CallbackCode(response.ErrorCode)}
			}
			if len(response.Result) == 0 {
				return nil, &playwrightipc.CallbackError{DispatchState: "unknown"}
			}
			return response.Result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	handler := func(ctx context.Context, callback playwrightipc.Callback) (any, error) {
		var params map[string]json.RawMessage
		if json.Unmarshal(callback.Params, &params) != nil {
			return nil, errors.New("playwright callback unavailable")
		}
		e.mu.Lock()
		e.callbackCount++
		e.lastCallback = closedPlaywrightCallback(callback.Method)
		if callback.Method == "relay.send" {
			var method string
			json.Unmarshal(params["method"], &method)
			if playwrightCDPMethod(method) {
				e.lastMethod = method
			} else {
				e.lastMethod = "other"
			}
		}
		e.mu.Unlock()

		if callback.Method != "relay.close" && callback.Method != "receipt.persist" {
			if currentErr := current(); currentErr != nil {
				return nil, currentErr
			}
		}
		switch callback.Method {
		case "admit":
			var admission struct {
				Command Command `json:"command"`
			}
			if closedPlaywright(callback.Params, &admission) != nil {
				return nil, errors.New("playwright admission denied")
			}
			var received Command
			if json.Unmarshal(params["command"], &received) != nil || !reflect.DeepEqual(received, command) {
				return nil, errors.New("playwright command substituted")
			}
			authority := map[string]any{"identity": command.Identity, "brokerEpoch": command.BrokerEpoch, "channelEpoch": command.ChannelEpoch, "scopeHash": command.ScopeHash, "controlLease": command.ControlLease, "fingerprintSHA256": command.FingerprintSHA256, "committed": committed, "privateQuarantined": false}
			b.mu.Lock()
			for _, d := range c.documents {
				if d.Identity == command.Identity {
					authority["origin"] = d.Origin
				}
			}
			if c.privacy != nil {
				authority["protectedOrigin"] = true
				authority["privacyState"] = "redacted-dom"
				authority["domReadQualified"] = c.privacy.active && c.privacy.published
				authority["privacyRevision"] = c.privacy.permitID
			}
			b.mu.Unlock()
			return authority, nil
		case "current":
			var in struct {
				ExecutionID string `json:"executionId"`
			}
			if closedPlaywright(callback.Params, &in) != nil || in.ExecutionID != command.RequestID {
				return nil, errors.New("playwright execution substituted")
			}
			return true, nil
		case "intent.confirm":
			var descriptor struct {
				AttemptID         string   `json:"attemptId"`
				Identity          Identity `json:"identity"`
				BrokerEpoch       string   `json:"brokerEpoch"`
				ChannelEpoch      string   `json:"channelEpoch"`
				ScopeHash         string   `json:"scopeHash"`
				ControlLease      *Lease   `json:"controlLease"`
				FingerprintSHA256 string   `json:"fingerprintSHA256"`
			}
			if closedPlaywright(callback.Params, &descriptor) != nil || !committed || descriptor.AttemptID != command.AttemptID || descriptor.Identity != command.Identity || descriptor.BrokerEpoch != command.BrokerEpoch || descriptor.ChannelEpoch != command.ChannelEpoch || descriptor.ScopeHash != command.ScopeHash || descriptor.FingerprintSHA256 != command.FingerprintSHA256 || !reflect.DeepEqual(descriptor.ControlLease, command.ControlLease) {
				return nil, errors.New("playwright binding mismatch")
			}
			e.mu.Lock()
			e.intentConfirmed = true
			e.mu.Unlock()
			return true, nil
		case "relay.open":
			var in struct {
				ExecutionID string `json:"executionId"`
			}
			if closedPlaywright(callback.Params, &in) != nil || in.ExecutionID != command.RequestID {
				return nil, errors.New("playwright execution substituted")
			}
			b.mu.Lock()
			origin := ""
			for _, d := range c.documents {
				if d.Identity == command.Identity {
					origin = d.Origin
				}
			}
			b.mu.Unlock()
			b.mu.Lock()
			badgeRequested := b.controlBadge != nil && (c.controlBadgeVersion == 1 || c.controlBadgeVersion == 2) && !hasControlBadge(ctx, b, c, command.Identity)
			b.mu.Unlock()
			extra := map[string]any{"command": command, "origin": origin, "deadlineUnixMs": command.DeadlineUnixMS}
			if badgeRequested {
				extra["controlBadge"] = true
			}
			raw, err := exchange(ctx, "playwright.open", extra)
			if err != nil {
				return nil, err
			}
			window, opened := playwrightOpened(raw, badgeRequested)
			if !opened {
				return nil, errors.New("playwright open denied")
			}
			if window != nil && e.processEvidence != nil && current() == nil {
				endBadge = b.controlBadge(ctx, actor, e.processEvidence.ChromeParent, *window)
			}
			return map[string]any{"relayId": e.relayID}, nil
		case "relay.send":
			var in struct {
				RelayID  string          `json:"relayId"`
				Method   string          `json:"method"`
				Params   json.RawMessage `json:"params"`
				Deadline int64           `json:"deadlineUnixMs"`
			}
			if closedPlaywright(callback.Params, &in) != nil || in.RelayID != e.relayID || in.Deadline > command.DeadlineUnixMS || in.Deadline <= time.Now().UnixMilli() || !playwrightCDPMethod(in.Method) {
				return nil, errors.New("playwright CDP denied")
			}
			if playwrightInput(in.Method, in.Params) {
				// Fresh complete trust immediately before any possible input;
				// the relay still guards the exact pinned target afterwards.
				if b.checkChannelProcess(ctx, c, true) != nil || current() != nil {
					return nil, &playwrightipc.CallbackError{DispatchState: "notDispatched"}
				}
				e.mu.Lock()
				if !mutation || !e.intentConfirmed {
					e.mu.Unlock()
					return nil, errors.New("playwright intent required")
				}
				e.mu.Unlock()
			}
			raw, err := exchange(ctx, "playwright.send", map[string]any{"method": in.Method, "params": in.Params, "deadlineUnixMs": in.Deadline})
			if err != nil {
				return nil, err
			}
			return raw, nil
		case "relay.redact":
			var in struct {
				RelayID string `json:"relayId"`
				Value   string `json:"value"`
			}
			if closedPlaywright(callback.Params, &in) != nil || in.RelayID != e.relayID || len(in.Value) > 32768 {
				return nil, errors.New("playwright redaction denied")
			}
			raw, err := exchange(ctx, "playwright.redact", map[string]any{"value": in.Value})
			if err != nil {
				return nil, err
			}
			var response struct {
				Type      string  `json:"type"`
				Value     *string `json:"value"`
				ErrorCode string  `json:"errorCode"`
			}
			if json.Unmarshal(raw, &response) != nil || response.Value == nil || len(*response.Value) > 32768 || response.ErrorCode != "" {
				return nil, errors.New("playwright redaction unconfirmed")
			}
			e.mu.Lock()
			e.redacted = response.Value
			e.mu.Unlock()
			return *response.Value, nil
		case "relay.close":
			var in struct {
				RelayID string `json:"relayId"`
			}
			if closedPlaywright(callback.Params, &in) != nil || in.RelayID != e.relayID {
				return nil, errors.New("playwright relay substituted")
			}
			_, err := exchange(ctx, "playwright.close", nil)
			return true, err
		case "receipt.persist":
			var receipt struct {
				AttemptID      string `json:"attemptId"`
				Fingerprint    string `json:"fingerprintSHA256"`
				Dispatch       string `json:"dispatchState"`
				Effect         string `json:"effectState"`
				ErrorCode      string `json:"errorCode,omitempty"`
				InputSemantics string `json:"inputSemantics,omitempty"`
			}
			if closedPlaywright(callback.Params, &receipt) != nil || !mutation || receipt.AttemptID != command.AttemptID || receipt.Fingerprint != command.FingerprintSHA256 {
				return nil, errors.New("playwright receipt denied")
			}
			e.mu.Lock()
			possible := e.inputPossible
			e.mu.Unlock()
			state := receipt.Dispatch
			if !possible {
				state = "notDispatched"
			} else if state != "dispatched" {
				state = "unknown"
			}
			effect := "none"
			if state == "dispatched" {
				effect = "unverified"
			}
			if state == "unknown" {
				effect = "unknown"
			}
			receiptFrame := map[string]any{"dispatchState": state, "effectState": effect, "inputSemantics": "Local Playwright over scoped extension CDP"}
			if code := safePlaywrightError(receipt.ErrorCode); code != "" {
				receiptFrame["errorCode"] = code
			}
			raw, err := exchange(ctx, "playwright.receipt", receiptFrame)
			if err != nil {
				return nil, err
			}
			if !playwrightAcknowledged(raw, "persisted") {
				return nil, &playwrightipc.CallbackError{DispatchState: "notDispatched", Code: "playwrightReceiptUncertain"}
			}
			reply := playwrightReply(command, state, effect, receipt.ErrorCode, nil)
			e.mu.Lock()
			e.receipt = &reply
			e.finished = true
			e.mu.Unlock()
			return true, nil
		}
		return nil, errors.New("playwright callback denied")
	}
	result, err := b.playwright.Execute(ctx, command.RequestID, command, handler, e.events)
	e.mu.Lock()
	possible := e.inputPossible
	receipt := e.receipt
	redacted := e.redacted
	e.mu.Unlock()
	if mutation && receipt != nil {
		b.mu.Lock()
		if receipt.DispatchState != "unknown" {
			c.receipts[command.AttemptID] = *receipt
			delete(c.unknown, command.AttemptID)
		}
		b.mu.Unlock()
		if receipt.Error != nil {
			return *receipt, e.diagnosticFailure(receipt.Error)
		}
		return *receipt, nil
	}
	state := "notDispatched"
	effect := "none"
	if possible {
		state = "unknown"
		effect = "unknown"
	}
	if err == nil && result.RequestID == command.RequestID && !mutation && result.Value != nil && redacted != nil && *result.Value == *redacted && current() == nil {
		return playwrightReply(command, state, effect, "", redacted), nil
	}
	code := result.ErrorCode
	if err != nil {
		code = playwrightipc.FailureCode(err)
	}
	reply := playwrightReply(command, state, effect, code, nil)
	if reply.Error == nil {
		reply.Error = browserError("playwrightUnavailable", "Local Playwright execution or receipt unavailable", state)
	}
	var detail *model.MechanizeError
	if errors.As(reply.Error, &detail) {
		detail.Message = e.failureDetails(detail.Code)
	}

	if mutation && !possible {
		b.mu.Lock()
		c.receipts[command.AttemptID] = reply
		delete(c.unknown, command.AttemptID)
		b.mu.Unlock()
	}
	return reply, e.diagnosticFailure(reply.Error)
}
func closedPlaywright(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > chromeframe.PrivateLimit || d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("playwright envelope invalid")
	}
	return nil
}
func safePlaywrightError(code string) string {
	switch code {
	case "", "playwrightRuntimeQualification", "playwrightChildLaunch", "playwrightDeadline", "playwrightIPCFrame", "playwrightIPCProtocol", "playwrightIPCWrite", "playwrightChildExited", "playwrightAttemptCapacity", "playwrightAttemptConflict", "playwrightAuthorityChanged", "playwrightAuthorityDenied", "playwrightBindingRequired", "playwrightBusy", "playwrightCommandDenied", "playwrightDocumentChanged", "playwrightFingerprintMismatch", "playwrightHostRequired", "playwrightIntentRequired", "playwrightLocatorDenied", "playwrightOriginDenied", "playwrightPrivateDOMDenied", "playwrightReadDenied", "playwrightReadTooLarge", "playwrightReceiptUncertain", "playwrightRedactionDenied", "playwrightTargetDenied", "playwrightTargetUnpinned", "playwrightTargetChanged", "playwrightUnavailable", "playwrightUncertain", "playwrightExecutionRequired", "playwrightHostDeadline", "playwrightHostDenied", "playwrightHostDisconnected", "playwrightRelayDenied":
		return code
	}
	if known := playwrightipc.CallbackCode(code); known != "playwrightHostDenied" {
		return known
	}
	return "playwrightUnavailable"
}

type playwrightFailureDiagnostic struct {
	cause      error
	diagnostic integration.PlaywrightDiagnostic
}

func (e *playwrightFailureDiagnostic) Error() string { return e.cause.Error() }
func (e *playwrightFailureDiagnostic) Unwrap() error { return e.cause }
func (e *playwrightFailureDiagnostic) PlaywrightExecutionDiagnostic() integration.PlaywrightDiagnostic {
	return e.diagnostic
}
func (e *playwrightExecution) diagnosticFailure(cause error) error {
	if cause == nil {
		return nil
	}
	var detail *model.MechanizeError
	if !errors.As(cause, &detail) || detail == nil {
		return cause
	}
	e.mu.Lock()
	value := integration.PlaywrightDiagnostic{Phase: safePlaywrightError(detail.Code), Callbacks: e.callbackCount, PeerChecks: e.verifyCount, PeerMs: e.verifyMS, IdentityChecks: e.identityChecks, ElapsedMs: time.Since(e.started).Milliseconds(), LastCallback: closedPlaywrightCallback(e.lastCallback), LastMethod: closedPlaywrightMethod(e.lastMethod)}
	e.mu.Unlock()
	return &playwrightFailureDiagnostic{cause: cause, diagnostic: value}
}

func playwrightReply(c Command, state, effect, code string, value *string) Reply {
	r := Reply{RequestID: c.RequestID, AttemptID: c.AttemptID, Identity: c.Identity, ControlLease: c.ControlLease, FingerprintVersion: c.FingerprintVersion, FingerprintSHA256: c.FingerprintSHA256, DispatchState: state, EffectState: effect, Value: value, Validated: true}
	if code != "" {
		r.Error = browserError(safePlaywrightError(code), "Local Playwright operation unavailable", state)
	}
	return r
}
func playwrightAcknowledged(raw []byte, kind string) bool {
	var response map[string]bool
	return json.Unmarshal(raw, &response) == nil && len(response) == 1 && response[kind]
}

func playwrightInput(method string, raw json.RawMessage) bool {
	if method == "Input.insertText" {
		return true
	}
	var p struct {
		Type string `json:"type"`
	}
	json.Unmarshal(raw, &p)
	return method == "Input.dispatchMouseEvent" && p.Type == "mousePressed" || method == "Input.dispatchKeyEvent" && (p.Type == "rawKeyDown" || p.Type == "keyDown" || p.Type == "char")
}
func playwrightCDPMethod(method string) bool {
	switch method {
	case "Page.enable", "Page.getFrameTree", "Page.setLifecycleEventsEnabled", "Page.addScriptToEvaluateOnNewDocument", "Page.createIsolatedWorld", "Page.bringToFront", "Page.getLayoutMetrics", "Runtime.enable", "Runtime.evaluate", "Runtime.callFunctionOn", "Runtime.getProperties", "Runtime.releaseObject", "Runtime.releaseObjectGroup", "Runtime.runIfWaitingForDebugger", "DOM.enable", "DOM.getDocument", "DOM.describeNode", "DOM.resolveNode", "DOM.getContentQuads", "DOM.getBoxModel", "DOM.scrollIntoViewIfNeeded", "DOM.getNodeForLocation", "Log.enable", "Inspector.enable", "Network.enable", "Network.setCacheDisabled", "Network.setBypassServiceWorker", "Emulation.setFocusEmulationEnabled", "Emulation.setEmulatedMedia", "Target.setAutoAttach", "Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText":
		return true
	}
	return false
}

// acceptPlaywrightFrame consumes only a response/event of the active private
// operation on the exact authenticated port. Nothing is promoted to MCP here.
func (b *Broker) acceptPlaywrightFrame(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || !strings.HasPrefix(kind.Type, "playwright.") {
		return false
	}
	b.mu.Lock()
	e := c.playwright
	valid := e != nil && e.conn == conn && c.conn == conn && !b.closed
	b.mu.Unlock()
	if !valid {
		return true
	}
	var frame struct {
		Type          string          `json:"type"`
		RequestID     string          `json:"requestId,omitempty"`
		RelayID       string          `json:"relayId"`
		Result        json.RawMessage `json:"result,omitempty"`
		ErrorCode     string          `json:"errorCode,omitempty"`
		DispatchState string          `json:"dispatchState,omitempty"`
		Method        string          `json:"method,omitempty"`
		Params        json.RawMessage `json:"params,omitempty"`
	}
	if closedPlaywright(raw, &frame) != nil || frame.RelayID != e.relayID {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if frame.Type == "playwright.result" && frame.RequestID != "" {
		if done := e.pending[frame.RequestID]; done != nil {
			select {
			case done <- append(json.RawMessage(nil), raw...):
			default:
			}
		}
	} else if frame.Type == "playwright.event" && frame.RequestID == "" && frame.Method != "" {
		select {
		case e.events <- playwrightipc.Event{RelayID: e.relayID, Method: frame.Method, Params: frame.Params}:
		default:
			e.revoked = true
		}
	}
	return true
}

// privacyOperationIdleLocked grants no new input authority. It permits only the
// exact already admitted local operation to recheck its published DOM privacy
// guard while its own transport/receipt is in flight. Other pending/unknown
// work remains a barrier; JSON/MCP callers cannot construct this context token.
func privacyOperationIdleLocked(ctx context.Context, c *channel, target ...Identity) bool {
	// Published privacy retains redaction, not a global input lane. Ordinary
	// admission uses the same exact-target health as control/retirement. Private
	// delivery and unbound hazards retain the existing conservative exclusion.
	published := c.privacy != nil && c.privacy.active && c.privacy.published
	ordinary := c.privateInspection == nil && c.privateCredential == nil &&
		c.privateAdvance == nil && c.privateFlow == nil && c.privacyPending == nil
	if len(target) == 1 && published && ordinary && target[0] == c.privacy.identity &&
		!pendingForTargetLocked(c, target[0]) && !domUnknownForTargetLocked(c, target[0]) {
		return true
	}
	if len(c.pending) == 0 && !domUnknownBlockedLocked(c) {
		return true
	}
	e, ok := ctx.Value(playwrightPrivacyKey{}).(*playwrightExecution)
	if !ok || e == nil || c.playwright != e || c.conn != e.conn || len(c.pending) != 1 {
		return false
	}
	actor, actorErr := auth.FromContext(ctx)
	binding, _ := auth.ConsentBindingFromContext(ctx)
	if actorErr != nil || actor.Namespace != e.actor.Namespace || actor.ClientID != e.actor.ClientID || binding != e.consent || c.epoch != e.command.ChannelEpoch || c.scopeHash != e.command.ScopeHash {
		return false
	}
	p := c.pending[e.command.RequestID]
	if p == nil || !p.playwright || p.command.RequestID != e.command.RequestID || p.command.AttemptID != e.command.AttemptID || p.command.Identity != e.command.Identity || p.command.BrokerEpoch != e.command.BrokerEpoch || p.command.ChannelEpoch != e.command.ChannelEpoch || p.command.ScopeHash != e.command.ScopeHash || !reflect.DeepEqual(p.command.ControlLease, e.command.ControlLease) || p.command.FingerprintSHA256 != e.command.FingerprintSHA256 {
		return false
	}
	e.mu.Lock()
	revoked, possible := e.revoked, e.inputPossible
	e.mu.Unlock()
	if revoked {
		return false
	}
	if !domUnknownForTargetLocked(c, e.command.Identity) {
		return true
	}
	if domUnknownForTargetOtherThanLocked(c, e.command.Identity, e.command.AttemptID) || !c.unknown[e.command.AttemptID] {
		return false
	}
	return possible
}

// A fresh semantic Playwright locator resolves and pins its actual ElementHandle
// inside this exact admitted execution. Unrelated same-document DOM mutations
// may advance generation without changing authority. This token cannot be used
// for legacy snapshot references or a later operation; the worker revalidates
// the target and private-field boundary before each actual input.
func playwrightOwnEffectIdentityLocked(ctx context.Context, c *channel, original, current Identity, lease *Lease) bool {
	e, ok := ctx.Value(playwrightPrivacyKey{}).(*playwrightExecution)
	if !ok || e == nil || c.playwright != e || c.conn != e.conn || len(c.pending) != 1 || !privacyOperationIdleLocked(ctx, c) || original != e.command.Identity || !reflect.DeepEqual(lease, e.command.ControlLease) {
		return false
	}
	e.mu.Lock()
	possible := !e.revoked && e.command.Locator != nil && (e.command.Action == "element.press" || e.command.Action == "element.fill" || e.command.Action == "read")
	e.mu.Unlock()
	return possible && current.ProfileChannel == original.ProfileChannel && current.BrowserInstance == original.BrowserInstance && current.TabID == original.TabID && current.FrameID == original.FrameID && current.DocumentID == original.DocumentID && current.Generation >= original.Generation
}

// IndexedControlQualified is a host-internal qualification query for an already
// authenticated authority, not a caller-selected approval or raw CDP capability.
func (g *Gateway) IndexedControlQualified(a ControlAuthority) bool {
	if g == nil || g.broker == nil {
		return false
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.channels[channelKey(a.Document.ProfileChannel, a.Document.BrowserInstance)]
	return c != nil && c.grant.Principal.Namespace == a.Owner && c.conn != nil && !b.closed && b.playwrightReady(c) && c.playwrightLocatorVersion == 1 && channelScopeQualified(c) && c.executorQualified && c.epoch == a.ChannelEpoch && c.scopeHash == a.ScopeHash && b.epoch == a.BrokerEpoch
}

// failureDetails contains only local numeric timing and closed protocol labels.
// It never retains or formats callback parameters, provider errors or CDP data.
func (e *playwrightExecution) failureDetails(code string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("Local Playwright unavailable: phase=%s; callbacks=%d; peerChecks=%d; peerMs=%d; identityChecks=%d; elapsedMs=%d; lastCallback=%s; lastMethod=%s", safePlaywrightError(code), e.callbackCount, e.verifyCount, e.verifyMS, e.identityChecks, time.Since(e.started).Milliseconds(), closedPlaywrightCallback(e.lastCallback), closedPlaywrightMethod(e.lastMethod))
}
func closedPlaywrightCallback(method string) string {
	switch method {
	case "admit", "current", "relay.open", "relay.send", "relay.redact", "relay.close", "intent.confirm", "receipt.persist":
		return method
	}
	return "none"
}
func closedPlaywrightMethod(method string) string {
	if playwrightCDPMethod(method) {
		return method
	}
	return "none"
}
