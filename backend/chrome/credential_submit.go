package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"io"
	"time"
)

// ErrCredentialPrivacyCandidate preserves quarantine for an independent DOM
// privacy inspection. It grants no authority and is not a login-success signal.
var ErrCredentialNativeChallenge = errors.New("local authentication challenge requires native human action")

var ErrCredentialPostSubmitPending = errors.New("private login outcome pending")
var ErrCredentialLoginRejected = errors.New("private login was rejected")

var ErrCredentialPrivacyCandidate = errors.New("private document requires independent DOM privacy qualification")

type credentialFlow struct {
	binding                    auth.ConsentBinding
	authority                  ControlAuthority
	fillAttempt, submitAttempt string
	poisoned                   bool
	submitConfirmed            bool
	submitState                string
	retireAttempt              string
	retired                    bool
	sameDocumentPrivacy        bool
}
type CredentialAdvanceResult struct {
	Authority ControlAuthority
	Stage     string
}
type credentialAdvanceReply struct {
	identity Identity
	stage    string
	ready    bool
}
type credentialAdvancePending struct {
	requestID, attemptID string
	previous             Identity
	done                 chan credentialAdvanceReply
	replied              bool
}

func (b *Broker) acceptCredentialAdvanceLocked(c *channel, raw []byte) bool {
	p := c.privateAdvance
	if p == nil {
		return false
	}
	defer clear(raw)
	var r struct {
		Type      string   `json:"type"`
		RequestID string   `json:"requestId"`
		AttemptID string   `json:"attemptId"`
		Identity  Identity `json:"identity"`
		Stage     string   `json:"stage"`
		Ready     *bool    `json:"ready"`
	}
	var result credentialAdvanceReply
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var idFields map[string]json.RawMessage
	_ = json.Unmarshal(fields["identity"], &idFields)
	identityClosed := len(idFields) == 6
	for _, key := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"} {
		if value, ok := idFields[key]; !ok || bytes.Equal(value, []byte("null")) {
			identityClosed = false
		}
	}
	if identityClosed && len(raw) <= 4096 && uniqueCredentialJSON(raw) && len(fields) == 6 && len(idFields) == 6 && d.Decode(&r) == nil && d.Decode(new(any)) == io.EOF && r.Type == "credentialAdvanceResult" && r.RequestID == p.requestID && r.AttemptID == p.attemptID && r.Ready != nil && r.Identity.ProfileChannel == p.previous.ProfileChannel && r.Identity.BrowserInstance == p.previous.BrowserInstance && r.Identity.TabID == p.previous.TabID && r.Identity.FrameID == 0 && (r.Identity.DocumentID != p.previous.DocumentID || !*r.Ready && r.Identity.Generation >= p.previous.Generation && (r.Stage == "pending" || r.Stage == "rejected" || r.Stage == "challenge" || r.Stage == "unavailable")) && fingerprintV2ID.MatchString(r.Identity.DocumentID) && r.Identity.Generation > 0 && r.Identity.Generation <= 9007199254740991 && credentialStage(r.Stage) {
		if *r.Ready && !credentialInputStage(r.Stage) {
			result = credentialAdvanceReply{}
		} else {
			result = credentialAdvanceReply{r.Identity, r.Stage, *r.Ready}
		}
	}
	if p.replied || result.identity.DocumentID == "" {
		result = credentialAdvanceReply{}
		if c.privateFlow != nil {
			c.privateFlow.poisoned = true
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
	p.replied = true
	select {
	case p.done <- result:
	default:
	}
	return true
}
func credentialInputStage(s string) bool { return s == "pair" || s == "username" || s == "password" }
func credentialStage(s string) bool {
	return credentialInputStage(s) || s == "challenge" || s == "unavailable" || s == "pending" || s == "rejected"
}

// SubmitVaultCredential has no values or selectors. The host must durably reserve
// UNKNOWN for this unique attempt before calling and retain native exposure and
// exact consent/revision guards through admit. It never retries uncertain input.
func (g *Gateway) SubmitVaultCredential(ctx context.Context, p auth.Principal, a ControlAuthority, fillAttemptID, submitAttemptID string, admit func(context.Context) error) (CredentialDeliveryResult, error) {
	result := CredentialDeliveryResult{DispatchState: "notDispatched"}
	if g == nil || g.broker == nil || admit == nil || !fingerprintV2Hash.MatchString(fillAttemptID) || !fingerprintV2Hash.MatchString(submitAttemptID) || fillAttemptID == submitAttemptID {
		return result, errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c == nil {
		return result, errCredentialDelivery
	}
	b := g.broker
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
	if admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	var endBadge func()
	ctx, endBadge = b.beginControlBadge(ctx, c, a.Document.Identity)
	defer endBadge()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	b.mu.Lock()
	flow := c.privateFlow
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !bound || flow == nil || flow.binding != binding || flow.poisoned || flow.retireAttempt != "" || flow.fillAttempt != fillAttemptID || flow.submitAttempt != "" || !sameControl(flow.authority, a) || c.conn == nil || c.privateCredential != nil || c.privateAdvance != nil || len(c.pending) != 0 || len(c.unknown) != 0 || c.lifecycleInhibited || c.privateCredentialAttempts[submitAttemptID] {
		b.mu.Unlock()
		return result, errCredentialDelivery
	}
	conn := c.conn
	pending := &credentialDeliveryPending{requestID: newPrivateID(), attemptID: submitAttemptID, identity: a.Document.Identity, done: make(chan string, 1), replyType: "credentialSubmitResult", lease: &a.Lease}
	c.invalidateConsentReconnect()
	c.privateCredential = pending
	c.privateCredentialAttempts[submitAttemptID] = true
	flow.submitAttempt = submitAttemptID
	c.unknown[submitAttemptID] = true
	b.mu.Unlock()
	completed := false
	defer func() {
		if !completed {
			_ = conn.Close()
		}
	}()
	command := map[string]any{"type": "credentialSubmit", "requestId": pending.requestID, "attemptId": submitAttemptID, "fillAttemptId": fillAttemptID, "identity": a.Document.Identity, "brokerEpoch": a.BrokerEpoch, "channelEpoch": a.ChannelEpoch, "scopeHash": a.ScopeHash, "controlLease": a.Lease, "deadlineUnixMs": deadline.UnixMilli(), "origin": a.Document.Origin}
	if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	result.DispatchState = "unknown"
	if conn.SetWriteDeadline(deadline) != nil {
		return result, errCredentialDelivery
	}
	err := WriteFrame(conn, command)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return result, errCredentialDelivery
	}
	select {
	case state := <-pending.done:
		if state == "unknown" || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
			return result, errCredentialDelivery
		}
		b.mu.Lock()
		if pending.failed || c.privateFlow != flow || flow.poisoned || c.conn != conn {
			b.mu.Unlock()
			return result, errCredentialDelivery
		}
		c.privateCredential = nil
		flow.submitConfirmed = state == "dispatched"
		flow.submitState = state
		delete(c.unknown, submitAttemptID)
		b.mu.Unlock()
		result.DispatchState = state
		completed = true
		return result, nil
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
}

// AdvanceVaultCredential accepts only a new top document at the exact original
// HTTPS origin through the quarantined worker. The old authority cannot dispatch
// after transition. No ordinary document, page text, title or value is decoded.
func (g *Gateway) AdvanceVaultCredential(ctx context.Context, p auth.Principal, a ControlAuthority, submitAttemptID string, admit func(context.Context) error) (result CredentialAdvanceResult, resultErr error) {
	phase := errCredentialDelivery
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, ErrCredentialPostSubmitPending) && !errors.Is(resultErr, ErrCredentialLoginRejected) && !errors.Is(resultErr, ErrCredentialNativeChallenge) && !errors.Is(resultErr, ErrCredentialPrivacyCandidate) {
			resultErr = errors.Join(phase, resultErr)
		}
	}()
	if g == nil || g.broker == nil || admit == nil || !fingerprintV2Hash.MatchString(submitAttemptID) {
		return result, errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c == nil {
		return result, errCredentialDelivery
	}
	b := g.broker
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
	phase = ErrCredentialAdvanceAdmission
	if admit(ctx) != nil {
		return result, errCredentialDelivery
	}
	phase = ErrCredentialAdvanceControl
	if g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	phase = ErrCredentialAdvanceFlow
	var endBadge func()
	ctx, endBadge = b.beginControlBadge(ctx, c, a.Document.Identity)
	defer endBadge()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	g.controlMu.Lock()
	g.controlGeneration++
	nextLease := Lease{ID: newID(), Generation: g.controlGeneration}
	g.controlMu.Unlock()
	b.mu.Lock()
	flow := c.privateFlow
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !bound || flow == nil || flow.binding != binding || flow.poisoned || flow.submitAttempt != submitAttemptID || !flow.submitConfirmed || !sameControl(flow.authority, a) || c.conn == nil || c.privateCredential != nil || c.privateAdvance != nil || len(c.pending) != 0 || len(c.unknown) != 0 || c.lifecycleInhibited {
		b.mu.Unlock()
		return result, errCredentialDelivery
	}
	conn := c.conn
	pending := &credentialAdvancePending{requestID: newPrivateID(), attemptID: submitAttemptID, previous: a.Document.Identity, done: make(chan credentialAdvanceReply, 1)}
	c.invalidateConsentReconnect()
	c.privateAdvance = pending
	b.mu.Unlock()
	completed := false
	defer func() {
		if !completed {
			_ = conn.Close()
		}
	}()
	command := map[string]any{"type": "credentialAdvance", "requestId": pending.requestID, "attemptId": submitAttemptID, "identity": a.Document.Identity, "brokerEpoch": a.BrokerEpoch, "channelEpoch": a.ChannelEpoch, "scopeHash": a.ScopeHash, "controlLease": a.Lease, "nextLease": nextLease, "deadlineUnixMs": deadline.UnixMilli(), "origin": a.Document.Origin}
	phase = ErrCredentialAdvanceAdmission
	if ctx.Err() != nil || admit(ctx) != nil {
		return result, errCredentialDelivery
	}
	phase = ErrCredentialAdvanceControl
	if g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	phase = ErrCredentialAdvanceTransport
	if conn.SetWriteDeadline(deadline) != nil {
		return result, errCredentialDelivery
	}
	err := WriteFrame(conn, command)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return result, errCredentialDelivery
	}
	select {
	case reply := <-pending.done:
		phase = ErrCredentialAdvanceReply
		if !reply.ready && (reply.stage == "unavailable" || reply.stage == "challenge" || reply.stage == "pending" || reply.stage == "rejected") && reply.identity.DocumentID != "" && admit(ctx) == nil && b.verifyChannelProcess(ctx, c) == nil && g.controlCheck(ctx, p, a, c, false) == nil {
			b.mu.Lock()
			valid := c.privateFlow == flow && !flow.poisoned && c.conn == conn && len(c.unknown) == 0
			if valid {
				c.privateAdvance = nil
				flow.sameDocumentPrivacy = reply.stage == "unavailable" && reply.identity.DocumentID == a.Document.DocumentID
				completed = true
			}
			b.mu.Unlock()
			if valid {
				if reply.stage == "pending" {
					return CredentialAdvanceResult{Stage: "pending"}, ErrCredentialPostSubmitPending
				}
				if reply.stage == "rejected" {
					return CredentialAdvanceResult{Stage: "rejected"}, ErrCredentialLoginRejected
				}
				if reply.stage == "challenge" {
					return CredentialAdvanceResult{Stage: "challenge"}, ErrCredentialNativeChallenge
				}
				return CredentialAdvanceResult{Stage: "privacyCandidate"}, ErrCredentialPrivacyCandidate
			}
		}
		if !reply.ready || admit(ctx) != nil || b.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, false) != nil {
			return CredentialAdvanceResult{Stage: reply.stage}, errCredentialDelivery
		}
		next := a
		// A recipient pin is document-local and cannot follow a login step
		// into another renderer. The existing continuation protocol retains
		// its strict generation checks until a new recipient is inspected.
		next.PrivateRecipientID = ""
		next.Document.Identity = reply.identity
		next.Document.Title = ""
		next.Lease = nextLease
		g.controlMu.Lock()
		defer g.controlMu.Unlock()
		record := g.controlRecordLocked(a)
		if record == nil || !sameControl(*record.authority, a) || record.retiring {
			return result, errCredentialDelivery
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if c.privateFlow != flow || flow.poisoned || c.conn != conn || len(c.unknown) != 0 {
			return result, errCredentialDelivery
		}
		replaced := false
		for i, d := range c.documents {
			if d == a.Document {
				c.documents[i] = next.Document
				replaced = true
			}
		}
		if !replaced {
			return result, errCredentialDelivery
		}
		if nextRecord := g.controlRecordLocked(next); nextRecord != nil && nextRecord != record {
			return result, errCredentialDelivery
		}
		delete(g.controls, controlTargetOf(a))
		g.setControlLocked(next)
		c.privateAdvance = nil
		c.privateFlow = nil
		c.privateInspection = &credentialAdmissionPending{identity: next.Document.Identity, done: make(chan credentialAdmissionReply, 1)}
		completed = true
		return CredentialAdvanceResult{Authority: next, Stage: reply.stage}, nil
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
}

// CancelVaultCredential closes only the matching private channel; it never clears
// unknown reservations or returns this connection to ordinary parsing.
func (g *Gateway) CancelVaultCredential(ctx context.Context, p auth.Principal, a ControlAuthority) error {
	if g == nil || g.broker == nil || authorize(ctx, p, true) != nil {
		return errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c == nil {
		return errCredentialDelivery
	}
	actual, e := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if e != nil || actual.ClientID != a.ClientID || p.ClientID != a.ClientID || p.Namespace != a.Owner {
		return errCredentialDelivery
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.privacy != nil && bound && c.privacy.binding == binding && (sameControl(c.privacy.source, a) || sameControl(c.privacy.authority, a)) && c.conn == c.privacy.conn {
		c.privacy.active = false
		return c.conn.Close()
	}
	if c.privateFlow != nil && (!bound || c.privateFlow.binding != binding) {
		return errCredentialDelivery
	}
	if c.conn == nil || (c.privateFlow == nil || !sameControl(c.privateFlow.authority, a)) && (c.privateInspection == nil || c.privateInspection.identity != a.Document.Identity) {
		return errCredentialDelivery
	}
	if c.privateFlow != nil {
		c.privateFlow.poisoned = true
	}
	return c.conn.Close()
}

// Closed phases diagnose metadata reads without changing private authority.
var ErrCredentialAdvanceAdmission = errors.New("private post-submit admission unavailable")
var ErrCredentialAdvanceControl = errors.New("private post-submit control authority unavailable")
var ErrCredentialAdvanceFlow = errors.New("private post-submit flow unavailable")
var ErrCredentialAdvanceTransport = errors.New("private post-submit transport unavailable")
var ErrCredentialAdvanceReply = errors.New("private post-submit reply unavailable")

func CredentialAdvanceAttention(err error) string {
	for _, entry := range []struct {
		err  error
		code string
	}{{ErrCredentialAdvanceAdmission, "postSubmitAdmissionUnavailable"}, {ErrCredentialAdvanceControl, "postSubmitControlAuthorityUnavailable"}, {ErrCredentialAdvanceFlow, "postSubmitFlowUnavailable"}, {ErrCredentialAdvanceTransport, "postSubmitTransportUnavailable"}, {ErrCredentialAdvanceReply, "postSubmitReplyUnavailable"}} {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	return "postSubmitAdvanceUnavailable"
}
