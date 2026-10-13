package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type credentialAdmissionReply struct {
	inspectionReason   string
	recipientID        string
	identity           Identity
	ready              bool
	stage              string
	acquisitionFailure string
}
type credentialAdmissionPending struct {
	knownNoInput bool // set only after a validated negative inspection reply, before acquire

	diagnostics bool
	recipientID string
	requestID   string
	identity    Identity
	lease       *Lease
	done        chan credentialAdmissionReply
}

func decodeCredentialAdmission(raw []byte, p *credentialAdmissionPending) credentialAdmissionReply {
	empty := credentialAdmissionReply{}
	if p.diagnostics {
		empty.inspectionReason = "replyInvalid"
	}
	if len(raw) > 4096 || !uniqueCredentialJSON(raw) {
		return empty
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return empty
	}
	var identityKeys map[string]json.RawMessage
	if json.Unmarshal(keys["identity"], &identityKeys) != nil || len(identityKeys) != 6 {
		return empty
	}
	for _, k := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"} {
		if v, ok := identityKeys[k]; !ok || bytes.Equal(v, []byte("null")) {
			return empty
		}
	}
	var r struct {
		Type             string   `json:"type"`
		RequestID        string   `json:"requestId"`
		Identity         Identity `json:"identity"`
		Ready            *bool    `json:"ready"`
		Validated        *bool    `json:"validated"`
		Lease            *Lease   `json:"controlLease"`
		Stage            *string  `json:"stage"`
		Protocol         *int     `json:"privateCredentialProtocolVersion"`
		RecipientID      string   `json:"recipientId,omitempty"`
		ErrorCode        string   `json:"errorCode,omitempty"`
		InspectionReason string   `json:"inspectionReason,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty
	}
	if r.RequestID != p.requestID {
		if p.diagnostics {
			empty.inspectionReason = "replyCorrelationUnavailable"
		}
		return empty
	}
	expected := p.identity
	expected.Generation = r.Identity.Generation
	if r.Identity != expected || r.Identity.Generation < p.identity.Generation || r.Identity.Generation > 9007199254740991 {
		return empty
	}
	if p.lease == nil {
		fields, version := 6, 2
		if p.recipientID != "" {
			fields, version = 7, 3
			if !fingerprintV2Hash.MatchString(p.recipientID) || r.RecipientID != p.recipientID {
				return empty
			}
		} else if r.RecipientID != "" {
			return empty
		}
		if p.diagnostics {
			fields++
			if !closedInspectionReason(r.InspectionReason) || r.Ready != nil && *r.Ready && r.InspectionReason != "none" {
				return empty
			}
		} else if r.InspectionReason != "" {
			return empty
		}
		if len(keys) != fields || keys["type"] == nil || keys["requestId"] == nil || keys["identity"] == nil || keys["ready"] == nil || keys["stage"] == nil || keys["privateCredentialProtocolVersion"] == nil || r.Protocol == nil || *r.Protocol != version || r.Stage == nil || !credentialStage(*r.Stage) || r.Type != "credentialInspectResult" || r.Ready == nil || r.Validated != nil || r.Lease != nil {
			return empty
		}
		stage := *r.Stage
		if *r.Ready && !credentialInputStage(stage) {
			return empty
		}
		return credentialAdmissionReply{identity: r.Identity, ready: *r.Ready, stage: stage, recipientID: r.RecipientID, inspectionReason: r.InspectionReason}
	}
	if len(keys) == 5 && keys["errorCode"] != nil {
		if r.Type != "" || r.Ready != nil || r.Stage != nil || r.Protocol != nil || r.RecipientID != "" || r.Validated == nil || *r.Validated || r.Lease == nil || *r.Lease != *p.lease || r.Identity != p.identity || r.ErrorCode != "staleGeneration" && r.ErrorCode != "acquisitionRejected" {
			return empty
		}
		for _, key := range []string{"requestId", "identity", "validated", "controlLease", "errorCode"} {
			if keys[key] == nil {
				return empty
			}
		}
		return credentialAdmissionReply{identity: r.Identity, acquisitionFailure: r.ErrorCode}
	}
	if len(keys) != 4 || r.Type != "" || r.Ready != nil || r.Validated == nil || !*r.Validated || r.Lease == nil || *r.Lease != *p.lease || r.Identity != p.identity || r.ErrorCode != "" {
		return empty
	}
	if _, ok := keys["type"]; ok {
		return empty
	}
	return credentialAdmissionReply{identity: r.Identity, ready: true}
}

// All private admission traffic is intercepted before any generic decoder.
func (b *Broker) acceptCredentialAdmissionLocked(c *channel, raw []byte) bool {
	if c.privateInspection == nil {
		return false
	}
	defer clear(raw)
	// Keep every unclassified frame quarantined, but only the correlated reply
	// kind can complete inspection. Controller bookkeeping is not a reply.
	var envelope struct {
		Type      string `json:"type"`
		RequestID string `json:"requestId"`
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &envelope) != nil {
		return true
	}
	pending := c.privateInspection
	if pending.lease == nil {
		if envelope.Type != "credentialInspectResult" || envelope.RequestID != pending.requestID {
			return true
		}
	} else if envelope.Type != "" || envelope.RequestID != pending.requestID {
		return true
	}
	select {
	case c.privateInspection.done <- decodeCredentialAdmission(raw, c.privateInspection):
	default:
	}
	return true
}

// An inventory can already be queued on the authenticated stream when private
// quarantine starts. Discard it without decoding documents or changing any
// authority; it is neither a private reply nor permission to expose content.
func discardQuarantinedInventory(c *channel, raw []byte) bool {
	if c == nil || (c.privateInspection == nil && c.privateCredential == nil && c.privateAdvance == nil && c.privateFlow == nil && c.privacyPending == nil && (c.privacy == nil || c.privacy.active)) {
		return false
	}
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "documents" {
		return false
	}
	clear(raw)
	return true
}

// AdmitCredentialControl establishes a normal retained renderer lease through a
// closed metadata-only credential inspector. It never calls public Observe.
// admit is a trusted host callback checking actual durable consent and held
// exposure protection on every probe/acquire; nil cannot activate this route.
func (g *Gateway) AdmitCredentialControl(ctx context.Context, p auth.Principal, surface model.Surface, admit func(context.Context) error) (result ControlAdmission, err error) {
	result.FailureStage = "candidate"
	defer func() {
		if recover() != nil {
			err = errCredentialDelivery
		}
	}()
	if g == nil || g.broker == nil || admit == nil || surface.Kind != "web" || !strings.HasPrefix(surface.Origin, "https://") || !OrdinaryWebsiteOrigin(surface.Origin) {
		return result, errCredentialDelivery
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.GrantID == "" || binding.Purpose == "" {
		return result, errCredentialDelivery
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	select {
	case g.admissionLane <- struct{}{}:
		defer func() { <-g.admissionLane }()
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
	b := g.broker
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
	if admit(ctx) != nil {
		return result, errCredentialDelivery
	}
	a, c, e := g.credentialControlSnapshot(ctx, p, surface)
	if e != nil || a.Document.FrameID != 0 || a.Document.Generation == 0 {
		return result, errCredentialDelivery
	}
	g.controlMu.Lock()
	result.FailureStage = "authority"
	busy := g.controlRetiring
	if g.control != nil {
		a.Lease = g.control.Lease
		busy = busy || !sameControl(a, *g.control)
	}
	g.controlMu.Unlock()
	if busy {
		return result, errCredentialDelivery
	}
	var endBadge func()
	ctx, endBadge = b.beginControlBadge(ctx, c, a.Document.Identity)
	defer endBadge()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	b.mu.Lock()
	if c.privateInspection != nil || c.privateCredential != nil || c.lifecycleInhibited || len(c.pending) != 0 || len(c.unknown) != 0 {
		b.mu.Unlock()
		return result, errCredentialDelivery
	}
	conn := c.conn
	c.privateOwner = p
	c.privateConsent, _ = auth.ConsentBindingFromContext(ctx)
	// Seal private demultiplexing before retaining a candidate in the live lease.
	c.invalidateConsentReconnect()
	c.privateInspection = &credentialAdmissionPending{done: make(chan credentialAdmissionReply, 1)}
	found := false
	for _, d := range c.documents {
		if d == a.Document {
			found = true
			break
		}
	}
	if !found {
		c.documents = append(c.documents, a.Document)
	}
	b.mu.Unlock()
	// On any uncertain stage keep the raw interceptor until connection teardown.
	completed := false
	defer func() {
		if !completed {
			_ = conn.Close()
		}
		// Keep the private interceptor after admission. Only private delivery or
		// connection teardown can follow; delayed inspector echoes cannot enter
		// ordinary observations. Existing lease metadata remains retained.
	}()
	exchange := func(payload any, pending *credentialAdmissionPending) (credentialAdmissionReply, error) {
		if ctx.Err() != nil || admit(ctx) != nil || b.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, false) != nil {
			return credentialAdmissionReply{}, errCredentialDelivery
		}
		b.mu.Lock()
		if len(c.pending) != 0 || len(c.unknown) != 0 || c.lifecycleInhibited || c.conn != conn {
			b.mu.Unlock()
			return credentialAdmissionReply{}, errCredentialDelivery
		}
		c.invalidateConsentReconnect()
		c.privateInspection = pending
		b.mu.Unlock()
		if conn.SetWriteDeadline(deadline) != nil {
			return credentialAdmissionReply{}, errCredentialDelivery
		}
		e := WriteFrame(conn, payload)
		_ = conn.SetWriteDeadline(time.Time{})
		if e != nil {
			return credentialAdmissionReply{}, errCredentialDelivery
		}
		select {
		case reply := <-pending.done:
			if pending.diagnostics && closedInspectionReason(reply.inspectionReason) {
				result.FailureReason = reply.inspectionReason
			}
			if reply.identity.DocumentID == "" || admit(ctx) != nil || b.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, false) != nil {
				return credentialAdmissionReply{}, errCredentialDelivery
			}
			return reply, nil
		case <-ctx.Done():
			return credentialAdmissionReply{}, errCredentialDelivery
		}
	}
	requestID := newPrivateID()
	b.mu.Lock()
	diagnostics := c.privateInspectionDiagnosticVersion == 1
	if c.workerBuild == 22 || c.workerBuild == 23 || c.workerBuild == 24 || c.workerBuild == 25 || c.workerBuild == 26 || c.workerBuild == 27 || c.workerBuild == 28 || c.workerBuild == 29 || c.workerBuild == 30 || c.workerBuild == 31 || c.workerBuild == 32 {
		a.PrivateRecipientID = newPrivateID()
	}
	b.mu.Unlock()
	result.FailureStage = "inspection"
	result.FailureReason = "replyUnavailable"
	probe := struct {
		Type         string   `json:"type"`
		RequestID    string   `json:"requestId"`
		Identity     Identity `json:"identity"`
		BrokerEpoch  string   `json:"brokerEpoch"`
		ChannelEpoch string   `json:"channelEpoch"`
		ScopeHash    string   `json:"scopeHash"`
		Deadline     int64    `json:"deadlineUnixMs"`
		Origin       string   `json:"origin"`
		RecipientID  string   `json:"recipientId,omitempty"`
		Diagnostics  bool     `json:"diagnostics,omitempty"`
	}{"credentialInspect", requestID, a.Document.Identity, a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash, deadline.UnixMilli(), a.Document.Origin, a.PrivateRecipientID, diagnostics}
	inspected, e := exchange(probe, &credentialAdmissionPending{diagnostics: probe.Diagnostics, requestID: requestID, identity: a.Document.Identity, recipientID: a.PrivateRecipientID, done: make(chan credentialAdmissionReply, 1)})
	result.CredentialStage = inspected.stage
	if e == nil {
		result.FailureReason = inspected.inspectionReason
	}
	if e == nil && !inspected.ready {
		// This closed correlated reply proves no acquisition/input occurred.
		// Retain quarantine until the typed zero-child retirement, while allowing
		// the original controller request to receive its finite diagnostic.
		b.mu.Lock()
		if c.conn == conn && c.privateInspection != nil && c.privateInspection.requestID == requestID && c.privateInspection.lease == nil {
			c.privateInspection.knownNoInput = true
			result.PreflightNoInput = true
			completed = true
		}
		b.mu.Unlock()
		return result, errCredentialDelivery
	}
	if e != nil {
		return result, errCredentialDelivery
	}
	b.mu.Lock()
	updated := false
	for i, d := range c.documents {
		if d == a.Document {
			c.documents[i].Generation = inspected.identity.Generation
			updated = true
		}
	}
	b.mu.Unlock()
	if !updated {
		return result, errCredentialDelivery
	}
	a.Document.Generation = inspected.identity.Generation
	g.controlMu.Lock()
	if g.controlRetiring {
		g.controlMu.Unlock()
		return result, errCredentialDelivery
	}
	if g.control != nil {
		a.Lease = g.control.Lease
		if !sameControl(a, *g.control) {
			g.controlMu.Unlock()
			return result, errCredentialDelivery
		}
	} else {
		g.controlGeneration++
		a.Lease = Lease{ID: newID(), Generation: g.controlGeneration}
		copy := a
		g.control = &copy
		result.Created = true
	}
	g.controlMu.Unlock()
	result.Authority = a
	result.CredentialStage = inspected.stage
	for acquireAttempt := 0; acquireAttempt < 3; acquireAttempt++ {
		requestID = newPrivateID()
		result.FailureStage = "acquisition"
		acquire := Command{RequestID: requestID, Action: "executor.acquire", Identity: a.Document.Identity, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, DeadlineUnixMS: deadline.UnixMilli(), ControlLease: &a.Lease}
		acquired, e := exchange(acquire, &credentialAdmissionPending{requestID: requestID, identity: a.Document.Identity, lease: &a.Lease, done: make(chan credentialAdmissionReply, 1)})
		if e != nil {
			return result, errCredentialDelivery
		}
		if acquired.ready {
			if g.VerifyControl(ctx, p, a) != nil || admit(ctx) != nil {
				return result, errCredentialDelivery
			}
			break
		}
		if acquired.acquisitionFailure != "staleGeneration" || a.PrivateRecipientID == "" || acquireAttempt == 2 || ctx.Err() != nil {
			return result, errCredentialDelivery
		}
		// Reinspect the SAME private recipient pin and retained lease. The worker
		// must prove it is still current; no replacement form/target is selected.
		result.FailureStage = "inspection"
		probe.RequestID = newPrivateID()
		probe.Identity = a.Document.Identity
		refreshed, e := exchange(probe, &credentialAdmissionPending{diagnostics: probe.Diagnostics, requestID: probe.RequestID, identity: a.Document.Identity, recipientID: a.PrivateRecipientID, done: make(chan credentialAdmissionReply, 1)})
		if e != nil || !refreshed.ready || refreshed.recipientID != a.PrivateRecipientID || refreshed.stage != inspected.stage || refreshed.identity.Generation <= a.Document.Generation {
			return result, errCredentialDelivery
		}
		g.controlMu.Lock()
		b.mu.Lock()
		valid := g.control != nil && !g.controlRetiring && sameControl(*g.control, a) && c.conn == conn && len(c.pending) == 0 && len(c.unknown) == 0 && !c.lifecycleInhibited
		updated := false
		if valid {
			for i, d := range c.documents {
				if d == a.Document {
					c.documents[i].Generation = refreshed.identity.Generation
					updated = true
				}
			}
		}
		if updated {
			a.Document.Generation = refreshed.identity.Generation
			copy := a
			g.control = &copy
		}
		b.mu.Unlock()
		g.controlMu.Unlock()
		if !valid || !updated {
			return result, errCredentialDelivery
		}
		result.Authority = a
		result.CredentialStage = refreshed.stage
	}
	result.Confirmed = true
	result.FailureStage = ""
	result.FailureReason = ""
	completed = true
	return result, nil
}
