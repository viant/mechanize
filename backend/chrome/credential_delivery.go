package chrome

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

var errCredentialDelivery = errors.New("private credential delivery unavailable")

// CredentialDeliveryResult contains only dispatch knowledge, never login success.
// The caller must retain unknown durably and must not automatically replay.
type CredentialDeliveryResult struct {
	DispatchState string `json:"dispatchState"`
	FailureStage  string `json:"-"`
}

type credentialPayload struct{ username, password []byte }

func (credentialPayload) MarshalJSON() ([]byte, error) { return nil, errCredentialDelivery }
func (credentialPayload) String() string               { return "[private credential withheld]" }
func (credentialPayload) GoString() string             { return "[private credential withheld]" }
func (credentialPayload) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[private credential withheld]"))
}

type credentialDeliveryPending struct {
	requestID, attemptID string
	identity             Identity
	done                 chan string
	replyType            string
	replied, failed      bool
	lease                *Lease
}

// acceptCredentialDeliveryLocked is called BEFORE generic event decoding. While
// private delivery is pending, any nonconforming frame fails closed; raw data is
// wiped and can never become public Nodes, Value, Error, receipts or documents.
func (b *Broker) acceptCredentialDeliveryLocked(c *channel, raw []byte) bool {
	p := c.privateCredential
	if p == nil {
		return false
	}
	defer clear(raw)
	state := decodeCredentialDeliveryReply(raw, p)
	if p.replied || state == "unknown" {
		p.failed = true
		if c.unknown != nil {
			c.unknown[p.attemptID] = true
		}
		state = "unknown"
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
	p.replied = true
	select {
	case p.done <- state:
	default:
	}
	return true
}
func credentialReplyType(p *credentialDeliveryPending) string {
	if p.replyType != "" {
		return p.replyType
	}
	return "credentialDeliveryResult"
}
func decodeCredentialDeliveryReply(raw []byte, p *credentialDeliveryPending) string {
	if len(raw) > 4096 {
		return "unknown"
	}
	var r struct {
		Type      string   `json:"type"`
		RequestID string   `json:"requestId"`
		AttemptID string   `json:"attemptId"`
		Identity  Identity `json:"identity"`
		Status    string   `json:"status"`
		Retired   *bool    `json:"retiredAuthorityQuiesced"`
		Lease     *Lease   `json:"controlLease"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Type != credentialReplyType(p) || r.RequestID != p.requestID || r.AttemptID != p.attemptID || r.Identity != p.identity {
		return "unknown"
	}
	// Check the closed representation for duplicate keys and omitted zero-valued
	// identity fields; whitespace/key order remain immaterial.
	var original map[string]json.RawMessage
	expectedFields := 5
	if p.replyType == "credentialSubmitResult" {
		expectedFields = 7
	}
	if json.Unmarshal(raw, &original) != nil || len(original) != expectedFields {
		return "unknown"
	}
	if p.replyType == "credentialSubmitResult" {
		if r.Retired == nil || r.Lease == nil || p.lease == nil || *r.Lease != *p.lease || r.Status == "dispatched" && !*r.Retired {
			return "unknown"
		}
	} else if r.Retired != nil || r.Lease != nil {
		return "unknown"
	}
	var identityFields map[string]json.RawMessage
	if json.Unmarshal(original["identity"], &identityFields) != nil || len(identityFields) != 6 {
		return "unknown"
	}
	for _, key := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"} {
		if value, ok := identityFields[key]; !ok || bytes.Equal(value, []byte("null")) {
			return "unknown"
		}
	}
	if !uniqueCredentialJSON(raw) {
		return "unknown"
	}
	if r.Status != "dispatched" && r.Status != "notDispatched" {
		return "unknown"
	}
	return r.Status
}
func uniqueCredentialJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var object func() bool
	object = func() bool {
		t, e := d.Token()
		if e != nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' {
				return false
			}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				key, ok := k.(string)
				if e != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !object() {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim('}')
		}
		return true
	}
	return object()
}

// encodeCredentialDelivery is the sole secret serialization boundary. It never
// marshals credentialPayload; returned bytes are synchronous transport-only.
func encodeCredentialDelivery(a ControlAuthority, p *credentialDeliveryPending, deadline time.Time, secret credentialPayload) ([]byte, error) {
	if len(secret.username) == 0 || len(secret.password) == 0 || len(secret.username)+len(secret.password) > 64*1024 || !utf8.Valid(secret.username) || !utf8.Valid(secret.password) || bytes.ContainsRune(secret.username, 0) || bytes.ContainsRune(secret.password, 0) {
		return nil, errCredentialDelivery
	}
	header := struct {
		Type         string   `json:"type"`
		RequestID    string   `json:"requestId"`
		AttemptID    string   `json:"attemptId"`
		Identity     Identity `json:"identity"`
		BrokerEpoch  string   `json:"brokerEpoch"`
		ChannelEpoch string   `json:"channelEpoch"`
		ScopeHash    string   `json:"scopeHash"`
		ControlLease Lease    `json:"controlLease"`
		Deadline     int64    `json:"deadlineUnixMs"`
		Origin       string   `json:"origin"`
		RecipientID  string   `json:"recipientId,omitempty"`
	}{"credentialDelivery", p.requestID, p.attemptID, p.identity, a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash, a.Lease, deadline.UnixMilli(), a.Document.Origin, a.PrivateRecipientID}
	raw, err := json.Marshal(header)
	if err != nil {
		return nil, errCredentialDelivery
	}
	// JSON's base64 []byte representation is deliberately avoided: the receiver
	// accepts exact UTF-8 strings. These short-lived copies never enter a journal.
	u, err := json.Marshal(string(secret.username))
	if err != nil {
		clear(raw)
		return nil, errCredentialDelivery
	}
	defer clear(u)
	pw, err := json.Marshal(string(secret.password))
	if err != nil {
		clear(raw)
		return nil, errCredentialDelivery
	}
	defer clear(pw)
	raw = append(raw[:len(raw)-1], `,"username":`...)
	raw = append(raw, u...)
	raw = append(raw, `,"password":`...)
	raw = append(raw, pw...)
	raw = append(raw, '}')
	if len(raw) > MaxFrameBytes {
		clear(raw)
		return nil, errCredentialDelivery
	}
	return raw, nil
}
func writeCredentialDelivery(w io.Writer, raw []byte) error {
	var h [4]byte
	binary.NativeEndian.PutUint32(h[:], uint32(len(raw)))
	for _, part := range [][]byte{h[:], raw} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil || n <= 0 || n > len(part) {
				return errCredentialDelivery
			}
			part = part[n:]
		}
	}
	return nil
}

// DeliverVaultCredential is a LOCAL host integration seam, never an MCP/DSL
// operation. admit must check durable control consent and held whole-window
// exposure protection; the host must commit UNKNOWN for attemptID before calling.
// Manager.Fresh must independently validate the exact session/navigation binding.
// No default admission, plaintext parameter, automatic retry or submit exists.
func (g *Gateway) DeliverVaultCredential(ctx context.Context, p auth.Principal, a ControlAuthority, attemptID string, manager *vault.Manager, binding vault.Binding, ref vault.Reference, revision string, admit func(context.Context) error) (result CredentialDeliveryResult, err error) {
	result.DispatchState = "notDispatched"
	phase := "deliveryAdmission"
	started := false
	retained := false
	defer func() {
		if recover() != nil {
			if started {
				result.DispatchState = "unknown"
			}
			err = errCredentialDelivery
		}
		if result.DispatchState != "dispatched" {
			result.FailureStage = phase
		}
	}()
	if g == nil || g.broker == nil || manager == nil || admit == nil || !fingerprintV2Hash.MatchString(attemptID) || !fingerprintV2Hash.MatchString(revision) || !strings.HasPrefix(a.Document.Origin, "https://") || !OrdinaryWebsiteOrigin(a.Document.Origin) || a.Document.FrameID != 0 || binding.Target.Origin != a.Document.Origin || binding.DocumentID != a.Document.DocumentID || a.Lease.ID == "" || a.Lease.Generation == 0 {
		return result, errCredentialDelivery
	}
	cb, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || cb.SessionID != binding.SessionID || cb.GrantID == "" || cb.Purpose == "" || binding.NavigationID != CredentialNavigationID(a) {
		return result, errCredentialDelivery
	}
	b := g.broker
	c := g.controlChannel(a)
	if c == nil {
		return result, errCredentialDelivery
	}
	if admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var conn net.Conn
	var pending *credentialDeliveryPending
	laneHeld, writeHeld := false, false
	defer func() {
		if writeHeld {
			c.writeMu.Unlock()
		}
		if laneHeld {
			<-b.lane
		}
	}()
	defer func() {
		if pending == nil {
			return
		}
		// Once secret bytes may have been sent, no later frame on this connection
		// may return to generic parsing, even after a scalar acknowledgement.
		if started && !retained {
			_ = conn.Close()
			return
		}
		b.mu.Lock()
		if c.privateCredential == pending {
			c.privateCredential = nil
		}
		b.mu.Unlock()
	}()
	var endBadge func()
	ctx, endBadge = b.beginControlBadge(ctx, c, a.Document.Identity)
	defer endBadge()
	// A real Manager.Fresh hook exchanges private inspector frames. Run it
	// before holding the broker/write lanes or installing delivery demux, then
	// retain the existing inspection protection across the handoff. The host
	// exclusive exposure lease covers this entire operation.
	phase = "localVaultRead"
	err = manager.ConsumeRevision(ctx, binding, ref, revision, func(credentials vault.Credentials) error {
		return credentials.WithBytes(func(username, password []byte) error {
			phase = "deliveryLane"
			select {
			case b.lane <- struct{}{}:
				laneHeld = true
			case <-ctx.Done():
				return errCredentialDelivery
			}
			c.writeMu.Lock()
			writeHeld = true
			phase = "deliveryAuthority"
			if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
				return errCredentialDelivery
			}
			b.mu.Lock()
			if c.privateCredential != nil || c.lifecycleInhibited || len(c.pending) != 0 || len(c.unknown) != 0 || c.conn == nil || b.closed || c.privateCredentialAttempts[attemptID] || len(c.privateCredentialAttempts) >= 512 {
				b.mu.Unlock()
				return errCredentialDelivery
			}
			conn = c.conn
			pending = &credentialDeliveryPending{requestID: newPrivateID(), attemptID: attemptID, identity: a.Document.Identity, done: make(chan string, 1)}
			if c.privateCredentialAttempts == nil {
				c.privateCredentialAttempts = map[string]bool{}
			}
			c.privateCredentialAttempts[attemptID] = true
			c.privateCredential = pending
			b.mu.Unlock()
			phase = "deliveryEncoding"
			raw, e := encodeCredentialDelivery(a, pending, deadline, credentialPayload{username, password})
			if e != nil {
				return errCredentialDelivery
			}
			defer clear(raw)
			phase = "deliveryAuthority"
			if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
				return errCredentialDelivery
			}
			b.mu.Lock()
			c.unknown[attemptID] = true
			b.mu.Unlock()
			started = true
			phase = "deliveryTransport"
			result.DispatchState = "unknown"
			if conn.SetWriteDeadline(deadline) != nil {
				return errCredentialDelivery
			}
			defer conn.SetWriteDeadline(time.Time{})
			return writeCredentialDelivery(conn, raw)
		})
	})
	if err != nil {
		if phase == "localVaultRead" && errors.Is(err, vault.ErrStale) {
			// Fresh recipient verification runs before reading any values.
			// Do not label this failure as a local decrypt/read failure.
			phase = "privateBindingFresh"
		}
		return result, errCredentialDelivery
	}
	phase = "privateFormReply"
	select {
	case state := <-pending.done:
		if state == "unknown" || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
			return result, errCredentialDelivery
		}
		b.mu.Lock()
		if pending.failed {
			b.mu.Unlock()
			return result, errCredentialDelivery
		}
		delete(c.unknown, attemptID)
		result.DispatchState = state
		if state == "dispatched" {
			c.privateFlow = &credentialFlow{authority: a, fillAttempt: attemptID, binding: cb}
			c.privateCredential = nil
			retained = true
		}
		b.mu.Unlock()
		return result, nil
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
}
