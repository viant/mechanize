package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

// CredentialNavigationID binds a private Vault recipient to the exact admitted
// channel, renderer incarnation, DOM generation and retained control lease.
// It hashes public authority metadata only, never credential bytes.
func CredentialNavigationID(a ControlAuthority) string {
	version := "mechanize-credential-recipient-v1"
	if a.PrivateRecipientID != "" {
		version = "mechanize-credential-recipient-v2"
	}
	raw, err := json.Marshal(struct {
		Version                                       string
		Broker, Channel, Scope, Owner, Client, Origin string
		Recipient                                     string `json:"recipientId,omitempty"`
		Identity                                      Identity
		Lease                                         Lease
	}{version, a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash, a.Owner, a.ClientID, a.Document.Origin, a.PrivateRecipientID, a.Document.Identity, a.Lease})
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// FreshCredentialBinding is a Manager.Hooks.Fresh adapter for an already-held
// secure renderer lease. It performs one metadata-only inspector exchange and
// returns the original binding only on exact equality. It never observes page
// content, adopts a new generation, acquires a lease, or clears quarantine.
func (g *Gateway) FreshCredentialBinding(ctx context.Context, p auth.Principal, a ControlAuthority, binding vault.Binding, admit func(context.Context) error) (result vault.Binding, err error) {
	defer func() {
		if recover() != nil {
			result = vault.Binding{}
			err = errCredentialDelivery
		}
	}()
	if g == nil || g.broker == nil || admit == nil || binding.Target.Validate() != nil || binding.Target.Origin != a.Document.Origin ||
		binding.DocumentID != a.Document.DocumentID || binding.NavigationID != CredentialNavigationID(a) || a.Document.FrameID != 0 ||
		a.Document.Generation == 0 || a.Lease.ID == "" || a.Lease.Generation == 0 || !strings.HasPrefix(a.Document.Origin, "https://") || !OrdinaryWebsiteOrigin(a.Document.Origin) {
		return result, errCredentialDelivery
	}
	cb, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || cb.SessionID == "" || cb.SessionID != binding.SessionID || cb.GrantID == "" || cb.Purpose == "" {
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
	if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c == nil {
		return result, errCredentialDelivery
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return result, errCredentialDelivery
	}
	b.mu.Lock()
	old := c.privateInspection
	if old == nil || old.identity != a.Document.Identity || old.lease != nil && *old.lease != a.Lease ||
		c.privateCredential != nil || c.lifecycleInhibited || len(c.pending) != 0 || len(c.unknown) != 0 || c.conn == nil || b.closed {
		b.mu.Unlock()
		return result, errCredentialDelivery
	}
	conn := c.conn
	pending := &credentialAdmissionPending{requestID: newPrivateID(), identity: a.Document.Identity, recipientID: a.PrivateRecipientID, done: make(chan credentialAdmissionReply, 1)}
	c.privateInspection = pending
	b.mu.Unlock()
	confirmed := false
	defer func() {
		if !confirmed {
			_ = conn.Close()
		}
	}()
	probe := struct {
		Type         string   `json:"type"`
		RequestID    string   `json:"requestId"`
		Identity     Identity `json:"identity"`
		BrokerEpoch  string   `json:"brokerEpoch"`
		ChannelEpoch string   `json:"channelEpoch"`
		ScopeHash    string   `json:"scopeHash"`
		Deadline     int64    `json:"deadlineUnixMs"`
		Origin       string   `json:"origin"`
		ControlLease Lease    `json:"controlLease"`
		RecipientID  string   `json:"recipientId,omitempty"`
	}{"credentialInspect", pending.requestID, a.Document.Identity, a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash, deadline.UnixMilli(), a.Document.Origin, a.Lease, a.PrivateRecipientID}
	if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil || conn.SetWriteDeadline(deadline) != nil {
		return result, errCredentialDelivery
	}
	writeErr := WriteFrame(conn, probe)
	_ = conn.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		return result, errCredentialDelivery
	}
	select {
	case reply := <-pending.done:
		identity := reply.identity
		if a.PrivateRecipientID != "" && reply.recipientID == a.PrivateRecipientID && identity.Generation >= a.Document.Generation {
			identity.Generation = a.Document.Generation
		}
		if !reply.ready || identity != a.Document.Identity || ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
			return result, errCredentialDelivery
		}
	case <-ctx.Done():
		return result, errCredentialDelivery
	}
	b.mu.Lock()
	current := c.conn == conn && c.privateInspection == pending && c.privateCredential == nil && !c.lifecycleInhibited && len(c.pending) == 0 && len(c.unknown) == 0 && !b.closed
	b.mu.Unlock()
	if !current {
		return result, errCredentialDelivery
	}
	confirmed = true
	return binding, nil
}
