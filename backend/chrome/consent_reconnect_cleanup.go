package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
)

// This is retained handshake evidence, not a cache of BrowserStatus. It can be
// minted only when the authenticated worker's prior grant forces its complete
// prepare/adopt reconnect path. Initial binding and an empty registry never mint it.
type consentReconnectProof struct {
	conn                                            net.Conn
	peer                                            nativepeer.ChromeProcessEvidence
	challenge, brokerEpoch, channelEpoch, scopeHash string
	prepared, inventoried                           bool
	documents                                       []Document
}

var ErrConsentReconnectProof = errors.New("complete unchanged browser reconnect cleanup proof unavailable")

func newConsentReconnectProof(c *channel, conn net.Conn, brokerEpoch string, previous json.RawMessage) *consentReconnectProof {
	var old struct {
		BrokerEpoch      string `json:"brokerEpoch"`
		ChannelEpoch     string `json:"channelEpoch"`
		ScopeHash        string `json:"scopeHash"`
		TrustScope       string `json:"trustScope"`
		ScopeQualified   bool   `json:"scopeQualified"`
		ProfileQualified bool   `json:"profileQualified"`
		LeaseRequired    bool   `json:"leaseRequired"`
		Fingerprint      int    `json:"mutationFingerprintVersion"`
	}
	if len(previous) > 2048 || c == nil || conn == nil || c.fixtureOnly || c.workerBuild != 32 || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) ||
		!reconnectTopFields(previous, "brokerEpoch", "channelEpoch", "scopeHash", "trustScope", "scopeQualified", "profileQualified", "leaseRequired", "mutationFingerprintVersion") || decodeReconnectClosed(previous, &old) != nil ||
		!receiptOpaqueID.MatchString(old.BrokerEpoch) || !receiptOpaqueID.MatchString(old.ChannelEpoch) || old.ScopeHash != c.scopeHash || old.TrustScope != c.grant.TrustScope || !old.ScopeQualified || old.ProfileQualified != c.profileQualified || !old.LeaseRequired || old.Fingerprint != 2 || old.BrokerEpoch == brokerEpoch && old.ChannelEpoch == c.epoch {
		return nil
	}
	return &consentReconnectProof{conn: conn, peer: *c.processEvidence, challenge: c.executorChallenge, brokerEpoch: brokerEpoch, channelEpoch: c.epoch, scopeHash: c.scopeHash}
}
func consentReconnectDocuments(documents []Document) []Document {
	result := make([]Document, len(documents))
	for i, d := range documents {
		result[i] = Document{Identity: d.Identity, Origin: d.Origin, MutationFingerprintVersion: d.MutationFingerprintVersion}
	}
	return result
}
func (c *channel) observeConsentReconnectInventory() {
	proof := c.consentReconnect
	if proof == nil || !proof.prepared {
		return
	}
	current := consentReconnectDocuments(c.documents)
	if proof.inventoried && !reflect.DeepEqual(proof.documents, current) {
		c.consentReconnect = nil
		return
	}
	proof.inventoried = true
	proof.documents = current
}
func (c *channel) invalidateConsentReconnect() { c.consentReconnect = nil }
func (b *Broker) consentReconnectValidLocked(c *channel, proof *consentReconnectProof) bool {
	return proof != nil && c.consentReconnect == proof && proof.prepared && proof.inventoried && !b.closed && c.conn == proof.conn && c.processEvidence != nil && c.processEvidence.KernelPeerQualified && c.processEvidence.NativeHost == proof.peer.NativeHost && c.processEvidence.ChromeParent == proof.peer.ChromeParent &&
		b.epoch == proof.brokerEpoch && c.epoch == proof.channelEpoch && c.scopeHash == proof.scopeHash && c.executorChallenge == proof.challenge && channelScopeQualified(c) && c.executorQualified && c.inventoryComplete && !c.lifecycleInhibited && c.lifecycleGuard == nil &&
		len(c.pending) == 0 && len(c.unknown) == 0 && len(c.attempts) == 0 && len(c.receipts) == 0 && !c.controllerCleanupPending && c.playwright == nil && c.privateInspection == nil && c.privateCredential == nil && c.privateAdvance == nil && c.privateFlow == nil && c.privacy == nil && c.privacyPending == nil && c.manualPending == nil && c.manualTransition == nil && c.openOriginPending == nil &&
		reflect.DeepEqual(proof.documents, consentReconnectDocuments(c.documents))
}
func lockConsentReconnect(ctx context.Context, mu *sync.Mutex) error {
	for !mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		mu.Unlock()
		return err
	}
	return nil
}

// WithConsentReconnectProof holds the existing browser admission/write lanes
// through the trusted consent CAS. It sends no renderer command and retires no
// business effect. Every enrolled channel in the namespace must independently
// carry a complete, current reconnect proof. Missing/foreign scopes fail closed.
func (g *Gateway) WithConsentReconnectProof(ctx context.Context, p auth.Principal, commit func() error) error {
	if g == nil || g.broker == nil || commit == nil || authorize(ctx, p, true) != nil {
		return auth.ErrUnauthorized
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.ClientID == "" || actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	select {
	case g.admissionLane <- struct{}{}:
		defer func() { <-g.admissionLane }()
	case <-ctx.Done():
		return ctx.Err()
	}
	b := g.broker
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return ctx.Err()
	}
	g.controlMu.Lock()
	busy := g.control != nil || g.controlRetiring
	g.controlMu.Unlock()
	if busy {
		return ErrConsentReconnectProof
	}
	b.mu.Lock()
	channels := []*channel{}
	proofs := []*consentReconnectProof{}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace {
			channels = append(channels, c)
			proofs = append(proofs, c.consentReconnect)
		}
	}
	b.mu.Unlock()
	if len(channels) == 0 || len(channels) > 64 {
		return ErrConsentReconnectProof
	}
	// The global admission lane serializes acquisitions, so this fixed set cannot
	// deadlock another proof guard's per-channel write locks.
	for i, c := range channels {
		if err = b.verifyChannelProcess(ctx, c); err != nil {
			return ErrConsentReconnectProof
		}
		if err = lockConsentReconnect(ctx, &c.writeMu); err != nil {
			return err
		}
		defer c.writeMu.Unlock()
		b.mu.Lock()
		valid := b.consentReconnectValidLocked(c, proofs[i])
		b.mu.Unlock()
		if !valid {
			return ErrConsentReconnectProof
		}
	}
	// No command can cross the held channel write lanes. Keep metadata publication
	// serialized with the exact final proof and generated consent CAS as well.
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range channels {
		if b.channels[channelKey(c.grant.ProfileChannel, c.grant.BrowserInstance)] != c || !b.consentReconnectValidLocked(c, proofs[i]) {
			return ErrConsentReconnectProof
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return commit()
}
