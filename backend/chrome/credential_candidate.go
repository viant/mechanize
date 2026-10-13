package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// Quarantined origins advertise only closed routing metadata to the signed
// broker. These candidates never enter ordinary tab lists or observations.
type credentialCandidate struct {
	Identity
	Origin string `json:"origin"`
}

// Closed admission reasons contain no renderer, page or credential data.
var ErrCredentialCandidateUnavailable = errors.New("credential candidate unavailable")
var ErrCredentialCandidateAmbiguous = errors.New("credential candidate ambiguous")
var ErrCredentialChannelBusy = errors.New("credential channel busy")

func (c *credentialCandidate) UnmarshalJSON(raw []byte) error {
	type wire credentialCandidate
	if !uniqueCredentialJSON(raw) {
		return errCredentialDelivery
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var v wire
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return errCredentialDelivery
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || len(keys) != 7 {
		return errCredentialDelivery
	}
	*c = credentialCandidate(v)
	return nil
}
func (c credentialCandidate) document() Document {
	return Document{Identity: c.Identity, Origin: c.Origin, MutationFingerprintVersion: 2}
}
func (c credentialCandidate) valid(e Enrollment) bool {
	return c.ProfileChannel == e.ProfileChannel && c.BrowserInstance == e.BrowserInstance && c.TabID > 0 && c.FrameID == 0 && fingerprintV2ID.MatchString(c.DocumentID) && c.Generation > 0 && c.Generation <= 9007199254740991 && strings.HasPrefix(c.Origin, "https://") && OrdinaryWebsiteOrigin(c.Origin) && allowedOrigin(e, c.Origin)
}

// This selection performs no renderer probe or input. The caller must retain
// exposure protection before the actual private inspection starts.
func (g *Gateway) credentialControlSnapshot(ctx context.Context, p auth.Principal, s model.Surface) (ControlAuthority, *channel, error) {
	if authorize(ctx, p, true) != nil || s.Kind != "web" || s.BundleID != "" || s.Title != "" || s.ValidateProcessIdentity() != nil || !OrdinaryWebsiteOrigin(s.Origin) || !strings.HasPrefix(s.Origin, "https://") {
		return ControlAuthority{}, nil, errCredentialDelivery
	}
	b := g.broker
	b.mu.Lock()
	var selected *channel
	var doc Document
	count := 0
	busy := false
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace && c.conn != nil && (c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privacy != nil || c.privateAdvance != nil || c.lifecycleInhibited || len(c.pending) > 0 || len(c.unknown) > 0) {
			busy = true
		}
		if c.grant.Principal.Namespace != p.Namespace || c.conn == nil || c.fixtureOnly || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete || !c.grant.Principal.HasScope("desktop:control") || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privacy != nil || c.privateAdvance != nil || c.lifecycleInhibited || len(c.pending) > 0 || len(c.unknown) > 0 {
			continue
		}
		seen := map[string]bool{}
		candidates := append([]Document(nil), c.documents...)
		for _, candidate := range c.credentialCandidates {
			candidates = append(candidates, candidate.document())
		}
		for _, d := range candidates {
			if d.Origin != s.Origin || d.FrameID != 0 || !allowedOrigin(c.grant, d.Origin) || (s.TabID != "" && s.TabID != d.QualifiedTabID()) || seen[d.QualifiedTabID()+"/"+d.DocumentID] {
				continue
			}
			seen[d.QualifiedTabID()+"/"+d.DocumentID] = true
			selected = c
			doc = d
			count++
		}
	}
	b.mu.Unlock()
	if count != 1 || selected == nil {
		if count > 1 {
			return ControlAuthority{}, nil, ErrCredentialCandidateAmbiguous
		}
		if busy {
			return ControlAuthority{}, nil, ErrCredentialChannelBusy
		}
		return ControlAuthority{}, nil, ErrCredentialCandidateUnavailable
	}
	if err := b.verifyChannelProcess(ctx, selected); err != nil {
		return ControlAuthority{}, nil, errCredentialDelivery
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c := selected
	if b.closed || c.conn == nil || c.processEvidence == nil || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete {
		return ControlAuthority{}, nil, errCredentialDelivery
	}
	e := *c.processEvidence
	e.Ancestors = append([]session.ProcessIdentity(nil), e.Ancestors...)
	return ControlAuthority{AllWebsites: c.grant.AllWebsites, MutationFingerprintVersion: c.mutationFingerprintVersion, SelectOptionVersion: c.selectOptionVersion, TrustScope: c.grant.TrustScope, ScopeQualified: true, Owner: p.Namespace, ClientID: p.ClientID, ExtensionOrigin: c.grant.ExtensionOrigin, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Document: doc, Evidence: e, ProfileQualified: c.profileQualified, ExtensionQualified: c.grant.ExtensionOrigin != "", DocumentQualified: true, ExecutorQualified: true}, c, nil
}
func (g *Gateway) CredentialCandidateAvailable(ctx context.Context, p auth.Principal, s model.Surface) error {
	if g == nil || g.broker == nil {
		return errors.New("private credential candidate unavailable")
	}
	_, _, err := g.credentialControlSnapshot(ctx, p, s)
	return err
}
