package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"net"
	"sort"
	"time"
)

// ChannelTrust reports each independent layer. Process evidence cannot qualify
// extension-local profile claims, DOM documents or unresolved old executors.
type ChannelTrust struct {
	TrustScope        string                            `json:"trustScope"`
	ScopeQualified    bool                              `json:"scopeQualified"`
	ProfileChannel    string                            `json:"profileChannel"`
	BrowserInstance   string                            `json:"browserInstance"`
	FixtureOnly       bool                              `json:"fixtureOnly"`
	ProcessQualified  bool                              `json:"processQualified"`
	ProfileQualified  bool                              `json:"profileQualified"`
	ExecutorQualified bool                              `json:"executorQualified"`
	Evidence          *nativepeer.ChromeProcessEvidence `json:"evidence,omitempty"`
}
type chromePeerCheck func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error)

func processPeerCheck(config Config) (chromePeerCheck, error) {
	if config.FixtureEnrollment {
		if config.ProcessTrust != nil {
			return nil, errors.New("fixture and production process trust cannot be combined")
		}
		return nil, nil
	}
	if config.ProcessTrust == nil {
		return nil, errors.New("production Chrome parent/signature enrollment is not qualified")
	}
	verifier, err := nativepeer.NewChromePeerVerifier(*config.ProcessTrust)
	if err != nil {
		return nil, err
	}
	return verifier.Verify, nil
}
func (b *Broker) verifyChannelProcess(ctx context.Context, c *channel) error {
	return b.checkChannelProcess(ctx, c, true)
}

func (b *Broker) checkChannelProcess(ctx context.Context, c *channel, revokeInvalid bool) error {
	b.mu.Lock()
	conn := c.conn
	fixture := c.fixtureOnly
	expected := c.processEvidence
	trustScope := c.grant.TrustScope
	b.mu.Unlock()
	if fixture {
		return nil
	}
	unix, ok := conn.(*net.UnixConn)
	if !ok || b.verifyPeer == nil || expected == nil {
		return errors.New("signed native-host channel process proof unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	current, err := b.verifyPeer(bounded, unix)
	if err != nil || !current.KernelPeerQualified || current.NativeHost != expected.NativeHost || current.ChromeParent != expected.ChromeParent || trustScope == TrustScopeDesktop && !desktopProcessQualified(&current) {
		if revokeInvalid {
			_ = conn.Close()
		}
		return errors.Join(err, errors.New("signed Chrome process/channel identity changed"))
	}
	b.mu.Lock()
	unchanged := c.conn == conn && c.processEvidence == expected && c.grant.TrustScope == trustScope && channelScopeQualified(c)
	b.mu.Unlock()
	if !unchanged {
		return errors.New("signed channel changed during verification")
	}
	return bounded.Err()
}
func (b *Broker) ChannelTrust(ctx context.Context, p auth.Principal) ([]ChannelTrust, error) {
	if err := authorize(ctx, p, false); err != nil {
		return nil, err
	}
	b.mu.Lock()
	selected := []*channel{}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace {
			selected = append(selected, c)
		}
	}
	b.mu.Unlock()
	result := make([]ChannelTrust, 0, len(selected))
	for _, c := range selected {
		qualified := b.verifyChannelProcess(ctx, c) == nil
		b.mu.Lock()
		status := ChannelTrust{TrustScope: c.grant.TrustScope, ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, FixtureOnly: c.fixtureOnly}
		if !c.fixtureOnly && c.conn != nil && c.processEvidence != nil && qualified {
			copied := *c.processEvidence
			copied.Ancestors = append(copied.Ancestors[:0:0], c.processEvidence.Ancestors...)
			status.Evidence = &copied
			status.ProcessQualified = true
		}
		status.ProfileQualified = !c.fixtureOnly && status.ProcessQualified && c.profileQualified
		status.ScopeQualified = !c.fixtureOnly && status.ProcessQualified && channelScopeQualified(c)
		status.ExecutorQualified = status.ScopeQualified && c.executorQualified
		b.mu.Unlock()
		result = append(result, status)
	}
	return result, ctx.Err()
}
func (g *Gateway) ChannelTrust(ctx context.Context, p auth.Principal) ([]ChannelTrust, error) {
	return g.broker.ChannelTrust(ctx, p)
}

// BrowserStatus is a read-only owned-channel diagnostic. It excludes configured
// identifiers, native process paths, document content and enrollment resources.
type BrowserStatus struct {
	Available bool                   `json:"available"`
	Channels  []BrowserChannelStatus `json:"channels"`
}

type BrowserChannelStatus struct {
	TrustScope        string `json:"trustScope"`
	Connected         bool   `json:"connected"`
	FixtureOnly       bool   `json:"fixtureOnly"`
	ProcessQualified  bool   `json:"processQualified"`
	ScopeQualified    bool   `json:"scopeQualified"`
	ProfileQualified  bool   `json:"profileQualified"`
	ExecutorQualified bool   `json:"executorQualified"`
	InventoryComplete bool   `json:"inventoryComplete"`
	DocumentCount     int    `json:"documentCount"`
	PendingCount      int    `json:"pendingCount"`
	UnknownCount      int    `json:"unknownCount"`
	AttentionCode     string `json:"attentionCode,omitempty"`
}

func browserAttentionCode(code string) string {
	switch code {
	case "storedFenceMismatch", "inventoryUnavailable", "inventoryIncomplete", "executorInjectionFailed", "executorBindingFailed", "executorNotQuiescent", "unknownEffect", "notEnrolled", "requestCapacity", "transportFailure", "rendererAuthorityRequired":
		return code
	default:
		return "unclassifiedAttention"
	}
}

func (b *Broker) BrowserStatus(ctx context.Context, p auth.Principal) (BrowserStatus, error) {
	result := BrowserStatus{Available: true, Channels: []BrowserChannelStatus{}}
	if err := authorize(ctx, p, false); err != nil {
		return BrowserStatus{}, err
	}
	b.mu.Lock()
	keys := []string{}
	for key, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	selected := make([]*channel, 0, len(keys))
	for _, key := range keys {
		selected = append(selected, b.channels[key])
	}
	b.mu.Unlock()
	for _, c := range selected {
		// Unlike operational verification, diagnostics never close a connection
		// or send a command when fresh process evidence is unavailable.
		fresh := b.checkChannelProcess(ctx, c, false) == nil
		b.mu.Lock()
		connected := c.conn != nil && !b.closed
		process := connected && !c.fixtureOnly && fresh && c.processEvidence != nil && c.processEvidence.KernelPeerQualified
		scope := process && channelScopeQualified(c)
		status := BrowserChannelStatus{TrustScope: c.grant.TrustScope, Connected: connected, FixtureOnly: c.fixtureOnly, ProcessQualified: process, ScopeQualified: scope, ProfileQualified: scope && c.profileQualified, ExecutorQualified: scope && c.executorQualified, InventoryComplete: connected && c.inventoryComplete, DocumentCount: len(c.documents), PendingCount: len(c.pending), UnknownCount: len(c.unknown), AttentionCode: c.attentionCode}
		b.mu.Unlock()
		result.Channels = append(result.Channels, status)
	}
	return result, ctx.Err()
}

func (g *Gateway) BrowserStatus(ctx context.Context, p auth.Principal) (BrowserStatus, error) {
	return g.broker.BrowserStatus(ctx, p)
}
