package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
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

// ErrProcessQualification is a closed pre-secret startup failure. The host may
// keep native administration available, but must not retry or load Chrome
// enrollment credentials until a new explicitly reviewed startup configuration.
var ErrProcessQualification = errors.New("Chrome process qualification unavailable")

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
		return nil, ErrProcessQualification
	}
	return verifier.Verify, nil
}
func (b *Broker) verifyChannelProcess(ctx context.Context, c *channel) error {
	if execution, ok := ctx.Value(playwrightPrivacyKey{}).(*playwrightExecution); ok && execution != nil && b.verifyPeerIdentity != nil {
		return b.checkScopedChannelIdentity(ctx, c, execution)
	}
	return b.checkChannelProcess(ctx, c, true)
}

// No TTL, channel-wide cache or wire claim can enter this lane. Each use is
// bound to the one fully qualified private execution and rechecks kernel identity.
func (b *Broker) checkScopedChannelIdentity(ctx context.Context, c *channel, e *playwrightExecution) error {
	denied := errors.New("scoped Chrome process proof unavailable")
	b.mu.Lock()
	if c == nil || e.processEvidence == nil || c.processEvidence != e.processEvidence || c.playwright != e || c.conn != e.conn || b.closed || b.epoch != e.command.BrokerEpoch || c.epoch != e.command.ChannelEpoch || c.scopeHash != e.command.ScopeHash || !channelScopeQualified(c) || !c.executorQualified || c.lifecycleInhibited || len(c.pending) != 1 || !privacyOperationIdleLocked(ctx, c) {
		b.mu.Unlock()
		return denied
	}
	conn := c.conn
	expected := *e.processEvidence
	expected.Ancestors = append([]session.ProcessIdentity(nil), expected.Ancestors...)
	b.mu.Unlock()
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return denied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := b.verifyPeerIdentity(ctx, unix, expected)
	e.mu.Lock()
	e.identityChecks++
	e.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			_ = conn.Close()
		}
		return errors.Join(err, denied)
	}
	b.mu.Lock()
	valid := c.playwright == e && c.conn == conn && c.processEvidence == e.processEvidence && !b.closed && b.epoch == e.command.BrokerEpoch && c.epoch == e.command.ChannelEpoch && c.scopeHash == e.command.ScopeHash && channelScopeQualified(c) && c.executorQualified && len(c.pending) == 1 && privacyOperationIdleLocked(ctx, c)
	b.mu.Unlock()
	if !valid {
		return denied
	}
	return ctx.Err()
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
	if !ok || b.verifyPeer == nil {
		return channelProcessError("nativeChannelUnavailable", nil)
	}
	if expected == nil {
		return channelProcessError("processEvidenceUnavailable", nil)
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	started := time.Now()
	current, err := b.verifyPeer(bounded, unix)
	if execution, ok := ctx.Value(playwrightPrivacyKey{}).(*playwrightExecution); ok && execution != nil {
		execution.mu.Lock()
		execution.verifyCount++
		execution.verifyMS += time.Since(started).Milliseconds()
		execution.mu.Unlock()
	}

	// A cancelled probe is absence of fresh evidence, not evidence that the
	// authenticated peer changed. Deny this operation without destroying the
	// connection (including its private demultiplexer and retained receipts).
	// The next operation must perform a new full verification.
	if bounded.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return bounded.Err()
	}
	if err != nil || !current.KernelPeerQualified || current.NativeHost != expected.NativeHost || current.ChromeParent != expected.ChromeParent || trustScope == TrustScopeDesktop && !desktopProcessQualified(&current) {
		if revokeInvalid {
			_ = conn.Close()
		}
		if err != nil {
			return channelProcessError("processVerificationUnavailable", err)
		}
		if !current.KernelPeerQualified {
			return channelProcessError("kernelPeerUnqualified", nil)
		}
		if current.NativeHost != expected.NativeHost {
			return channelProcessError("nativeHostIdentityChanged", nil)
		}
		if current.ChromeParent != expected.ChromeParent {
			return channelProcessError("chromeIdentityChanged", nil)
		}
		return channelProcessError("desktopAncestryUnqualified", nil)
	}
	b.mu.Lock()
	unchanged := c.conn == conn && c.processEvidence == expected
	scopeUnchanged := c.grant.TrustScope == trustScope && channelScopeQualified(c)
	b.mu.Unlock()
	if !unchanged {
		return channelProcessError("channelChanged", nil)
	}
	if !scopeUnchanged {
		return channelProcessError("scopeChanged", nil)
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
		status := ChannelTrust{TrustScope: c.grant.TrustScope, FixtureOnly: c.fixtureOnly}
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
	AttentionCode string                 `json:"attentionCode,omitempty"`
	Setup         *BrowserSetup          `json:"setup,omitempty"`
	Available     bool                   `json:"available"`
	Channels      []BrowserChannelStatus `json:"channels"`
}

type BrowserChannelStatus struct {
	// Reported by the authenticated worker; diagnostic metadata, not code attestation.
	ExtensionVersion          string                       `json:"extensionVersion,omitempty"`
	WorkerBuild               int                          `json:"workerBuild,omitempty"`
	ProfileChannel            string                       `json:"profileChannel,omitempty"`
	BrowserInstance           string                       `json:"browserInstance,omitempty"`
	SetupMetadataAvailable    bool                         `json:"setupMetadataAvailable"`
	AllWebsites               bool                         `json:"allWebsites,omitempty"`
	TrustScope                string                       `json:"trustScope"`
	Connected                 bool                         `json:"connected"`
	FixtureOnly               bool                         `json:"fixtureOnly"`
	ProcessVerificationReason string                       `json:"processVerificationReason,omitempty"`
	ProcessQualified          bool                         `json:"processQualified"`
	ScopeQualified            bool                         `json:"scopeQualified"`
	ProfileQualified          bool                         `json:"profileQualified"`
	ExecutorQualified         bool                         `json:"executorQualified"`
	InventoryComplete         bool                         `json:"inventoryComplete"`
	DocumentCount             int                          `json:"documentCount"`
	PendingCount              int                          `json:"pendingCount"`
	UnknownCount              int                          `json:"unknownCount"`
	VisibilityUnknownCount    int                          `json:"visibilityUnknownCount,omitempty"`
	AttentionCode             string                       `json:"attentionCode,omitempty"`
	ReconnectPhase            string                       `json:"reconnectPhase,omitempty"`
	ReconnectReason           string                       `json:"reconnectReason,omitempty"`
	ReconnectInventoryReason  string                       `json:"reconnectInventoryReason,omitempty"`
	ReconnectJournal          *ReconnectJournalDiagnostic  `json:"reconnectJournal,omitempty"`
	ReconnectRecovery         *ReconnectRecoveryDiagnostic `json:"reconnectRecovery,omitempty"`
}

func browserAttentionCode(code string) string {
	switch code {
	case "websiteScopeMismatch", "lifecycleInhibited", "storedFenceMismatch", "inventoryUnavailable", "inventoryIncomplete", "executorInjectionFailed", "executorBindingFailed", "executorNotQuiescent", "unknownEffect", "notEnrolled", "requestCapacity", "transportFailure", "rendererAuthorityRequired":
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
		processErr := b.checkChannelProcess(ctx, c, false)
		fresh := processErr == nil
		b.mu.Lock()
		connected := c.conn != nil && !b.closed
		process := connected && !c.fixtureOnly && fresh && c.processEvidence != nil && c.processEvidence.KernelPeerQualified
		scope := process && channelScopeQualified(c)
		status := BrowserChannelStatus{SetupMetadataAvailable: scope && c.setupAvailable, AllWebsites: c.grant.AllWebsites, TrustScope: c.grant.TrustScope, Connected: connected, FixtureOnly: c.fixtureOnly, ProcessQualified: process, ScopeQualified: scope, ProfileQualified: scope && c.profileQualified, ExecutorQualified: scope && c.executorQualified, InventoryComplete: connected && c.inventoryComplete, DocumentCount: len(c.documents), PendingCount: len(c.pending), UnknownCount: len(c.unknown), VisibilityUnknownCount: visibilityUnknownCountLocked(c), AttentionCode: c.attentionCode}
		if connected && !fresh {
			status.ProcessVerificationReason = processVerificationReason(processErr)
		}
		if scope {
			status.ReconnectPhase = c.reconnectPhase
			status.ReconnectReason = c.reconnectReason
			status.ReconnectInventoryReason = c.reconnectInventoryReason
			if c.reconnectJournal != nil {
				copy := *c.reconnectJournal
				status.ReconnectJournal = &copy
			}
			if c.reconnectRecovery != nil {
				copy := *c.reconnectRecovery
				status.ReconnectRecovery = &copy
			}
		}
		if process {
			status.WorkerBuild = c.workerBuild
			status.ExtensionVersion = c.extensionVersion
		}
		if auth.NativeHuman(ctx) {
			status.ProfileChannel = c.grant.ProfileChannel
			status.BrowserInstance = c.grant.BrowserInstance
		}
		b.mu.Unlock()
		result.Channels = append(result.Channels, status)
	}
	return result, ctx.Err()
}

func (g *Gateway) BrowserStatus(ctx context.Context, p auth.Principal) (BrowserStatus, error) {
	// A status refresh may recover a late transport receipt, but never executes
	// input or alters the durable effect ledger. Original attempt/fingerprint
	// validation remains mandatory; missing or unknown receipts retain the fence.
	g.broker.refreshUnknownReceipts(ctx, p)
	return g.broker.BrowserStatus(ctx, p)
}

// Only finite metadata from an authenticated stored-fence attention frame may
// enter ordinary browser status; arbitrary extension/provider data is omitted.
func closedReconnectAttention(raw []byte, code string) (string, string) {
	if code != "storedFenceMismatch" || len(raw) > 4096 || !uniqueCredentialJSON(raw) {
		return "", ""
	}
	var frame struct {
		Phase  string `json:"reconnectPhase"`
		Reason string `json:"reconnectReason"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		return "", ""
	}
	if !closedReconnectPhase(frame.Phase) || !closedReconnectReason(frame.Reason) {
		return "", ""
	}
	return frame.Phase, frame.Reason
}
func closedReconnectPhase(v string) bool {
	switch v {
	case "idle", "scope", "barriers", "journal", "inventory", "inspect", "prepare", "adopt", "commit":
		return true
	}
	return false
}

func closedReconnectInventoryAttention(raw []byte, code string) string {
	phase, reason := closedReconnectAttention(raw, code)
	if phase == "" || reason != "inventoryChanged" {
		return ""
	}
	var frame struct {
		Reason string `json:"reconnectInventoryReason"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		return ""
	}
	switch frame.Reason {
	case "none", "tabQueryUnavailable", "tabListInvalid", "tabLimitExceeded", "tabMetadataInvalid", "tabIDInvalid", "tabIDDuplicate", "tabURLUnavailable", "tabURLInvalid", "pendingNavigation", "incognitoTab", "discardedTab", "nonSetupTab", "frameQueryUnavailable", "frameListUnavailable", "frameLimitExceeded", "frameMetadataInvalid", "frameIDInvalid", "frameIDDuplicate", "frameParentInvalid", "frameDocumentUnavailable", "frameError", "frameLifecycleInactive", "frameTypeDenied", "rootLifecycleMissing", "rootLifecyclePrerender", "rootLifecycleCached", "rootLifecyclePendingDeletion", "rootLifecycleInvalid", "rootFrameTypeMissing", "rootFrameTypeDenied", "childLifecycleMissing", "childLifecyclePrerender", "childLifecycleCached", "childLifecyclePendingDeletion", "childLifecycleInvalid", "childFrameTypeMissing", "childFrameTypeDenied", "rootFrameTypeOuterMost", "rootFrameTypeSubFrame", "rootFrameTypeFenced", "rootFrameTypeInvalid", "childFrameTypeOuterMost", "childFrameTypeSubFrame", "childFrameTypeFenced", "childFrameTypeInvalid", "frameRootURLDenied", "builtInRootURLDenied", "tabSchemeDenied", "rootFrameURLInvalid", "childFrameURLInvalid", "rootFrameUserinfoDenied", "childFrameUserinfoDenied", "rootFrameSchemeDenied", "rootFrameError", "builtInRootFrameError", "childSourceIdentityUnavailable", "rootFrameOriginNotGranted", "childFrameOriginNotGranted", "rootTabOriginMismatch", "frameChildURLDenied", "frameRootMissing", "inactiveRootParentDenied", "frameParentDocumentMismatch", "frameParentMissing", "frameCycle", "inventoryDrift":
		return frame.Reason
	}
	return ""
}
func closedReconnectReason(v string) bool {
	switch v {
	case "none", "portChanged", "deadline", "busy", "unknownReceipts", "privateProtection", "lifecycle", "scopeChanged", "journalChanged", "inventoryChanged", "storageFailure", "rendererUnavailable", "executorRefused", "injectionUnavailable", "restrictedBrowserPage", "packagedExecutorUnavailable", "documentChanged", "websitePermissionMissing", "extensionContextInvalidated", "restrictedFrame", "injectionArgumentsRejected", "executorEvaluationFailed":
		return true
	}
	return false
}

// ReconnectJournalDiagnostic contains only bounded journal shape metadata.
// No fence, identity, nonce, receipt, or underlying error is retained here.
type ReconnectJournalDiagnostic struct {
	Reason        string `json:"reason"`
	Version       int    `json:"version"`
	HistoryCount  int    `json:"historyCount"`
	State         string `json:"state"`
	GrantRelation string `json:"grantRelation"`
}

// ReconnectRecoveryDiagnostic reports only distinct-source blocker counts.
// It contains no document identity, origin, receipt, or provider error text.
type ReconnectRecoveryDiagnostic struct {
	MissingLiveReceipts  int `json:"missingLiveReceipts"`
	UnknownLiveReceipts  int `json:"unknownLiveReceipts"`
	UnavailableExecutors int `json:"unavailableExecutors"`
	PrivateSources       int `json:"privateSources"`
}

func closedReconnectRecoveryAttention(raw []byte, code string) *ReconnectRecoveryDiagnostic {
	phase, reason := closedReconnectAttention(raw, code)
	if phase == "" || phase == "idle" || reason == "none" {
		return nil
	}
	var frame struct {
		Recovery json.RawMessage `json:"reconnectRecovery"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(frame.Recovery, &fields) != nil || len(fields) != 4 {
		return nil
	}
	for _, key := range []string{"missingLiveReceipts", "unknownLiveReceipts", "unavailableExecutors", "privateSources"} {
		value, ok := fields[key]
		var count int
		if !ok || string(bytes.TrimSpace(value)) == "null" || json.Unmarshal(value, &count) != nil || count < 0 || count > 200 {
			return nil
		}
	}
	var result ReconnectRecoveryDiagnostic
	if json.Unmarshal(frame.Recovery, &result) != nil {
		return nil
	}
	return &result
}

func closedReconnectJournalAttention(raw []byte, code string) *ReconnectJournalDiagnostic {
	phase, reason := closedReconnectAttention(raw, code)
	if phase == "" || reason != "journalChanged" {
		return nil
	}
	var envelope struct {
		Journal json.RawMessage `json:"reconnectJournal"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Journal, &fields) != nil || len(fields) != 5 {
		return nil
	}
	for _, key := range []string{"reason", "version", "historyCount", "state", "grantRelation"} {
		v, ok := fields[key]
		if !ok || string(v) == "null" {
			return nil
		}
	}
	var value ReconnectJournalDiagnostic
	if json.Unmarshal(envelope.Journal, &value) != nil || value.Version < -1 || value.Version > 6 || value.HistoryCount < -1 || value.HistoryCount > 64 {
		return nil
	}
	switch value.Reason {
	case "none", "recoveryDepthLimit", "historyLimit", "lineageInvalid", "recordChanged", "bindingSnapshotUnavailable":
	default:
		return nil
	}
	switch value.State {
	case "absent", "pending", "adopted", "unrecognized":
	default:
		return nil
	}
	switch value.GrantRelation {
	case "none", "unavailable", "old", "new", "both", "neither":
	default:
		return nil
	}
	return &value
}
