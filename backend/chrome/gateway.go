package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

type Lease struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}
type GatewayOptions struct {
	Lease func(context.Context, auth.Principal) (Lease, error)
}
type Gateway struct {
	admissionLane     chan struct{}
	controlMu         sync.Mutex
	control           *ControlAuthority
	controlRetiring   bool
	controlGeneration uint64
	broker            *Broker
	options           GatewayOptions
	observationMu     sync.Mutex
	observations      map[string]model.Observation
	observationOrder  []string
}

func NewGateway(broker *Broker, options GatewayOptions) (*Gateway, error) {
	if broker == nil {
		return nil, errors.New("Chrome broker required")
	}
	return &Gateway{admissionLane: make(chan struct{}, 1), broker: broker, options: options, observations: map[string]model.Observation{}}, nil
}
func (g *Gateway) Close() error { return g.broker.Close() }
func (g *Gateway) Capabilities() []model.Capability {
	g.broker.mu.Lock()
	connected := false
	mutationReady := false
	for _, c := range g.broker.channels {
		connected = connected || c.conn != nil && channelScopeQualified(c) && c.executorQualified && len(c.documents) > 0
		mutationReady = mutationReady || c.conn != nil && channelScopeQualified(c) && c.executorQualified && len(c.documents) > 0 && c.grant.Principal.HasScope("desktop:control")
	}
	g.broker.mu.Unlock()
	return []model.Capability{{Name: "observe", Surface: "web", Supported: connected, Reason: "Enrolled root-frame DOM fixture; partial semantics"}, {Name: "element.read", Surface: "web", Supported: connected}, {Name: "element.press", Surface: "web", Supported: mutationReady && g.options.Lease != nil, Reason: "DOM activation; untrusted events; business verification required"}, {Name: "element.fill", Surface: "web", Supported: mutationReady && g.options.Lease != nil, Reason: "Native HTML input/textarea only; untrusted events"}, {Name: "frameScope", Surface: "web", Supported: false}, {Name: "recording", Surface: "web", Supported: mutationReady, Reason: "Explicit document scope, visible badge, locally redacted trusted events, bounded gap-aware polling"}, {Name: "browser.listTabs", Surface: "web", Supported: connected}, {Name: "browser.navigate", Surface: "web", Supported: mutationReady && g.options.Lease != nil, Reason: "One Chrome API dispatch; redirects checked; receipt is not business verification"}, {Name: "browser.activate", Surface: "web", Supported: mutationReady && g.options.Lease != nil, Reason: "Tab activation only; physical window focus requires native route"}, {Name: "observe.delta", Surface: "web", Supported: connected, Reason: "Bounded per-user snapshots; explicit semantic coverage"}, {Name: "trustedInput", Surface: "web", Supported: false}, {Name: "fileSelection", Surface: "web", Supported: false}}
}

// CapabilitiesFor reports only read routes available to this authenticated
// owner. Mutation qualification belongs to the separate control manager.
func (g *Gateway) CapabilitiesFor(ctx context.Context, p auth.Principal) ([]model.Capability, error) {
	if err := authorize(ctx, p, false); err != nil {
		return nil, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready := false
	if g != nil && g.broker != nil {
		b := g.broker
		b.mu.Lock()
		owned := []*channel{}
		for _, c := range b.channels {
			if c.grant.Principal.Namespace == actual.Namespace && c.conn != nil && !c.fixtureOnly && channelScopeQualified(c) && c.executorQualified && c.inventoryComplete && len(c.documents) > 0 {
				owned = append(owned, c)
			}
		}
		b.mu.Unlock()
		for _, c := range owned {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if b.checkChannelProcess(ctx, c, false) != nil {
				continue
			}
			b.mu.Lock()
			if !b.closed && c.conn != nil && !c.fixtureOnly && channelScopeQualified(c) && c.executorQualified && c.inventoryComplete && c.grant.Principal.Namespace == actual.Namespace {
				for _, d := range c.documents {
					if d.FrameID == 0 && d.TabID > 0 && d.DocumentID != "" && d.Generation > 0 && allowedOrigin(c.grant, d.Origin) {
						ready = true
						break
					}
				}
			}
			b.mu.Unlock()
			if ready {
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	capabilities := []model.Capability{}
	for _, name := range []string{"observe", "element.read", "browser.listTabs", "observe.delta", "boundedObservation", "attributeRead", "roleLocator", "idLocator", "testIdLocator", "labelRelationships"} {
		capabilities = append(capabilities, model.Capability{Name: name, Surface: "web", Supported: ready, Reason: "Qualified owned root document; exact unique DOM selectors and bounded protected reads"})
	}
	for _, name := range []string{"element.press", "element.fill", "browser.navigate", "browser.activate", "recording", "nameLocator", "textLocator", "cssLocator", "frameScope", "windowScope", "ancestorScope", "orderedQuery", "checkedObservation", "trustedInput", "fileSelection"} {
		capabilities = append(capabilities, model.Capability{Name: name, Surface: "web", Supported: false})
	}
	return capabilities, nil
}
func authorize(ctx context.Context, p auth.Principal, mutation bool) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace {
		return auth.ErrUnauthorized
	}
	scope := "desktop:observe"
	if mutation {
		scope = "desktop:control"
	}
	if (!actual.HasScope(scope) && !(scope == "desktop:observe" && actual.HasScope("desktop:control"))) || (!p.HasScope(scope) && !(scope == "desktop:observe" && p.HasScope("desktop:control"))) {
		return auth.ErrUnauthorized
	}
	return nil
}
func (g *Gateway) LeaseEpoch(ctx context.Context, p auth.Principal) (int, error) {
	if err := authorize(ctx, p, false); err != nil {
		return 0, err
	}
	if g.options.Lease == nil {
		return 0, browserError("leaseUnavailable", "External desktop-wide fence required", "notDispatched")
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return 0, err
	}
	if lease.ID == "" || lease.Generation == 0 || lease.Generation > uint64(math.MaxInt) {
		return 0, browserError("invalidLease", "Held positive external fence required", "notDispatched")
	}
	return int(lease.Generation), nil
}
func (b *Broker) selectDocument(p auth.Principal, surface model.Surface) (*channel, Document, error) {
	if surface.Kind != "web" || surface.ValidateProcessIdentity() != nil || surface.BundleID != "" || (surface.Origin == "" && surface.TabID == "") {
		return nil, Document{}, browserError("scopeDenied", "Explicit web origin or tab ID required", "notDispatched")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var selected *channel
	var document Document
	count := 0
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace || c.conn == nil || (!channelScopeQualified(c) || !c.executorQualified) {
			continue
		}
		for _, d := range c.documents {
			if d.FrameID != 0 || (surface.Origin != "" && d.Origin != surface.Origin) || (surface.Title != "" && (d.TitleTruncated || d.Title != surface.Title)) || (surface.TabID != "" && strconv.Itoa(d.TabID) != surface.TabID && d.QualifiedTabID() != surface.TabID) {
				continue
			}
			selected, document = c, d
			count++
		}
	}
	if count != 1 {
		return nil, Document{}, browserError("ambiguousTarget", fmt.Sprintf("Expected exactly one enrolled root document for this user, found %d", count), "notDispatched")
	}
	return selected, document, nil
}
func (b *Broker) call(ctx context.Context, c *channel, command Command, mutation bool, beforeSend ...func() error) (Reply, error) {
	return b.callPrepared(ctx, c, command, mutation, nil, beforeSend...)
}
func (b *Broker) callBound(ctx context.Context, c *channel, command Command, p auth.Principal, commit CommitMutationBinding, beforeSend ...func() error) (Reply, error) {
	if commit == nil {
		return Reply{}, browserError("bindingRequired", "Committed mutation binding required", "notDispatched")
	}
	return b.callPrepared(ctx, c, command, true, func(command Command) (BindingCommit, error) {
		b.mu.Lock()
		qualified := c.mutationFingerprintVersion == 2
		b.mu.Unlock()
		if !qualified {
			return BindingCommit{}, browserError("bindingRequired", "Negotiated worker v2 required", "notDispatched")
		}
		descriptor := BoundMutation{Action: command.Action, BrowserAttemptID: command.AttemptID, Identity: command.Identity, BrokerEpoch: command.BrokerEpoch, ChannelEpoch: command.ChannelEpoch, ScopeHash: command.ScopeHash, ControlLease: *command.ControlLease, Fingerprint: MutationFingerprint{Version: 2, SHA256: command.FingerprintSHA256}}
		return commit(ctx, p, descriptor)
	}, beforeSend...)
}
func (b *Broker) callPrepared(ctx context.Context, c *channel, command Command, mutation bool, seal func(Command) (BindingCommit, error), beforeSend ...func() error) (Reply, error) {
	if c == nil {
		return Reply{}, browserError("channelUnqualified", "Exact enrolled channel required", "notDispatched")
	}
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if err := b.verifyChannelProcess(ctx, c); err != nil {
		return Reply{}, browserError("channelUnqualified", "Signed native-host/Chrome channel proof unavailable", "notDispatched")
	}
	b.mu.Lock()
	scopeQualified := channelScopeQualified(c) && c.executorQualified
	b.mu.Unlock()
	if !scopeQualified {
		return Reply{}, browserError("profileUnqualified", "Profile enrollment and executor quiescence are not qualified", "notDispatched")
	}
	if mutation {
		if !c.grant.Principal.HasScope("desktop:control") {
			return Reply{}, auth.ErrUnauthorized
		}
		select {
		case b.lane <- struct{}{}:
			defer func() { <-b.lane }()
		case <-ctx.Done():
			return Reply{}, ctx.Err()
		}
	}
	for _, check := range beforeSend {
		if err := check(); err != nil {
			return Reply{}, err
		}
	}
	command.RequestID = newID()
	b.mu.Lock()
	command.BrokerEpoch = b.epoch
	command.ChannelEpoch = c.epoch
	command.ScopeHash = c.scopeHash
	b.mu.Unlock()
	deadline := time.Now().Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	command.DeadlineUnixMS = deadline.UnixMilli()
	if seal != nil {
		fingerprint, err := FingerprintMutationV2(command)
		if err != nil || command.FingerprintVersion != 2 {
			return Reply{}, browserError("bindingRequired", "Exact logical v2 mutation required", "notDispatched")
		}
		command.FingerprintSHA256 = fingerprint.SHA256
		b.mu.Lock()
		previous, historyErr := b.mutationHistoryLocked(c, command)
		unavailable := c.conn == nil || b.closed || len(c.pending) >= 4096
		b.mu.Unlock()
		if previous != nil {
			return *previous, historyErr
		}
		if historyErr != nil {
			return Reply{}, historyErr
		}
		if unavailable {
			return Reply{}, browserError("hostUnavailable", "Exact idle channel unavailable before binding", "notDispatched")
		}

		// The exclusive mutation lane is held, but no broker/control/write mutex is
		// held across the synchronous generated commit and readback callback.
		committed, err := seal(command)
		if err != nil || !committed.CommitConfirmed || !committed.ReadbackMatched || !fingerprintV2Hash.MatchString(committed.BindingID) {
			return Reply{}, browserError("bindingUnconfirmed", "Exact mutation binding commit/readback is unconfirmed", "notDispatched")
		}
		if err = ctx.Err(); err != nil {
			return Reply{}, err
		}
		for _, check := range beforeSend {
			if err = check(); err != nil {
				return Reply{}, err
			}
		}
	}

	b.mu.Lock()
	if c.lifecycleInhibited {
		b.mu.Unlock()
		return Reply{}, browserError("channelLifecycleInhibited", "Channel is inhibited for explicit lifecycle reconciliation", "notDispatched")
	}
	if mutation {
		previous, err := b.mutationHistoryLocked(c, command)
		if previous != nil || err != nil {
			b.mu.Unlock()
			if previous != nil {
				return *previous, err
			}
			return Reply{}, err
		}
	}

	conn := c.conn
	if conn == nil || b.closed {
		b.mu.Unlock()
		return Reply{}, browserError("hostUnavailable", "Enrolled Chrome host is disconnected", "notDispatched")
	}
	if len(c.pending) >= 4096 {
		b.mu.Unlock()
		return Reply{}, browserError("requestCapacity", "Too many pending Chrome commands", "notDispatched")
	}
	p := &pending{command: command, mutation: mutation, done: make(chan Reply, 1)}
	c.pending[command.RequestID] = p
	if mutation {
		retained := command
		if retained.FingerprintVersion == 2 {
			retained.Args = nil
			retained.Locator = nil
		}
		c.attempts[command.AttemptID] = retained
		c.unknown[command.AttemptID] = true
	}
	b.mu.Unlock()
	type writeResult struct {
		err       error
		attempted bool
	}
	written := make(chan writeResult, 1)
	go func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		_ = conn.SetWriteDeadline(deadline)
		err := b.verifyChannelProcess(ctx, c)
		if err == nil {
			for _, check := range beforeSend {
				if err = check(); err != nil {
					break
				}
			}
		}
		if err == nil && seal != nil {
			fingerprint, e := FingerprintMutationV2(command)
			if e != nil || fingerprint.Version != command.FingerprintVersion || fingerprint.SHA256 != command.FingerprintSHA256 {
				err = browserError("bindingUnconfirmed", "Prepared logical mutation binding changed", "notDispatched")
			}
		}
		attempted := err == nil
		if attempted {
			err = WriteFrame(conn, command)
		}
		_ = conn.SetWriteDeadline(time.Time{})
		written <- writeResult{err: err, attempted: attempted}
	}()
	var err error
	select {
	case outcome := <-written:
		err = outcome.err
		if err != nil && !outcome.attempted {
			b.mu.Lock()
			delete(c.pending, command.RequestID)
			if mutation {
				delete(c.attempts, command.AttemptID)
				delete(c.unknown, command.AttemptID)
			}
			b.mu.Unlock()
			return Reply{}, browserError("dispatchGateClosed", "Pinned authority or signed channel changed before transport write", "notDispatched")
		}
	case <-ctx.Done():
		conn.Close()
		return Reply{}, browserError("cancelled", "Chrome transport cancelled; reconcile original attempt", uncertain(mutation))
	}
	if err != nil {
		conn.Close()
		return Reply{}, browserError("hostLost", "Dispatch transport failed; reconcile original attempt", uncertain(mutation))
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case reply := <-p.done:
		if reply.Error != nil {
			return reply, reply.Error
		}
		return reply, nil
	case <-ctx.Done():
		if !mutation {
			b.mu.Lock()
			delete(c.pending, command.RequestID)
			b.mu.Unlock()
		}
		return Reply{}, browserError("cancelled", "Chrome dispatch cancelled; late original receipt remains reconcilable", uncertain(mutation))
	case <-timer.C:
		return Reply{}, browserError("deadlineExceeded", "Chrome receipt deadline exceeded; never replay mutation", uncertain(mutation))
	}
}
func (g *Gateway) observe(ctx context.Context, p auth.Principal, surface model.Surface) (model.Observation, *channel, Document, error) {
	c, d, err := g.broker.selectDocument(p, surface)
	if err != nil {
		return model.Observation{}, nil, Document{}, err
	}
	started := time.Now()
	reply, err := g.broker.call(ctx, c, Command{Action: "observe", Identity: d.Identity, Args: map[string]any{"limit": 100}}, false)
	if err != nil {
		return model.Observation{}, nil, Document{}, err
	}
	observation := model.Observation{ID: newID(), Epoch: g.broker.epoch, Started: started, Ended: time.Now(), Surface: surface, Truncated: reply.Truncated, Unavailable: append([]string(nil), reply.Coverage...)}
	g.broker.mu.Lock()
	// Scope and channel identity bind retained snapshots and element refs. A
	// scope transition must reset deltas even inside the same broker process.
	epochData, _ := json.Marshal([]string{g.broker.epoch, c.epoch, c.scopeHash, c.grant.TrustScope})
	epochHash := sha256.Sum256(epochData)
	observation.Epoch = hex.EncodeToString(epochHash[:])
	g.broker.sequence++
	observation.Sequence = g.broker.sequence
	g.broker.mu.Unlock()
	if len(reply.Nodes) > 200 {
		return model.Observation{}, nil, Document{}, browserError("invalidObservation", "Chrome node limit exceeded", "notDispatched")
	}
	d.Identity = reply.Identity
	for i, node := range reply.Nodes {
		if len(node.Name) > 1024 || len(node.ID) > 1024 || len(node.Role) > 64 {
			return model.Observation{}, nil, Document{}, browserError("invalidObservation", "Chrome semantic attribute limit exceeded", "notDispatched")
		}
		observation.Nodes = append(observation.Nodes, model.Node{Ref: model.ElementRef{ID: fmt.Sprintf("%s:%d", d.DocumentID, i), Epoch: observation.Epoch, AppLaunchID: d.ProfileChannel + ":" + d.BrowserInstance, Generation: d.Generation}, Role: node.Role, Name: node.Name, Identifier: node.ID, Visible: node.Visible, Enabled: node.Enabled, Unavailable: []string{"generation-scoped semantic observation; use locator for fresh resolve"}})
	}
	return observation, c, d, nil
}
func (g *Gateway) Observe(ctx context.Context, p auth.Principal, surface model.Surface) (model.Observation, error) {
	if err := authorize(ctx, p, false); err != nil {
		return model.Observation{}, err
	}
	observation, _, _, err := g.observe(ctx, p, surface)
	if err == nil {
		g.remember(p, observation)
	}
	return observation, err
}
func compileLocator(selector model.Selector, bindings map[string]model.Value) (*Locator, error) {
	if selector.Ancestor != nil || len(selector.Scope.Frame) > 0 || len(selector.Scope.Window) > 0 {
		return nil, browserError("unsupportedScope", "Only enrolled root document scope is qualified", "notDispatched")
	}
	if selector.Locator == nil || !selector.Locator.Exact || selector.Cardinality != "one" {
		return nil, browserError("unsupportedLocator", "Exact cardinality-one locator required", "notDispatched")
	}
	l := selector.Locator
	if l.Strategy != "role" && l.Strategy != "id" && l.Strategy != "testId" && l.Strategy != "label" {
		return nil, browserError("unsupportedLocator", "Qualified Chrome selectors: role, id, testId, label", "notDispatched")
	}
	value, err := model.ResolveValue(l.Value, bindings)
	if err != nil || value.Kind != model.StringValue {
		return nil, browserError("invalidLocator", "Locator must resolve to string", "notDispatched")
	}
	out := &Locator{Strategy: l.Strategy, Value: value.String, Exact: true}
	if l.Name != nil {
		name, e := model.ResolveValue(*l.Name, bindings)
		if e != nil || name.Kind != model.StringValue {
			return nil, browserError("invalidLocator", "Role name must resolve to string", "notDispatched")
		}
		out.Name = &name.String
	}
	return out, nil
}
func (g *Gateway) Execute(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	mutation := step.Action == "element.press" || step.Action == "element.fill"
	if err := authorize(ctx, p, mutation); err != nil {
		return result, err
	}
	if err := step.Validate(); err != nil {
		return result, err
	}
	if err := validateReadOperation(step); err != nil {
		return result, err
	}
	locator, err := compileLocator(step.Target, bindings)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, min(time.Duration(step.TimeoutMs)*time.Millisecond, 30*time.Second))
	defer cancel()
	observation, c, d, err := g.observe(ctx, p, step.Target.Surface)
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	command := Command{Action: step.Action, Identity: d.Identity, Locator: locator}
	if mutation {
		if _, err = g.LeaseEpoch(ctx, p); err != nil {
			return result, err
		}
		metadata, ok := integration.ExecutionFromContext(ctx)
		if !ok || metadata.RunID == "" || metadata.PlanID == "" {
			return result, browserError("attemptIdentityRequired", "Mutation requires stable durable Endly run/plan identity", "notDispatched")
		}
		hash := sha256.Sum256([]byte(metadata.RunID + "\x00" + metadata.PlanID + "\x00" + step.ID))
		command.AttemptID = hex.EncodeToString(hash[:])
		if step.Action == "element.fill" {
			value, e := model.ResolveValue(step.Arguments["value"], bindings)
			if e != nil || value.Kind != model.StringValue {
				return result, browserError("invalidValue", "Fill value must resolve to string", "notDispatched")
			}
			command.Args = map[string]any{"value": value.String}
		}
		reply, e := g.broker.call(ctx, c, command, true, func() error { _, e := g.LeaseEpoch(ctx, p); return e })
		if reply.DispatchState != "" {
			result.DispatchState = reply.DispatchState
		} else {
			var detail *model.MechanizeError
			if errors.As(e, &detail) {
				result.DispatchState = detail.DispatchState
			}
		}
		return result, e
	}
	attribute := ""
	command.Action = "read"
	if step.Action == "element.read" {
		attribute = step.Arguments["attribute"].String
	} else {
		switch step.Assertion.Matcher {
		case "toHaveText":
			attribute = "text"
		case "toHaveValue":
			attribute = "value"
		case "toBeVisible", "toBeEnabled":
			command.Action = "resolve"
		}
	}
	if attribute != "" {
		command.Args = map[string]any{"attribute": attribute}
	}
	reply, err := g.broker.call(ctx, c, command, false)
	if err != nil {
		return result, err
	}
	if step.Action == "element.read" {
		if reply.Value == nil || *reply.Value == "[redacted]" {
			return result, browserError("attributeUnavailable", "Requested value is unavailable or redacted", "notDispatched")
		}
		value := model.Value{Kind: model.StringValue, String: *reply.Value}
		result.Value = &value
	} else {
		var holds bool
		if command.Action == "resolve" {
			value := reply.Visible
			if step.Assertion.Matcher == "toBeEnabled" {
				value = reply.Enabled
			}
			if value == nil {
				return result, browserError("incompleteObservation", "Assertion attribute unavailable", "notDispatched")
			}
			holds = *value
		} else {
			expected, e := model.ResolveValue(*step.Assertion.Expected, bindings)
			if e != nil || expected.Kind != model.StringValue || reply.Value == nil || *reply.Value == "[redacted]" {
				return result, browserError("incompleteObservation", "Assertion value unavailable", "notDispatched")
			}
			holds = *reply.Value == expected.String
		}
		if step.Assertion.Not {
			holds = !holds
		}
		if !holds {
			return result, browserError("assertionFailed", "Browser assertion failed", "notDispatched")
		}
	}
	result.VerificationState = "verified"
	return result, nil
}

func validateReadOperation(step model.Step) error {
	switch step.Action {
	case "element.read":
		switch step.Arguments["attribute"].String {
		case "text", "value", "name":
			return nil
		default:
			return browserError("unsupportedAttribute", "Chrome reads support only text, value, and name", "notDispatched")
		}
	case "expect":
		if step.Assertion == nil {
			return browserError("invalidAssertion", "Chrome assertion is required", "notDispatched")
		}
		switch step.Assertion.Matcher {
		case "toHaveText", "toHaveValue":
			if step.Assertion.Expected == nil {
				return browserError("invalidAssertion", "Chrome text/value assertions require an expected value", "notDispatched")
			}
		case "toBeVisible", "toBeEnabled":
			if step.Assertion.Expected != nil {
				return browserError("invalidAssertion", "Chrome visible/enabled assertions do not accept an expected value", "notDispatched")
			}
		default:
			return browserError("unsupportedAssertion", "Chrome assertions support text, value, visible, and enabled", "notDispatched")
		}
	}
	return nil
}

// QueryReceipt is observational: it cannot replay or complete a business effect.
func (b *Broker) QueryReceipt(ctx context.Context, p auth.Principal, attemptID string) (Reply, error) {
	if err := authorize(ctx, p, false); err != nil {
		return Reply{}, err
	}
	b.mu.Lock()
	var selected *channel
	var command Command
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace {
			continue
		}
		if receipt, ok := c.receipts[attemptID]; ok {
			b.mu.Unlock()
			if receipt.Error != nil {
				return receipt, receipt.Error
			}
			return receipt, nil
		}
		if original, ok := c.attempts[attemptID]; ok {
			if selected != nil {
				b.mu.Unlock()
				return Reply{}, browserError("ambiguousAttempt", "Attempt occurs in multiple profile channels", "unknown")
			}
			selected = c
			command = original
		}
	}
	b.mu.Unlock()
	if selected == nil {
		return Reply{}, browserError("receiptUnavailable", "Original attempt receipt is not known; business reconciliation required", "unknown")
	}
	command.Action = "receipt.query"
	command.Locator = nil
	command.Args = nil
	reply, err := b.call(ctx, selected, command, false)
	if err != nil {
		return reply, browserError("receiptUnavailable", "Receipt query unavailable; business reconciliation required", "unknown")
	}
	if reply.ReceiptAvailable != nil && !*reply.ReceiptAvailable || reply.DispatchState == "unknown" {
		return reply, browserError("receiptUnavailable", "Document lost original receipt; business reconciliation required", "unknown")
	}
	return reply, nil
}

// Called only with b.mu held. History is checked both before the commit callback
// and after it so persistence cannot erase original receipts or uncertainty.
func (b *Broker) mutationHistoryLocked(c *channel, command Command) (*Reply, error) {
	if previous, exists := c.attempts[command.AttemptID]; exists {
		if previous.FingerprintVersion != command.FingerprintVersion || previous.FingerprintVersion == 2 && previous.FingerprintSHA256 != command.FingerprintSHA256 || previous.FingerprintVersion != 2 && (previous.Action != command.Action || !reflect.DeepEqual(previous.Locator, command.Locator) || !reflect.DeepEqual(previous.Args, command.Args)) {
			return nil, browserError("attemptConflict", "Attempt already bound to different mutation arguments", "unknown")
		}
		if receipt, known := c.receipts[command.AttemptID]; known {
			if receipt.Error != nil {
				return &receipt, receipt.Error
			}
			return &receipt, nil
		}
		return nil, browserError("unknownEffect", "Attempt already dispatched without a receipt; query/reconcile, never replay", "unknown")
	}
	for _, other := range b.channels {
		if len(other.unknown) > 0 {
			return nil, browserError("unknownEffect", "Prior browser mutation has unknown outcome; reconcile it first", "unknown")
		}
	}
	if len(c.attempts) >= 512 {
		return nil, browserError("receiptCapacity", "Document receipt quota exhausted; explicit reconciliation required", "notDispatched")
	}
	return nil, nil
}
