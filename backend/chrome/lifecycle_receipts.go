package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

type LifecycleReceiptInventory struct {
	GuardID, Owner, ClientID, ProfileChannel, BrowserInstance, BrokerEpoch, ChannelEpoch, ScopeHash, TrustScope string
	Process                                                                                                     nativepeer.ChromeProcessEvidence
	ProcessTrust                                                                                                *nativepeer.ChromeProcessPolicy
	ExtensionOrigin, ProfileDirectory                                                                           string
	Origins                                                                                                     []string
	ProfileQualified                                                                                            bool
	Roots                                                                                                       []Identity
}
type LifecycleReceiptGuard struct {
	gateway   *Gateway
	channel   *channel
	owner     auth.Principal
	inventory LifecycleReceiptInventory
	peer      nativepeer.ChromeProcessEvidence
	conn      net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	active    atomic.Bool
	lane      chan struct{}
}
type lifecycleReply struct {
	raw json.RawMessage
	err error
}

var ErrLifecycleReceiptAuthority = errors.New("active exact old-channel lifecycle authority required")

// BeginLifecycleReceiptExport acquires an opaque lifecycle capability and
// inhibits normal admission. Close never clears that inhibition.
func (g *Gateway) BeginLifecycleReceiptExport(ctx context.Context, p auth.Principal, profile, browser string) (*LifecycleReceiptGuard, error) {
	if err := authorize(ctx, p, true); err != nil {
		return nil, err
	}
	actor, _ := auth.FromContext(ctx)
	if actor.ClientID == "" || actor.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(profile, browser)]
	owned := c != nil && c.grant.Principal.Namespace == p.Namespace
	b.mu.Unlock()
	if !owned {
		return nil, auth.ErrUnauthorized
	}
	if err := b.verifyChannelProcess(ctx, c); err != nil {
		return nil, ErrLifecycleReceiptAuthority
	}
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.channels[channelKey(profile, browser)] != c || b.closed || c.conn == nil || c.fixtureOnly || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || !channelScopeQualified(c) || (!c.executorQualified && !c.lifecycleInhibited) || c.lifecycleGuard != nil || c.lifecycleOwner != "" && c.lifecycleOwner != actor.ClientID || !c.inventoryComplete || len(c.pending) != 0 || len(c.unknown) != 0 {
		return nil, ErrLifecycleReceiptAuthority
	}
	roots, err := lifecycleRoots(c.documents)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	guard := &LifecycleReceiptGuard{gateway: g, channel: c, owner: actor, peer: *c.processEvidence, conn: c.conn, ctx: life, cancel: cancel, lane: make(chan struct{}, 1), inventory: LifecycleReceiptInventory{GuardID: newID(), Owner: p.Namespace, ClientID: actor.ClientID, ProfileChannel: profile, BrowserInstance: browser, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, TrustScope: c.grant.TrustScope, Roots: roots}}
	guard.peer.Ancestors = append([]session.ProcessIdentity(nil), guard.peer.Ancestors...)
	guard.inventory.Process = guard.peer
	guard.inventory.Process.Ancestors = append([]session.ProcessIdentity(nil), guard.peer.Ancestors...)
	if b.processTrust != nil {
		copy := *b.processTrust
		guard.inventory.ProcessTrust = &copy
	}
	guard.inventory.ExtensionOrigin = c.grant.ExtensionOrigin
	guard.inventory.ProfileDirectory = c.grant.ProfileDirectory
	guard.inventory.Origins = append([]string(nil), c.grant.Origins...)
	guard.inventory.ProfileQualified = c.profileQualified
	guard.active.Store(true)
	c.lifecycleGuard = guard
	c.lifecycleInhibited = true
	c.lifecycleOwner = actor.ClientID
	c.executorQualified = false
	return guard, nil
}
func lifecycleRoots(documents []Document) ([]Identity, error) {
	roots := []Identity{}
	seen := map[string]bool{}
	for _, d := range documents {
		if d.FrameID != 0 {
			continue
		}
		key := channelKey(d.ProfileChannel, d.BrowserInstance) + "/" + d.DocumentID
		if d.TabID < 1 || d.DocumentID == "" || d.Generation == 0 || seen[key] {
			return nil, ErrLifecycleReceiptAuthority
		}
		seen[key] = true
		roots = append(roots, d.Identity)
	}
	if len(roots) > 64 {
		return nil, ErrLifecycleReceiptAuthority
	}
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].TabID != roots[j].TabID {
			return roots[i].TabID < roots[j].TabID
		}
		return roots[i].DocumentID < roots[j].DocumentID
	})
	return roots, nil
}
func (g *LifecycleReceiptGuard) validLocked() bool {
	if g == nil || g.gateway == nil || g.channel == nil || !g.active.Load() || g.ctx.Err() != nil {
		return false
	}
	b, c := g.gateway.broker, g.channel
	if b.channels[channelKey(g.inventory.ProfileChannel, g.inventory.BrowserInstance)] != c || b.closed || c.lifecycleGuard != g || !c.lifecycleInhibited || c.executorQualified || c.conn != g.conn || c.epoch != g.inventory.ChannelEpoch || c.scopeHash != g.inventory.ScopeHash || b.epoch != g.inventory.BrokerEpoch || c.grant.TrustScope != g.inventory.TrustScope || c.grant.Principal.Namespace != g.owner.Namespace || c.processEvidence == nil || c.processEvidence.NativeHost != g.peer.NativeHost || c.processEvidence.ChromeParent != g.peer.ChromeParent || !channelScopeQualified(c) || !c.inventoryComplete || len(c.unknown) != 0 {
		return false
	}
	if !reflect.DeepEqual(b.processTrust, g.inventory.ProcessTrust) || c.grant.ExtensionOrigin != g.inventory.ExtensionOrigin || c.grant.ProfileDirectory != g.inventory.ProfileDirectory || c.profileQualified != g.inventory.ProfileQualified || !reflect.DeepEqual(c.grant.Origins, g.inventory.Origins) {
		return false
	}
	roots, err := lifecycleRoots(c.documents)
	if err != nil || len(roots) != len(g.inventory.Roots) {
		return false
	}
	for i, r := range roots {
		original := g.inventory.Roots[i]
		if r.ProfileChannel != original.ProfileChannel || r.BrowserInstance != original.BrowserInstance || r.TabID != original.TabID || r.FrameID != original.FrameID || r.DocumentID != original.DocumentID || r.Generation < original.Generation {
			return false
		}
	}
	return true
}
func (g *LifecycleReceiptGuard) check(ctx context.Context, p auth.Principal) error {
	if g == nil || g.gateway == nil || !g.active.Load() {
		return ErrLifecycleReceiptAuthority
	}
	if err := authorize(ctx, p, true); err != nil {
		return err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != g.owner.ClientID || p.ClientID != g.owner.ClientID || p.Namespace != g.owner.Namespace {
		return auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.gateway.broker.verifyChannelProcess(ctx, g.channel); err != nil {
		return ErrLifecycleReceiptAuthority
	}
	b := g.gateway.broker
	b.mu.Lock()
	valid := g.validLocked()
	b.mu.Unlock()
	if !valid {
		return ErrLifecycleReceiptAuthority
	}
	return nil
}
func (g *LifecycleReceiptGuard) Inventory(ctx context.Context, p auth.Principal) (LifecycleReceiptInventory, error) {
	if err := g.check(ctx, p); err != nil {
		return LifecycleReceiptInventory{}, err
	}
	b := g.gateway.broker
	b.mu.Lock()
	idle := g.validLocked() && len(g.channel.pending) == 0
	b.mu.Unlock()
	if !idle {
		return LifecycleReceiptInventory{}, ErrLifecycleReceiptAuthority
	}
	out := g.inventory
	out.Roots = append([]Identity(nil), out.Roots...)
	out.Origins = append([]string(nil), out.Origins...)
	out.Process.Ancestors = append([]session.ProcessIdentity(nil), out.Process.Ancestors...)
	if out.ProcessTrust != nil {
		copy := *out.ProcessTrust
		out.ProcessTrust = &copy
	}
	return out, nil
}
func (g *LifecycleReceiptGuard) Close() {
	if g == nil || g.gateway == nil {
		return
	}
	g.active.Store(false)
	g.cancel()
	b := g.gateway.broker
	b.mu.Lock()
	if g.channel.lifecycleGuard == g {
		g.channel.lifecycleGuard = nil
	}
	b.mu.Unlock()
}
func (g *LifecycleReceiptGuard) pinned(identity Identity) bool {
	for _, root := range g.inventory.Roots {
		if root == identity {
			return true
		}
	}
	return false
}

// call is lifecycle-only: it cannot dispatch an application/browser mutation.
func (g *LifecycleReceiptGuard) call(ctx context.Context, p auth.Principal, command Command) (json.RawMessage, error) {
	if err := g.check(ctx, p); err != nil {
		return nil, err
	}
	if !g.admitLifecycleCommand(command) {
		return nil, ErrLifecycleReceiptAuthority
	}
	select {
	case g.lane <- struct{}{}:
		defer func() { <-g.lane }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, ErrLifecycleReceiptAuthority
	}
	if err := g.check(ctx, p); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if command.RequestID == "" {
		command.RequestID = newID()
	}
	command.BrokerEpoch = g.inventory.BrokerEpoch
	command.ChannelEpoch = g.inventory.ChannelEpoch
	command.ScopeHash = g.inventory.ScopeHash
	command.DeadlineUnixMS = deadline.UnixMilli()
	b := g.gateway.broker
	pendingRequest := &pending{command: command, lifecycle: g, lifecycleDone: make(chan lifecycleReply, 1)}
	b.mu.Lock()
	if !g.validLocked() || len(g.channel.pending) != 0 {
		b.mu.Unlock()
		return nil, ErrLifecycleReceiptAuthority
	}
	g.channel.pending[command.RequestID] = pendingRequest
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(g.channel.pending, command.RequestID); b.mu.Unlock() }()
	g.channel.writeMu.Lock()
	err := g.check(ctx, p)
	if err == nil {
		_ = g.conn.SetWriteDeadline(deadline)
		err = WriteFrame(g.conn, struct {
			Command
			Type    string `json:"type"`
			GuardID string `json:"lifecycleGuardId"`
		}{command, "lifecycle", g.inventory.GuardID})
		_ = g.conn.SetWriteDeadline(time.Time{})
	}
	g.channel.writeMu.Unlock()
	if err != nil {
		return nil, ErrLifecycleReceiptAuthority
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case response := <-pendingRequest.lifecycleDone:
		if response.err != nil {
			return nil, response.err
		}
		if err = g.check(ctx, p); err != nil {
			return nil, err
		}
		return response.raw, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, ErrLifecycleReceiptAuthority
	case <-timer.C:
		return nil, ErrLifecycleReceiptAuthority
	}
}
func (g *LifecycleReceiptGuard) FetchPage(ctx context.Context, p auth.Principal, pinned Identity, request ReceiptExportRequest) (json.RawMessage, error) {
	if request.RequestID == "" || request.Offset < 0 || request.Offset > 512 || request.Limit < 1 || request.Limit > 64 || request.Offset > 0 && request.ExpectedRevision == nil {
		return nil, invalidReceiptExport()
	}
	args := map[string]any{"offset": request.Offset, "limit": request.Limit}
	if request.ExpectedRevision != nil {
		args["expectedRevision"] = *request.ExpectedRevision
	}
	raw, err := g.call(ctx, p, Command{RequestID: request.RequestID, Action: "executor.receipts", Identity: pinned, Args: args})
	if err != nil {
		return nil, err
	}
	page, err := DecodeReceiptExportPage(raw)
	if err != nil || page.RequestID != request.RequestID {
		return nil, invalidReceiptExport()
	}
	return raw, nil
}
func (g *LifecycleReceiptGuard) Collect(ctx context.Context, p auth.Principal, pinned Identity) (ReceiptExportManifest, error) {
	return CollectReceiptExport(ctx, pinned, func(c context.Context, i Identity, r ReceiptExportRequest) (json.RawMessage, error) {
		return g.FetchPage(c, p, i, r)
	})
}
func (g *LifecycleReceiptGuard) Quiesce(ctx context.Context, p auth.Principal, pinned Identity) error {
	raw, err := g.call(ctx, p, Command{Action: "executor.quiesce", Identity: pinned})
	if err != nil {
		return err
	}
	var reply struct {
		Quiescent bool `json:"quiescent"`
	}
	if json.Unmarshal(raw, &reply) != nil || !reply.Quiescent {
		return ErrLifecycleReceiptAuthority
	}
	return nil
}
func (g *LifecycleReceiptGuard) RetireControl(ctx context.Context, p auth.Principal) error {
	if err := g.check(ctx, p); err != nil {
		return err
	}
	gateway := g.gateway
	gateway.controlMu.Lock()
	var authority *ControlAuthority
	if gateway.control != nil {
		copy := *gateway.control
		authority = &copy
	}
	gateway.controlMu.Unlock()
	if authority == nil {
		return nil
	}
	if authority.Owner != p.Namespace || authority.ClientID != p.ClientID || authority.Document.ProfileChannel != g.inventory.ProfileChannel || authority.Document.BrowserInstance != g.inventory.BrowserInstance {
		return ErrLifecycleReceiptAuthority
	}
	raw, err := g.call(ctx, p, Command{Action: "executor.retire", Identity: authority.Document.Identity, ControlLease: &authority.Lease})
	if err != nil {
		return err
	}
	var reply Reply
	if json.Unmarshal(raw, &reply) != nil || !reply.RetiredAuthorityQuiesced || reply.ControlLease == nil || *reply.ControlLease != authority.Lease {
		return ErrLifecycleReceiptAuthority
	}
	gateway.controlMu.Lock()
	defer gateway.controlMu.Unlock()
	if gateway.control == nil || !sameControl(*gateway.control, *authority) {
		return ErrLifecycleReceiptAuthority
	}
	gateway.control = nil
	gateway.controlRetiring = false
	return nil
}

// StopRecording accepts only a code-owned scoped recording identity. It exports
// no recording events; retained recording history must be persisted separately.
func (g *LifecycleReceiptGuard) StopRecording(ctx context.Context, p auth.Principal, pinned Identity, recordingID string) error {
	if !receiptOpaqueID.MatchString(recordingID) {
		return ErrLifecycleReceiptAuthority
	}
	raw, err := g.call(ctx, p, Command{Action: "record.stop", Identity: pinned, Args: map[string]any{"recordingId": recordingID}})
	if err != nil {
		return err
	}
	var reply struct {
		ID    string `json:"recordingId"`
		State string `json:"recordingState"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.ID != recordingID || reply.State != "stopped" {
		return ErrLifecycleReceiptAuthority
	}
	return nil
}
