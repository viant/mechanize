package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
)

type ControllerPolicy struct {
	Enabled bool     `json:"enabled"`
	Origins []string `json:"origins"`
}

// ControllerPolicyKey binds saved settings to the exact enrolled owner/channel.
// It carries no live controller-session authority.
type ControllerPolicyKey struct {
	Namespace       string `json:"namespace"`
	ProfileChannel  string `json:"profileChannel"`
	BrowserInstance string `json:"browserInstance"`
	ExtensionOrigin string `json:"extensionOrigin"`
}
type ControllerPolicyStore interface {
	Load(ControllerPolicyKey) (ControllerPolicy, error)
	Save(context.Context, auth.Principal, ControllerPolicyKey, ControllerPolicy) error
}

func controllerPolicyKey(c *channel) ControllerPolicyKey {
	return ControllerPolicyKey{c.grant.Principal.Namespace, c.grant.ProfileChannel, c.grant.BrowserInstance, c.grant.ExtensionOrigin}
}
func ValidControllerPolicy(p ControllerPolicy) bool {
	if len(p.Origins) > 20 || p.Enabled && len(p.Origins) == 0 {
		return false
	}
	for i, o := range p.Origins {
		if !controllerPolicyOrigin(o) || slices.Contains(p.Origins[:i], o) {
			return false
		}
	}
	return true
}

type ControllerSession struct {
	ctx              context.Context
	cancel           context.CancelFunc
	identity         ControllerIdentity
	inFlight         bool
	expiryTimer      *time.Timer
	expiryGeneration uint64
	ID               string    `json:"id"`
	Origin           string    `json:"origin"`
	DocumentID       string    `json:"documentId"`
	TabID            int       `json:"tabId"`
	Approved         bool      `json:"approved"`
	ExpiresAt        time.Time `json:"expiresAt"`
}
type ControllerManagement struct {
	ProfileChannel  string            `json:"profileChannel"`
	BrowserInstance string            `json:"browserInstance"`
	Action          string            `json:"action"`
	Policy          *ControllerPolicy `json:"policy,omitempty"`
	SessionID       string            `json:"sessionId,omitempty"`
}
type ControllerState struct {
	CleanupPending bool                `json:"cleanupPending"`
	Policy         ControllerPolicy    `json:"policy"`
	Sessions       []ControllerSession `json:"sessions"`
	Connected      bool                `json:"connected"`
}

func controllerOrigin(origin string) bool {
	u, e := url.Parse(origin)
	return len(origin) <= 512 && e == nil && u.Host != "" && u.User == nil && u.Scheme+"://"+u.Host == origin && !strings.ContainsAny(origin, "*\\") && (u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))
}

// Policy patterns are a closed local-development exception, not a glob syntax.
// Sender/session origins remain concrete Chrome origins throughout the protocol.
func controllerPolicyOrigin(value string) bool {
	return value == "localhost:*" || value == "http://localhost:*" || value == "https://localhost:*" || controllerOrigin(value)
}
func controllerPolicyMatches(patterns []string, origin string) bool {
	if !controllerOrigin(origin) {
		return false
	}
	u, e := url.Parse(origin)
	if e != nil {
		return false
	}
	for _, pattern := range patterns {
		if pattern == origin {
			return true
		}
		if pattern != "localhost:*" && pattern != "http://localhost:*" && pattern != "https://localhost:*" {
			continue
		}
		if u.Hostname() != "localhost" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if u.Port() == "" && u.Host != "localhost" {
			continue
		}
		if port := u.Port(); port != "" {
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || u.Scheme == "http" && n == 80 || u.Scheme == "https" && n == 443 {
				continue
			}
		}
		if pattern == "localhost:*" || pattern == u.Scheme+"://localhost:*" {
			return true
		}
	}
	return false
}

// ManageControllers is reachable only from the authenticated native human
// control plane. Website target permissions never participate in this policy.
// Saved origins and closed localhost port patterns authorize new document-bound connections; live sessions
// remain volatile and never confer tool consent.
func (g *Gateway) ManageControllers(ctx context.Context, p auth.Principal, in ControllerManagement) (ControllerState, error) {
	g.controllerMu.Lock()
	defer g.controllerMu.Unlock()
	fail := errors.New("controller management unavailable")
	if !auth.NativeHuman(ctx) || authorize(ctx, p, false) != nil {
		return ControllerState{}, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(in.ProfileChannel, in.BrowserInstance)]
	if c == nil || c.grant.Principal.Namespace != p.Namespace {
		b.mu.Unlock()
		return ControllerState{}, fail
	}
	var frame map[string]any
	switch in.Action {
	case "status":
		if in.Policy != nil || in.SessionID != "" {
			b.mu.Unlock()
			return ControllerState{}, fail
		}
	case "configure":
		if in.Policy == nil || in.SessionID != "" || !ValidControllerPolicy(*in.Policy) {
			b.mu.Unlock()
			return ControllerState{}, fail
		}
		for _, o := range in.Policy.Origins {
			if !controllerPolicyOrigin(o) {
				b.mu.Unlock()
				return ControllerState{}, fail
			}
		}
		if g.options.ControllerPolicies != nil {
			if err := g.options.ControllerPolicies.Save(ctx, p, controllerPolicyKey(c), *in.Policy); err != nil {
				b.mu.Unlock()
				return ControllerState{}, fail
			}
		}
		changed := !sameControllerPolicy(c.controllerPolicy, *in.Policy)
		c.controllerPolicy = ControllerPolicy{Enabled: in.Policy.Enabled, Origins: append([]string{}, in.Policy.Origins...)}
		if changed {
			for _, s := range c.controllerSessions {
				cancelControllerSession(s)
			}
			c.controllerSessions = make(map[string]*ControllerSession)
		}
		frame = map[string]any{"type": "controllerPolicy", "enabled": c.controllerPolicy.Enabled, "origins": c.controllerPolicy.Origins}
	case "approve", "revoke":
		if in.Policy != nil || in.SessionID == "" {
			b.mu.Unlock()
			return ControllerState{}, fail
		}
		s := c.controllerSessions[in.SessionID]
		if s == nil || !s.ExpiresAt.After(time.Now()) || !c.controllerPolicy.Enabled || !controllerPolicyMatches(c.controllerPolicy.Origins, s.Origin) {
			b.mu.Unlock()
			return ControllerState{}, fail
		}
		if in.Action == "approve" {
			s.Approved = true
			frame = map[string]any{"type": "controllerApproval", "sessionId": s.ID}
		} else {
			cancelControllerSession(s)
			delete(c.controllerSessions, s.ID)
			frame = map[string]any{"type": "controllerRevocation", "sessionId": s.ID}
		}
	default:
		b.mu.Unlock()
		return ControllerState{}, fail
	}
	state := ControllerState{CleanupPending: c.controllerCleanupPending, Policy: ControllerPolicy{Enabled: c.controllerPolicy.Enabled, Origins: append([]string{}, c.controllerPolicy.Origins...)}, Sessions: []ControllerSession{}, Connected: c.conn != nil}
	for id, s := range c.controllerSessions {
		if !s.ExpiresAt.After(time.Now()) {
			cancelControllerSession(s)
			delete(c.controllerSessions, id)
		} else {
			state.Sessions = append(state.Sessions, *s)
		}
	}
	conn := c.conn
	if frame != nil {
		frame["brokerEpoch"] = b.epoch
		frame["channelEpoch"] = c.epoch
		frame["scopeHash"] = c.scopeHash
	}
	b.mu.Unlock()
	if frame != nil && conn != nil {
		c.writeMu.Lock()
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		err := WriteFrame(conn, frame)
		conn.SetWriteDeadline(time.Time{})
		c.writeMu.Unlock()
		if err != nil {
			conn.Close()
			return ControllerState{}, fail
		}
	}
	return state, nil
}
func (b *Broker) controllerLifecycle(c *channel, conn net.Conn, raw []byte) bool {
	var r struct {
		Type         string `json:"type"`
		SessionID    string `json:"sessionId"`
		Origin       string `json:"origin,omitempty"`
		DocumentID   string `json:"documentId,omitempty"`
		TabID        int    `json:"tabId,omitempty"`
		BrokerEpoch  string `json:"brokerEpoch"`
		ChannelEpoch string `json:"channelEpoch"`
		ScopeHash    string `json:"scopeHash"`
	}
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "controllerOpen" && kind.Type != "controllerClosed" && kind.Type != "controllerSync" {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 4096 || d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return true
	}
	if kind.Type == "controllerSync" {
		b.mu.Lock()
		valid := c.conn == conn && r.BrokerEpoch == b.epoch && r.ChannelEpoch == c.epoch && r.ScopeHash == c.scopeHash
		frame := map[string]any{"type": "controllerPolicy", "enabled": c.controllerPolicy.Enabled, "origins": append([]string{}, c.controllerPolicy.Origins...), "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
		b.mu.Unlock()
		if valid {
			c.writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			err := WriteFrame(conn, frame)
			conn.SetWriteDeadline(time.Time{})
			c.writeMu.Unlock()
			if err != nil {
				conn.Close()
			}
		}
		return true
	}
	b.mu.Lock()
	var admitted *ControllerSession
	defer func() {
		b.mu.Unlock()
		if admitted != nil {
			b.sendControllerAdmission(c, conn, admitted)
		}
	}()
	if c.conn != conn || !channelScopeQualified(c) || r.BrokerEpoch != b.epoch || r.ChannelEpoch != c.epoch || r.ScopeHash != c.scopeHash || !controllerID.MatchString(r.SessionID) {
		return true
	}
	if r.Type == "controllerClosed" {
		cancelControllerSession(c.controllerSessions[r.SessionID])
		delete(c.controllerSessions, r.SessionID)
		return true
	}
	if !c.controllerPolicy.Enabled || !controllerPolicyMatches(c.controllerPolicy.Origins, r.Origin) || !controllerID.MatchString(r.DocumentID) || r.TabID < 0 || len(c.controllerSessions) >= 8 || c.controllerSessions[r.SessionID] != nil {
		return true
	}
	if c.controllerSessions == nil {
		for _, s := range c.controllerSessions {
			cancelControllerSession(s)
		}
		c.controllerSessions = make(map[string]*ControllerSession)
	}
	c.controllerSessions[r.SessionID] = &ControllerSession{ID: r.SessionID, Origin: r.Origin, DocumentID: r.DocumentID, TabID: r.TabID, Approved: true, ExpiresAt: time.Now().Add(controllerIdleTTL)}
	b.initControllerSessionLocked(c, c.controllerSessions[r.SessionID])
	admitted = c.controllerSessions[r.SessionID]
	return true
}

func sameControllerPolicy(a, b ControllerPolicy) bool {
	if a.Enabled != b.Enabled || len(a.Origins) != len(b.Origins) {
		return false
	}
	left, right := append([]string(nil), a.Origins...), append([]string(nil), b.Origins...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// The saved origin policy authorizes this connection only. Every tool request
// still passes its original authenticated controller and tool-consent gates.
func (b *Broker) sendControllerAdmission(c *channel, conn net.Conn, s *ControllerSession) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	b.mu.Lock()
	valid := !b.closed && c.conn == conn && channelScopeQualified(c) && c.controllerSessions[s.ID] == s && s.Approved && s.ExpiresAt.After(time.Now()) && c.controllerPolicy.Enabled && controllerPolicyMatches(c.controllerPolicy.Origins, s.Origin)
	frame := map[string]any{"type": "controllerApproval", "sessionId": s.ID, "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
	b.mu.Unlock()
	if !valid {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	err := WriteFrame(conn, frame)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
	}
}
