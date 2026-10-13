package chrome

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"time"
)

// Reverse RPC admits only native-approved document sessions. Diagnostic requests
// use closed projections; standard MCP calls use the canonical host adapter.
// Credentials and native-human authority never enter the controller context.
type controllerRequest struct {
	privateContinuation bool
	privateSession      string
	Params              *ControllerToolCall `json:"params,omitempty"`
	Type                string              `json:"type"`
	RequestID           string              `json:"requestId"`
	Operation           string              `json:"operation"`
	Deadline            int64               `json:"deadlineUnixMs"`
	Origin              string              `json:"origin"`
	DocumentID          string              `json:"documentId"`
	SessionID           string              `json:"sessionId"`
	BrokerEpoch         string              `json:"brokerEpoch"`
	ChannelEpoch        string              `json:"channelEpoch"`
	ScopeHash           string              `json:"scopeHash"`
}

var controllerID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func decodeControllerRequest(raw []byte, now time.Time) (*controllerRequest, bool) {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "controllerRequest" {
		return nil, false
	}
	var r controllerRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 65536 || d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || (r.Operation != "connection.status" && r.Operation != "tools.list" && r.Operation != "browser.inventory.summary" && r.Operation != "tools/list" && r.Operation != "tools/call" && r.Operation != "initialize") ||
		!controllerID.MatchString(r.RequestID) || !controllerID.MatchString(r.DocumentID) || !controllerID.MatchString(r.SessionID) ||
		r.Deadline <= now.UnixMilli() || r.Deadline > now.Add(10*time.Second).UnixMilli() ||
		!controllerOrigin(r.Origin) {
		return nil, true
	}
	if r.Operation == "tools/call" {
		if r.Params == nil || !controllerID.MatchString(r.Params.Name) || len(r.Params.Arguments) == 0 || len(r.Params.Arguments) > 49152 || r.Params.Arguments[0] != '{' {
			return nil, true
		}
	} else if r.Params != nil {
		return nil, true
	}
	return &r, true
}
func (b *Broker) controllerReply(c *channel, conn net.Conn, r *controllerRequest) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := map[string]any{"type": "controllerResult", "requestId": r.RequestID, "error": "unavailable"}
	if !b.controllerRequestAllowedLocked(c, conn, r) {
		return result
	}
	b.renewControllerSessionLocked(c, c.controllerSessions[r.SessionID], time.Now())
	delete(result, "error")
	switch r.Operation {
	case "connection.status":
		result["ready"] = c.scopeQualified && c.executorQualified && !c.fixtureOnly
	case "tools.list":
		result["tools"] = []string{"connection.status", "tools.list", "browser.inventory.summary"}
	case "browser.inventory.summary":
		if !c.inventoryComplete {
			result["error"] = "unavailable"
			return result
		}
		result["documentCount"] = len(c.documents)
		result["pendingCount"] = len(c.pending)
		result["unknownCount"] = len(c.unknown)
	default:
		result["error"] = "unavailable"
	}
	return result
}

func (b *Broker) controllerRequestAllowedLocked(c *channel, conn net.Conn, r *controllerRequest) bool {
	if b.closed || conn == nil || c.conn != conn || !channelScopeQualified(c) || r.BrokerEpoch != b.epoch || r.ChannelEpoch != c.epoch || r.ScopeHash != c.scopeHash ||
		!c.grant.Principal.HasScope("desktop:observe") || quarantinedChannel(c) && (!r.privateContinuation || !b.privateControllerAllowedLocked(c, conn, r)) || c.lifecycleInhibited || time.Now().UnixMilli() >= r.Deadline {
		return false
	}
	s := c.controllerSessions[r.SessionID]
	if !c.controllerPolicy.Enabled || !controllerPolicyMatches(c.controllerPolicy.Origins, r.Origin) || s == nil || !s.Approved || !s.ExpiresAt.After(time.Now()) || s.Origin != r.Origin || s.DocumentID != r.DocumentID {
		return false
	}
	return true
}
