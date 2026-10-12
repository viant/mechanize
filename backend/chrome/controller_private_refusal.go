package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/viant/mcp-protocol/schema"
)

// Only envelope routing is inspected here. Unowned/invalid tool arguments stay
// opaque and never reach the ordinary controller or private reply decoder.
func privateControllerRefusalEnvelope(raw []byte, now time.Time) *controllerRequest {
	if len(raw) > 65536 {
		return nil
	}
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "controllerRequest" {
		return nil
	}
	var r controllerRequest
	if json.Unmarshal(raw, &r) != nil || r.Type != "controllerRequest" || !controllerID.MatchString(r.RequestID) || !controllerID.MatchString(r.SessionID) || !controllerID.MatchString(r.DocumentID) || !controllerOrigin(r.Origin) || r.Deadline <= now.UnixMilli() || r.Deadline > now.Add(10*time.Second).UnixMilli() {
		return nil
	}
	return &r
}

// A distinct request rejected before dispatch receives an ordinary complete MCP
// refusal. Never block the reader behind the active inspection's write lane.
func (b *Broker) refusePrivateController(c *channel, conn net.Conn, r *controllerRequest) {
	yes := true
	body := map[string]any{"code": "controllerToolRejected", "message": "Private request was not dispatched.", "dispatchState": "notDispatched"}
	encoded, _ := json.Marshal(body)
	result, e := controllerCompleteToolResult(&schema.CallToolResult{IsError: &yes, StructuredContent: body, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(encoded)}}})
	if e != nil {
		return
	}
	frame := map[string]any{"type": "controllerResult", "requestId": r.RequestID, "result": result}
	b.mu.Lock()
	if b.closed || c.conn != conn {
		b.mu.Unlock()
		return
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		deadline := time.UnixMilli(r.Deadline)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		for !c.writeMu.TryLock() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		defer c.writeMu.Unlock()
		b.mu.Lock()
		s := c.controllerSessions[r.SessionID]
		current := !b.closed && c.conn == conn && s != nil && s.Approved && s.ExpiresAt.After(time.Now()) && s.Origin == r.Origin && s.DocumentID == r.DocumentID && b.epoch == r.BrokerEpoch && c.epoch == r.ChannelEpoch && c.scopeHash == r.ScopeHash
		b.mu.Unlock()
		if !current || ctx.Err() != nil {
			return
		}
		conn.SetWriteDeadline(deadline)
		_ = WriteFrame(conn, frame)
		conn.SetWriteDeadline(time.Time{})
	}()
}

// Closing the exact fenced controller remains effective during quarantine. It
// carries no tool arguments or renderer data and never waits on the write lane.
func (b *Broker) closePrivateController(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "controllerClosed" {
		return false
	}
	defer clear(raw)
	var closed struct {
		Type         string `json:"type"`
		SessionID    string `json:"sessionId"`
		BrokerEpoch  string `json:"brokerEpoch"`
		ChannelEpoch string `json:"channelEpoch"`
		ScopeHash    string `json:"scopeHash"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 2048 || !uniqueCredentialJSON(raw) || decoder.Decode(&closed) != nil || decoder.Decode(new(any)) != io.EOF || !controllerID.MatchString(closed.SessionID) {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || c.conn != conn || !channelScopeQualified(c) || closed.BrokerEpoch != b.epoch || closed.ChannelEpoch != c.epoch || closed.ScopeHash != c.scopeHash {
		return true
	}
	cancelControllerSession(c.controllerSessions[closed.SessionID])
	delete(c.controllerSessions, closed.SessionID)
	return true
}
