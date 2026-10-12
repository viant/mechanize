package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
)

// ControllerIdentity is minted only after native approval of a Chrome-owned
// document/port. ConversationID is the locally minted port ID, never page input.
type ControllerIdentity struct {
	Principal       auth.Principal
	ConversationID  string
	Origin          string
	DocumentID      string
	ProfileChannel  string
	BrowserInstance string
	// Receiver capability derived from the authenticated extension hello, never page params.
	CatalogToolLimit int
}
type ControllerToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Implementations must reuse the canonical host tool handlers and enforce closed
// input/result policy. No transport credentials or native-human assertion exist
// in the context handed to a controller.
type ControllerDispatcher interface {
	Initialize(context.Context, ControllerIdentity) (*schema.InitializeResult, error)
	ListTools(context.Context, ControllerIdentity) (*schema.ListToolsResult, error)
	CallTool(context.Context, ControllerIdentity, ControllerToolCall) (*schema.CallToolResult, error)
	CloseController(context.Context, ControllerIdentity) error
}

func (g *Gateway) SetControllerDispatcher(d ControllerDispatcher) error {
	if d == nil {
		return errors.New("controller dispatcher required")
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.controllerDispatcher != nil || b.closed {
		return errors.New("controller dispatcher already set or closed")
	}
	b.controllerDispatcher = d
	return nil
}
func (b *Broker) initControllerSessionLocked(c *channel, s *ControllerSession) {
	identity := ControllerIdentity{Principal: c.grant.Principal, ConversationID: s.ID, Origin: s.Origin, DocumentID: s.DocumentID, ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, CatalogToolLimit: controllerCatalogLimit(c.extensionVersion)}
	raw, _ := json.Marshal([]string{"mechanize.controller.client.v1", b.epoch, c.epoch, c.scopeHash, s.Origin, s.DocumentID, s.ID})
	digest := sha256.Sum256(raw)
	identity.Principal.ClientID = "controller:" + hex.EncodeToString(digest[:])
	identity.Principal.ClientName = "Web controller: " + s.Origin
	identity.Principal.Scopes = nil
	for _, scope := range []string{"desktop:observe", "desktop:control"} {
		if c.grant.Principal.HasScope(scope) {
			identity.Principal.Scopes = append(identity.Principal.Scopes, scope)
		}
	}
	s.identity = identity
	s.ctx, s.cancel = context.WithDeadline(auth.WithPrincipal(context.Background(), identity.Principal), s.ExpiresAt)
	dispatcher := b.controllerDispatcher
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		<-s.ctx.Done()
		if dispatcher != nil {
			ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), identity.Principal), 3*time.Second)
			defer cancel()
			if dispatcher.CloseController(ctx, identity) != nil {
				b.mu.Lock()
				c.controllerCleanupPending = true
				b.mu.Unlock()
			}
		}
	}()
}
func cancelControllerSession(s *ControllerSession) {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}
func (b *Broker) controllerMCPLocked(c *channel, conn net.Conn, r *controllerRequest) bool {
	if r.Operation != "tools/list" && r.Operation != "tools/call" && r.Operation != "initialize" {
		return false
	}
	b.mu.Lock()
	s := c.controllerSessions[r.SessionID]
	valid := b.controllerRequestAllowedLocked(c, conn, r) && s != nil && s.ctx != nil && s.ctx.Err() == nil && !s.inFlight && b.controllerDispatcher != nil && !c.controllerCleanupPending
	if !valid {
		b.mu.Unlock()
		return false
	}
	s.inFlight = true
	dispatcher := b.controllerDispatcher
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()

		ctx, cancel := context.WithDeadline(s.ctx, time.UnixMilli(r.Deadline))
		defer cancel()
		var result any
		var err error
		if r.Operation == "initialize" {
			result, err = dispatcher.Initialize(ctx, s.identity)
		} else if r.Operation == "tools/list" {
			var listed *schema.ListToolsResult
			listed, err = dispatcher.ListTools(ctx, s.identity)
			if err == nil && listed != nil {
				// Serialize the negotiated controller wire contract explicitly.
				// Upstream schema versions add cache/result hints to ListToolsResult;
				// those are not part of this closed browser-facing projection.
				tools := listed.Tools
				if tools == nil {
					tools = []schema.Tool{}
				}
				result = struct {
					Tools []schema.Tool `json:"tools"`
				}{Tools: tools}
			}
		} else {
			var answer *schema.CallToolResult
			answer, err = dispatcher.CallTool(ctx, s.identity, *r.Params)
			if err == nil {
				result, err = controllerCompleteToolResult(answer)
			}
		}
		frame := map[string]any{"type": "controllerResult", "requestId": r.RequestID, "error": controllerTransferCode(err)}
		var body []byte
		if err == nil && result != nil {
			body, err = json.Marshal(result)
			if err != nil {
				frame["error"] = "resultTransferInvalid"
			} else if len(body) > controllerResultLimit {
				frame["error"] = "resultTransferTooLarge"
			} else {
				delete(frame, "error")
				frame["result"] = result
			}
		}
		defer clear(body)
		raw, e := json.Marshal(frame)
		chunked := e == nil && len(raw) > controllerSmallResultLimit && r.Operation == "tools/call" && frame["error"] == nil
		b.mu.Lock()
		supported := c.controllerResultChunkVersion == 1
		b.mu.Unlock()
		if projection, ok := result.(controllerResultProjection); ok && !supported {
			for _, block := range projection.Content {
				if string(block["type"]) == `"image"` {
					frame = map[string]any{"type": "controllerResult", "requestId": r.RequestID, "error": "resultTransferInvalid"}
					chunked = false
					raw = nil
					break
				}
			}
		}
		if e != nil || len(raw) > controllerSmallResultLimit && (!chunked || !supported) {
			frame = map[string]any{"type": "controllerResult", "requestId": r.RequestID, "error": "resultTransferTooLarge"}
			chunked = false
		}
		defer func() { b.mu.Lock(); s.inFlight = false; b.mu.Unlock() }()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		count := 1
		digest := ""
		if chunked {
			count = (len(body) + controllerChunkBytes - 1) / controllerChunkBytes
			digest = controllerResultDigest(body)
		}
		for index := 0; index < count; index++ {
			b.mu.Lock()
			current := b.controllerRequestAllowedLocked(c, conn, r) && c.controllerSessions[r.SessionID] == s && ctx.Err() == nil
			b.mu.Unlock()
			if !current {
				return
			}
			deadline := time.Now().Add(time.Second)
			if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
				deadline = original
			}
			conn.SetWriteDeadline(deadline)
			var payload any = frame
			if chunked {
				payload = controllerChunk(r, body, digest, index)
			}
			err = WriteFrame(conn, payload)
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				conn.Close()
				return
			}
		}
	}()
	return true
}

// The browser bridge implements the 2025-11-25 complete tool-result contract.
// July input_required/future union members cannot be flattened into success.
func controllerCompleteToolResult(answer *schema.CallToolResult) (any, error) {
	if answer == nil || answer.ResultType != "" && answer.ResultType != "complete" {
		return nil, errors.New("controller result continuation unavailable")
	}
	content, err := projectControllerContent(answer.Content)
	if err != nil {
		return nil, err
	}
	if answer.StructuredContent != nil {
		raw, e := json.Marshal(answer.StructuredContent)
		if e != nil || len(raw) == 0 || raw[0] != '{' {
			return nil, controllerTransferFailure("resultTransferInvalid")
		}
		if len(raw) > controllerResultLimit {
			return nil, controllerTransferFailure("resultTransferTooLarge")
		}
	}
	return controllerResultProjection{Content: content, StructuredContent: answer.StructuredContent, IsError: answer.IsError}, nil
}
