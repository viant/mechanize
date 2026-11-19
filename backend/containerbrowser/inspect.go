package containerbrowser

import (
	"context"
	"encoding/json"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/model"
	"math"
)

func (h *Host) inspect(parent context.Context, s *browserSession, method string, frame *FrameInput, scales ...float64) (*schema.CallToolResult, *jsonrpc.Error) {
	scale := 1.0
	if len(scales) > 0 {
		scale = scales[0]
	}
	if math.IsNaN(scale) || math.IsInf(scale, 0) || scale <= 0 || scale > 1 {
		return failureResult("invalidScale", "notDispatched")
	}
	if err := s.authorize(parent); err != nil {
		return failureResult("unauthorized", "notDispatched")
	}
	select {
	case s.lane <- struct{}{}:
		defer func() { <-s.lane }()
	default:
		return failureResult("sessionBusy", "notDispatched")
	}
	s.mu.Lock()
	ready := s.registered && !s.terminated
	s.mu.Unlock()
	if !ready {
		return failureResult("openTabRequired", "notDispatched")
	}
	ctx, cancel := context.WithTimeout(parent, h.Timeout)
	defer cancel()
	var target *model.Step
	if frame != nil {
		if frame.ID == "" && frame.Name == "" && frame.Ref == "" || len(frame.ID) > 256 || len(frame.Name) > 256 || len(frame.Ref) > 256 {
			return failureResult("invalidFrame", "notDispatched")
		}
		scope := map[string]model.Value{}
		if frame.Ref != "" {
			scope["ref"] = model.Value{Kind: model.StringValue, String: frame.Ref}
		}
		if frame.ID != "" {
			scope["id"] = model.Value{Kind: model.StringValue, String: frame.ID}
		}
		if frame.Name != "" {
			scope["name"] = model.Value{Kind: model.StringValue, String: frame.Name}
		}
		target = &model.Step{Target: model.Selector{Scope: model.Scope{Frame: scope}}}
	}
	raw, err := h.Worker.Call(ctx, method, s.id, target, scale)
	if err != nil {
		if ctx.Err() != nil {
			_ = h.closeSession(s)
		}
		return failureResult("browserObservationFailed", "notDispatched")
	}
	var value struct {
		Origin   string `json:"origin"`
		URL      string `json:"url"`
		Data     string `json:"data"`
		MimeType string `json:"mimeType"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return failureResult("invalidBrowserResult", "notDispatched")
	}
	if !h.Policy.AllowAllWeb && !h.Policy.AllowedSurfaces[value.Origin] {
		return failureResult("originNotAllowed", "notDispatched")
	}
	if method == "screenshot" {
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.ImageContent{Type: "image", MimeType: value.MimeType, Data: value.Data}}}, nil
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		return failureResult("invalidBrowserResult", "notDispatched")
	}
	return toolResult(result)
}
