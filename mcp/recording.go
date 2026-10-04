package mcp

import (
	"context"
	"errors"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/recording"
	"github.com/viant/mechanize/record"
)

type RecordingRef struct {
	RecordingID string `json:"recordingId"`
	SessionID   string `json:"sessionId"`
}

// RegisterRecording registers only when a complete owned recording service is wired.
func RegisterRecording(base *protocol.DefaultHandler, s *recording.Service) error {
	if s == nil {
		return nil
	}
	if err := protocol.RegisterTool[*recording.StartRequest, *recording.Status](base.Registry, "mechanize_record_start", "Request declared desktop or scoped Chrome demonstration capture with owned session record consent, an objective, bounded duration/events and local text redaction. The configured backend must support that surface. Capture never establishes business success.", func(ctx context.Context, input *recording.StartRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(errors.New("recording scope required"))
		}
		p, e := auth.FromContext(ctx)
		if e != nil {
			return failure(e)
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: input.GrantID, SessionID: input.SessionID, Purpose: input.Purpose})
		v, e := s.Start(ctx, p, *input)
		if e != nil {
			return failure(e)
		}
		return result(v)
	}); err != nil {
		return err
	}
	for _, entry := range []struct {
		name, description string
		call              func(context.Context, auth.Principal, string) (recording.Status, error)
	}{
		{"mechanize_record_pause", "Pause the owned recording; persist trailing events and report unconfirmed controls honestly.", s.Pause},
		{"mechanize_record_stop", "Stop the owned recording and persist trailing events. Host loss yields unconfirmed stop and a coverage gap.", s.Stop},
		{"mechanize_record_status", "Inspect owned capture state and persisted coverage; restart evidence never proves a live recording.", s.Status},
	} {
		entry := entry
		if e := protocol.RegisterTool[*RecordingRef, *recording.Status](base.Registry, entry.name, entry.description, func(ctx context.Context, input *RecordingRef) (*schema.CallToolResult, *jsonrpc.Error) {
			if input == nil || input.RecordingID == "" || input.SessionID == "" {
				return failure(errors.New("recordingId and owned sessionId required"))
			}
			p, e := auth.FromContext(ctx)
			if e != nil {
				return failure(e)
			}
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: input.SessionID})
			v, e := entry.call(ctx, p, input.RecordingID)
			if e != nil {
				return failure(e)
			}
			return result(v)
		}); e != nil {
			return e
		}
	}
	return protocol.RegisterTool[*recording.ExportRequest, *record.Export](base.Registry, "mechanize_record_export", "Compile the owned persisted demonstration into editable typed IR with parameters, provenance, gaps and review issues. Always unqualified until isolated replay and independent outcome checks; reviewed does not grant production readiness.", func(ctx context.Context, input *recording.ExportRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil || input.RecordingID == "" || input.SessionID == "" {
			return failure(errors.New("recordingId and owned sessionId required"))
		}
		p, e := auth.FromContext(ctx)
		if e != nil {
			return failure(e)
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: input.SessionID})
		v, e := s.Export(ctx, p, *input)
		if e != nil {
			return failure(e)
		}
		return result(v)
	})
}
