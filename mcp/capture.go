package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

const MaximumInlineCaptureBytes = 2 << 20

type CaptureWindowsInput struct {
	SessionID string        `json:"sessionId"`
	GrantID   string        `json:"grantId"`
	Purpose   string        `json:"purpose"`
	Surface   model.Surface `json:"surface"`
	Limit     int           `json:"limit,omitempty"`
}
type CaptureWindowInput struct {
	SessionID string        `json:"sessionId"`
	GrantID   string        `json:"grantId"`
	Purpose   string        `json:"purpose"`
	Surface   model.Surface `json:"surface"`
	PID       int32         `json:"pid"`
	WindowID  uint32        `json:"windowId"`
}
type CaptureResult struct {
	Artifact        data.ArtifactReference `json:"artifact"`
	Metadata        native.CaptureMetadata `json:"metadata"`
	ImageReturned   bool                   `json:"imageReturned"`
	ImageIsPreview  bool                   `json:"imageIsPreview"`
	Preview         *CapturePreview        `json:"preview,omitempty"`
	InlineByteLimit int                    `json:"inlineByteLimit"`
	Reason          string                 `json:"reason,omitempty"`
}

func captureContext(ctx context.Context, session, grant, purpose string) (context.Context, auth.Principal, error) {
	if session == "" || purpose == "" {
		return nil, auth.Principal{}, errors.New("owned session and exact purpose required; host verifies session or permanent observe approval")
	}
	p, err := auth.FromContext(ctx)
	if err != nil {
		return nil, p, err
	}
	return auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, GrantID: grant, Purpose: purpose}), p, nil
}

func captureFailure(err error, ref data.ArtifactReference) (*schema.CallToolResult, *jsonrpc.Error) {
	var transport *native.CaptureError
	if errors.As(err, &transport) {
		code, message := "captureFailed", "Capture did not return publishable evidence; inspect cleanup status before continuing"
		var nativeErr *native.NativeError
		if errors.As(err, &nativeErr) {
			switch nativeErr.Code {
			case "permissionDenied":
				code, message = "permissionDenied", "Mechanize helper needs macOS Screen Recording permission; review its status in the native permission panel"
			case "targetNotFound", "staleReference", "staleEpoch":
				code, message = nativeErr.Code, "The exact capture target changed; refresh scoped window discovery before another capture"
			case "captureTooLarge":
				code, message = nativeErr.Code, "Capture exceeds the configured image byte or pixel budget"
			case "captureOffDisplay":
				code, message = nativeErr.Code, "The full window is outside one display; move it fully onto a display, then refresh window discovery"
			case "captureAmbiguousDisplay":
				code, message = nativeErr.Code, "The window does not have one unambiguous display; choose a single-display position and refresh discovery"
			case "captureUnqualified":
				code, message = nativeErr.Code, "Exact full-window capture is not qualified for this window geometry or platform"
			case "invalidScope":
				code, message = nativeErr.Code, "Capture requires the exact approved application, PID and physical window"
			}
		}
		r, rpcErr := failure(&model.MechanizeError{Code: code, Message: message, Stage: "capture", DispatchState: transport.DispatchState})
		body := r.StructuredContent.(map[string]any)
		body["cleanupConfirmed"] = transport.CleanupConfirmed
		encoded, _ := result(body)
		encoded.IsError = r.IsError
		return encoded, rpcErr
	}
	if ref.ID != "" {
		r, rpcErr := result(map[string]any{"code": "artifactPublicationUnconfirmed", "message": "Encrypted capture bytes retained; metadata publication requires reconciliation", "artifact": ref, "publicationState": "unknown", "dispatchState": "dispatched", "imageReturned": false})
		bad := true
		r.IsError = &bad
		return r, rpcErr
	}
	return failure(err)
}

func registerCapture(base *protocol.DefaultHandler, d Dependencies) error {
	if d.CaptureWindows != nil {
		if err := protocol.RegisterTool[*CaptureWindowsInput, *native.CaptureWindowList](base.Registry, "mechanize_capture_windows", "List bounded fresh physical windows for one native application under observe consent. A once grant is consumed by discovery; use a session grant for discovery followed by capture. No display capture.", func(ctx context.Context, in *CaptureWindowsInput) (*schema.CallToolResult, *jsonrpc.Error) {
			if in == nil {
				return failure(errors.New("capture discovery input required"))
			}
			bound, p, err := captureContext(ctx, in.SessionID, in.GrantID, in.Purpose)
			if err != nil {
				return failure(err)
			}
			limit := in.Limit
			if limit == 0 {
				limit = 32
			}
			if limit < 1 || limit > native.MaximumCaptureWindows {
				return failure(errors.New("limit must be 1...128"))
			}
			windows, err := d.CaptureWindows(bound, p, in.Surface, limit)
			if err != nil {
				return captureFailure(err, data.ArtifactReference{})
			}
			return result(windows)
		}); err != nil {
			return err
		}
	}
	if d.CaptureWindow == nil {
		return nil
	}
	return protocol.RegisterTool[*CaptureWindowInput, *CaptureResult](base.Registry, "mechanize_capture", "Capture an exact native application/PID/window under observe consent and publish encrypted full-resolution evidence. Inline images are bounded to 2 MiB; large images may return an explicitly labelled PNG/JPEG preview with logical mapping. Unfit previews are omitted. Screenshot is separate from AX and proves no business outcome.", func(ctx context.Context, in *CaptureWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil || in.PID <= 0 || in.WindowID == 0 {
			return failure(errors.New("exact positive PID and physical windowId required"))
		}
		bound, p, err := captureContext(ctx, in.SessionID, in.GrantID, in.Purpose)
		if err != nil {
			return failure(err)
		}
		ref, image, err := d.CaptureWindow(bound, p, in.Surface, in.PID, in.WindowID)
		if err != nil {
			return captureFailure(err, ref)
		}
		hash := sha256.Sum256(image.PNG)
		m := image.Metadata
		if ref.ID == "" || ref.MediaType != "image/png" || ref.SizeBytes != len(image.PNG) || ref.ContentHash != hex.EncodeToString(hash[:]) || len(image.PNG) == 0 || len(image.PNG) > native.MaximumCaptureBytes || m.BundleID != in.Surface.BundleID || m.PID != in.PID || m.WindowID != in.WindowID || m.Bytes != len(image.PNG) || m.Identity != fmt.Sprintf("window:%d", in.WindowID) {
			return failure(&model.MechanizeError{Code: "captureEvidenceMismatch", Message: "Capture publication did not match the exact requested window and bytes", Stage: "capture", DispatchState: "unknown"})
		}
		out := CaptureResult{Artifact: ref, Metadata: m, ImageReturned: len(image.PNG) <= MaximumInlineCaptureBytes, InlineByteLimit: MaximumInlineCaptureBytes}
		inline, mime := image.PNG, "image/png"
		if !out.ImageReturned {
			preview, previewErr := BuildCapturePreview(ctx, image.PNG, m, MaximumInlineCaptureBytes)
			out.Preview = &preview
			if previewErr == nil && preview.Available {
				out.ImageReturned, out.ImageIsPreview = true, true
				inline, mime = preview.Image, preview.MimeType
				out.Reason = "Inline image is a display preview; full-resolution evidence remains in the immutable encrypted artifact"
			} else {
				out.Reason = "Full image saved; bounded display preview unavailable"
				if previewErr == nil {
					out.Reason = preview.Reason
				}
			}
		}
		r, rpcErr := result(out)
		if rpcErr == nil && out.ImageReturned {
			r.Content = append(r.Content, schema.ImageContent{Type: "image", MimeType: mime, Data: base64.StdEncoding.EncodeToString(inline)})
		}
		return r, rpcErr
	})
}
