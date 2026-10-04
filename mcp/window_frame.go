package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
)

type WindowFrameCaptureResult struct {
	Purpose       string                   `json:"purpose"`
	CaptureRef    string                   `json:"captureRef"`
	Artifact      data.ArtifactReference   `json:"artifact"`
	Provenance    data.ArtifactReference   `json:"provenance"`
	Metadata      native.WindowFramePermit `json:"metadata"`
	ImageReturned bool                     `json:"imageReturned"`
}

func registerWindowFrameCapture(base *protocol.DefaultHandler, capture CaptureWindowFrame) error {
	if capture == nil {
		return nil
	}
	return protocol.RegisterTool[*CaptureWindowInput, *WindowFrameCaptureResult](base.Registry, "mechanize_capture_window_frame", "Capture one exact native process/window for a single left click in the returned image's integer pixel coordinates. Requires separate operator windowFrameClick qualification and observe/control consent. Returns encrypted PNG/provenance plus a one-use 30-second captureRef. Execute the click with the same session, grant and returned purpose. Full-resolution PNGs are bounded to 32 MiB; larger images fail. No scaling or global pointer coordinates. Artifact refs grant no input authority.", func(ctx context.Context, in *CaptureWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil || in.PID <= 0 || in.WindowID == 0 || in.Surface.ProcessID != int(in.PID) || in.Surface.ProcessStartToken == "" || in.Surface.ValidateProcessIdentity() != nil {
			return failure(errors.New("exact positive native PID, birth token and physical window required"))
		}
		bound, p, err := captureContext(ctx, in.SessionID, in.GrantID, in.Purpose)
		if err != nil {
			return failure(err)
		}
		imageRef, provenanceRef, frame, err := capture(bound, p, in.Surface, in.PID, in.WindowID)
		if err != nil {
			return captureFailure(err, imageRef)
		}
		sum := sha256.Sum256(frame.PNG)
		permit := frame.Permit
		owner := native.WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: in.SessionID}
		if imageRef.ID == "" || imageRef.MediaType != "image/png" || imageRef.SizeBytes != len(frame.PNG) || imageRef.ContentHash != hex.EncodeToString(sum[:]) || provenanceRef.ID == "" || provenanceRef.MediaType != "application/json" || permit.Owner != owner || permit.BundleID != in.Surface.BundleID || permit.PID != int(in.PID) || permit.ProcessStartToken != in.Surface.ProcessStartToken || permit.WindowID != in.WindowID || permit.ID == "" || permit.ContentHash != imageRef.ContentHash || len(frame.PNG) == 0 || len(frame.PNG) > native.MaximumWindowFrameBytes || !time.Now().Before(permit.ExpiresAt) {
			return failure(errors.New("capture permit and encrypted publication evidence mismatch"))
		}
		out := WindowFrameCaptureResult{Purpose: in.Purpose, CaptureRef: permit.ID, Artifact: imageRef, Provenance: provenanceRef, Metadata: permit, ImageReturned: true}
		result, rpcErr := result(out)
		if rpcErr == nil {
			result.Content = append(result.Content, schema.ImageContent{Type: "image", MimeType: "image/png", Data: base64.StdEncoding.EncodeToString(frame.PNG)})
		}
		return result, rpcErr
	})
}
