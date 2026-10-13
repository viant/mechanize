package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/viant/mcp-protocol/schema"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
)

// Canonical screenshots retain MaximumInlineCaptureBytes and use the existing
// negotiated chunk transport. One-use frame previews keep their smaller budget.
const controllerFramePreviewBytes = 96 * 1024

// Frame coordinates retain their original pixel space. The preview only renders
// evidence; clients map preview pixels to Metadata.Width/Height before a click.
type controllerFrameCapture struct {
	WindowFrameCaptureResult
	ImageIsPreview bool            `json:"imageIsPreview"`
	Preview        *CapturePreview `json:"preview,omitempty"`
}

func controllerImage(answer *schema.CallToolResult) (*schema.ImageContent, error) {
	var found *schema.ImageContent
	for _, content := range answer.Content {
		var item schema.ImageContent
		switch value := content.(type) {
		case map[string]any:
			kind, _ := value["type"].(string)
			if kind != "image" {
				continue
			}
			encoded, err := json.Marshal(value)
			if err != nil || json.Unmarshal(encoded, &item) != nil {
				return nil, errors.New("invalid capture image")
			}
		case schema.ImageContent:
			item = value
		case *schema.ImageContent:
			if value == nil {
				return nil, errors.New("invalid capture image")
			}
			item = *value
		default:
			continue
		}
		if found != nil || item.Type != "image" || item.MimeType != "image/png" && item.MimeType != "image/jpeg" {
			return nil, errors.New("invalid capture image")
		}
		found = &item
	}
	return found, nil
}

func projectControllerCapture(ctx context.Context, name string, encoded []byte, answer *schema.CallToolResult) (*schema.CallToolResult, error) {
	image, err := controllerImage(answer)
	if err != nil {
		return controllerRejected("unknown"), nil
	}
	if name == "mechanize_capture" {
		var capture CaptureResult
		if json.Unmarshal(encoded, &capture) != nil {
			return controllerRejected("unknown"), nil
		}
		capture.InlineByteLimit = MaximumInlineCaptureBytes
		capture.ImageReturned = false
		var inline *schema.ImageContent
		if image != nil && len(image.Data) <= base64.StdEncoding.EncodedLen(MaximumInlineCaptureBytes) {
			bytes, e := base64.StdEncoding.Strict().DecodeString(image.Data)
			if e != nil || len(bytes) > MaximumInlineCaptureBytes {
				return controllerRejected("unknown"), nil
			}
			capture.ImageReturned = true
			inline = &schema.ImageContent{Type: "image", MimeType: image.MimeType, Data: image.Data}
		} else if image != nil {
			capture.Reason = "Image exceeds canonical inline capture budget; full evidence remains in the encrypted artifact"
		}
		out, rpc := result(capture)
		if rpc != nil {
			return nil, errors.New("controller capture unavailable")
		}
		if inline != nil {
			out.Content = append(out.Content, *inline)
		}
		return out, nil
	}
	var frame WindowFrameCaptureResult
	if json.Unmarshal(encoded, &frame) != nil || image == nil || image.MimeType != "image/png" || len(image.Data) > base64.StdEncoding.EncodedLen(native.MaximumWindowFrameBytes) {
		return controllerRejected("unknown"), nil
	}
	source, err := base64.StdEncoding.Strict().DecodeString(image.Data)
	if err != nil || len(source) > native.MaximumWindowFrameBytes || len(source) != frame.Artifact.SizeBytes {
		return controllerRejected("unknown"), nil
	}
	digest := sha256.Sum256(source)
	if hex.EncodeToString(digest[:]) != frame.Artifact.ContentHash || frame.Metadata.ContentHash != frame.Artifact.ContentHash {
		return controllerRejected("unknown"), nil
	}
	m := frame.Metadata
	preview, err := BuildCapturePreview(ctx, source, native.CaptureMetadata{Width: m.Width, Height: m.Height, Bytes: len(source), Bounds: m.Bounds, Scale: m.Scale, CoordinateSpace: "globalLogicalPoints"}, controllerFramePreviewBytes)
	if err != nil {
		return controllerRejected("unknown"), nil
	}
	frame.ImageReturned = preview.Available
	out, rpc := result(controllerFrameCapture{WindowFrameCaptureResult: frame, ImageIsPreview: true, Preview: &preview})
	if rpc != nil {
		return nil, errors.New("controller capture unavailable")
	}
	if preview.Available {
		out.Content = append(out.Content, schema.ImageContent{Type: "image", MimeType: preview.MimeType, Data: base64.StdEncoding.EncodeToString(preview.Image)})
	}
	return out, nil
}

// projectControllerCaptureFailure reuses the canonical capture failure messages.
// Only finite codes, a closed dispatch state and a typed cleanup acknowledgement
// cross the browser boundary; upstream text and arbitrary metadata never do.
func projectControllerCaptureFailure(structured map[string]any) *schema.CallToolResult {
	code, _ := structured["code"].(string)
	if code == "artifactPublicationUnconfirmed" {
		encoded, err := json.Marshal(structured["artifact"])
		var ref data.ArtifactReference
		if err != nil || json.Unmarshal(encoded, &ref) != nil || !controllerCaptureArtifactReference(ref) {
			out, _ := captureFailure(&native.CaptureError{DispatchState: "unknown"}, data.ArtifactReference{})
			return out
		}
		phase, _ := structured["publicationPhase"].(string)
		cause, _ := structured["publicationCause"].(string)
		out, _ := captureFailure(&controllerCapturePublication{ref: ref, phase: phase, cause: cause}, ref)
		return out
	}
	dispatch, _ := structured["dispatchState"].(string)
	if dispatch != "notDispatched" && dispatch != "dispatched" {
		dispatch = "unknown"
	}
	cleanup, hasCleanup := structured["cleanupConfirmed"].(bool)
	if !hasCleanup && (code == "permissionDenied" || code == "invalidScope") {
		return controllerRejected(dispatch, code)
	}
	if code == "staleFramePermit" || code == "windowFrameUnconfirmed" || code == "captureEvidenceMismatch" {
		message := "The window frame permit is stale; capture the exact current window again before input"
		if code == "captureEvidenceMismatch" {
			message = "Capture evidence did not match the exact requested window; refresh scoped discovery before another capture"
		}
		if code == "windowFrameUnconfirmed" {
			message = "Window frame input receipt is unconfirmed; reconcile its outcome before replay"
		}
		body := map[string]any{"code": code, "message": message, "dispatchState": dispatch}
		if hasCleanup {
			body["cleanupConfirmed"] = cleanup
		}
		out, _ := result(body)
		yes := true
		out.IsError = &yes
		return out
	}
	var cause error = errors.New("capture unavailable")
	switch code {
	case "captureFailed", "permissionDenied", "targetNotFound", "staleReference", "staleEpoch", "captureTooLarge", "captureOffDisplay", "captureAmbiguousDisplay", "captureUnqualified", "invalidScope":
		cause = &native.NativeError{Code: code}
	default:
		if !hasCleanup {
			rejected := controllerRejected(dispatch, code)
			if rejected.StructuredContent.(map[string]any)["code"] != "controllerToolRejected" {
				return rejected
			}
		}
	}
	out, _ := captureFailure(&native.CaptureError{Cause: cause, DispatchState: dispatch, CleanupConfirmed: cleanup}, data.ArtifactReference{})
	if !hasCleanup {
		body := out.StructuredContent.(map[string]any)
		delete(body, "cleanupConfirmed")
		out, _ = result(body)
		yes := true
		out.IsError = &yes
	}
	return out
}

// This projection carries an opaque encrypted-artifact reference, never input
// authority. Diagnostics are closed by captureFailure's existing contract.
type controllerCapturePublication struct {
	ref          data.ArtifactReference
	phase, cause string
}

func (e *controllerCapturePublication) Error() string { return "capture publication unconfirmed" }
func (e *controllerCapturePublication) RetainedArtifactReference() data.ArtifactReference {
	return e.ref
}
func (e *controllerCapturePublication) ArtifactPublicationDiagnostic() (string, string) {
	return e.phase, e.cause
}

func controllerCaptureArtifactReference(ref data.ArtifactReference) bool {
	if ref.ID == "" || len(ref.ID) > 256 || ref.SizeBytes <= 0 || ref.SizeBytes > native.MaximumCaptureBytes || ref.MediaType != "image/png" || len(ref.ContentHash) != 64 || len(ref.KeyReference) > 256 {
		return false
	}
	digest, err := hex.DecodeString(ref.ContentHash)
	if err != nil || len(digest) != sha256.Size {
		return false
	}
	for _, value := range []string{ref.ID, ref.KeyReference} {
		if value == ref.ID && strings.ContainsAny(value, "/\\") {
			return false
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return false
			}
		}
	}
	return true
}
