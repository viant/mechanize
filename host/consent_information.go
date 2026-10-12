package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"io"
)

func (h *Host) NativeInformation(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || !auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	user, err := h.enrolled(ctx, p)
	if err != nil {
		return nil, err
	}
	if method == "credential.pending" || method == "credential.bind" || method == "credential.cancel" {
		if h.credentials == nil {
			return nil, errPrivateCredential
		}
		return h.credentials.native(ctx, method, raw)
	}
	if method == "browserControllers" {
		return h.nativeBrowserControllers(ctx, p, raw)
	}
	if method == "migration.managementProof" {
		return h.nativeManagementProof(ctx, raw)
	}
	if method == "browserSetupMetadata" {
		return h.nativeBrowserSetupMetadata(ctx, p, raw)
	}
	if method == "browserStatus" {
		return h.BrowserStatus(ctx, p)
	}
	if method == "settings.get" {
		return h.runtimeSettings()
	}
	if method == "settings.port.set" {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var input struct {
			SessionID        string `json:"sessionID"`
			ExpectedRevision *int   `json:"expectedRevision"`
			Port             *int   `json:"port"`
		}
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.ExpectedRevision == nil || input.Port == nil {
			return nil, errRuntimeSettings
		}
		return h.saveRuntimePort(*input.ExpectedRevision, *input.Port)
	}
	if method == "applicationAccess.get" || method == "applicationAccess.set" {
		if h.applicationAccess == nil {
			return nil, errors.New("application policy unavailable")
		}
		if method == "applicationAccess.get" {
			return h.applicationAccess.snapshot(ctx, p)
		}
		var input struct {
			ExpectedRevision *int                    `json:"expectedRevision"`
			Policy           *data.ApplicationPolicy `json:"policy"`
		}
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		if input.ExpectedRevision == nil || input.Policy == nil {
			return nil, errors.New("expectedRevision and policy required")
		}
		return h.applicationAccess.update(ctx, p, *input.ExpectedRevision, *input.Policy)
	}
	if method == "inventory" {
		rows := []map[string]any{}
		for _, bundle := range user.NativeBundles {
			rows = append(rows, map[string]any{"id": bundle, "scope": map[string]any{"kind": "application", "bundleID": bundle, "displayName": bundle}})
		}
		if user.DesktopAccess && h.chromeAllWebsites[p.Namespace] {
			rows = append(rows, map[string]any{"id": "chrome-all-websites", "scope": map[string]any{"kind": "browser", "bundleID": "com.google.Chrome", "displayName": "Google Chrome — all HTTP and HTTPS websites"}})
		}
		for _, origin := range user.WebOrigins {
			rows = append(rows, map[string]any{"id": origin, "scope": map[string]any{"kind": "origin", "origin": origin, "displayName": origin}})
		}
		return rows, nil
	}
	if method != "helperPermissionDoctor" {
		return nil, errors.New("unknown native info method")
	}
	values := map[string]bool{}
	available := false
	detail := "observationHelperUnavailable: The observation helper is unavailable. Restart Mechanize to reconnect it."
	if h.nativeClient != nil {
		reply, e := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "doctor", DeadlineRemainingMS: 3000})
		if e != nil {
			detail = helperDoctorFailureDetail(e)
		} else if reply.Error != nil {
			detail = helperDoctorFailureDetail(reply.Error)
		} else {
			var data struct {
				AXTrusted      *bool `json:"axTrusted"`
				CaptureGranted *bool `json:"captureGranted"`
				ListenGranted  *bool `json:"listenGranted"`
			}
			if json.Unmarshal(reply.Result, &data) == nil && data.AXTrusted != nil && data.CaptureGranted != nil && data.ListenGranted != nil && ctx.Err() == nil {
				values["accessibility"] = *data.AXTrusted
				values["screenRecording"] = *data.CaptureGranted
				values["inputMonitoring"] = *data.ListenGranted
				available = true
				detail = "Reported by the automation runtime. macOS permission and tool access are checked separately."
			} else {
				detail = "observationHelperReplyInvalid: Permission status could not be verified. Refresh or restart Mechanize."
			}
		}
	}
	rows := []map[string]any{}
	for _, permission := range []string{"accessibility", "screenRecording", "inputMonitoring"} {
		state := "unknown"
		if available {
			state = "denied"
			if values[permission] {
				state = "granted"
			}
		}
		rows = append(rows, map[string]any{"helperBundleID": "unqualified-native-helper", "permission": permission, "state": state, "detail": detail})
	}
	return rows, nil
}

func newInfoID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "doctor-entropy-unavailable"
	}
	return hex.EncodeToString(value[:])
}

// Only fixed classifications reach the panel. Never interpolate helper errors,
// process identities, paths, credentials, or provider messages into diagnostics.
func helperDoctorFailureDetail(err error) string {
	if helperDoctorCleanupFailure(err, 0) {
		return "observationHelperCleanupUnconfirmed: The previous observation helper could not be safely closed. Restart Mechanize to reconnect it."
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "observationHelperCheckInterrupted: The permission check was interrupted. Refresh to check again."
	}
	return "observationHelperUnavailable: The observation helper is unavailable. Restart Mechanize to reconnect it."
}
func helperDoctorCleanupFailure(err error, depth int) bool {
	if err == nil || depth >= 8 {
		return false
	}
	// Existing Client.Close emits these fixed errors without a typed wrapper.
	// Recognize exact leaves only; arbitrary provider text is never a code.
	switch err.Error() {
	case "console helper teardown unconfirmed", "helper teardown exceeded one second":
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if helperDoctorCleanupFailure(child, depth+1) {
				return true
			}
		}
	} else if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return helperDoctorCleanupFailure(wrapped.Unwrap(), depth+1)
	}
	return false
}
