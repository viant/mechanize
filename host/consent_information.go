package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
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
	if h.nativeClient != nil {
		reply, e := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "doctor", DeadlineRemainingMS: 3000})
		if e == nil && reply.Error == nil {
			var data struct {
				AXTrusted      bool `json:"axTrusted"`
				CaptureGranted bool `json:"captureGranted"`
				ListenGranted  bool `json:"listenGranted"`
			}
			if json.Unmarshal(reply.Result, &data) == nil {
				values["accessibility"] = data.AXTrusted
				values["screenRecording"] = data.CaptureGranted
				values["inputMonitoring"] = data.ListenGranted
				available = true
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
		rows = append(rows, map[string]any{"helperBundleID": "unqualified-native-helper", "permission": permission, "state": state, "detail": "Reported by the automation helper, not the console. Stable signed helper identity remains a qualification gate."})
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
