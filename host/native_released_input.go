package host

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

// No key codes, characters, clipboard or field contents cross this channel.
// The separately signed observation helper has no input-posting lease.
func (h *Host) proveReleasedNativeInput(ctx context.Context, p auth.Principal) error {
	if h.nativeClient == nil || !p.HasScope("desktop:control") {
		return ErrNativeControlCleanupUnknown
	}
	doctor, err := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "doctor", DeadlineRemainingMS: 1000})
	if err != nil || doctor.Error != nil || doctor.HelperEpoch == "" {
		return ErrNativeControlCleanupUnknown
	}
	reply, err := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "input.releasedState", HelperEpoch: doctor.HelperEpoch, DeadlineRemainingMS: 1000})
	if err != nil || reply.Error != nil || reply.HelperEpoch != doctor.HelperEpoch {
		return ErrNativeControlCleanupUnknown
	}
	var state struct {
		Released *bool `json:"released"`
	}
	decoder := json.NewDecoder(bytes.NewReader(reply.Result))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Released == nil || !*state.Released {
		return ErrNativeControlCleanupUnknown
	}
	return nil
}
