package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"io"
)

// Controller administration is a closed native-console route. Transport sessionID
// and controllerSessionID are deliberately distinct; neither asserts human identity.
func (h *Host) nativeBrowserControllers(ctx context.Context, p auth.Principal, raw json.RawMessage) (chrome.ControllerState, error) {
	if !auth.NativeHuman(ctx) {
		return chrome.ControllerState{}, auth.ErrUnauthorized
	}
	if _, err := h.authorize(ctx, p); err != nil {
		return chrome.ControllerState{}, err
	}
	var in struct {
		SessionID           string                   `json:"sessionID"`
		ProfileChannel      string                   `json:"profileChannel"`
		BrowserInstance     string                   `json:"browserInstance"`
		Action              string                   `json:"action"`
		Policy              *chrome.ControllerPolicy `json:"policy,omitempty"`
		ControllerSessionID string                   `json:"controllerSessionID,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16384 || d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || len(in.ProfileChannel) == 0 || len(in.ProfileChannel) > 128 || len(in.BrowserInstance) == 0 || len(in.BrowserInstance) > 128 || len(in.ControllerSessionID) > 128 || h.chrome == nil {
		return chrome.ControllerState{}, errors.New("controller management unavailable")
	}
	return h.chrome.ManageControllers(ctx, p, chrome.ControllerManagement{ProfileChannel: in.ProfileChannel, BrowserInstance: in.BrowserInstance, Action: in.Action, Policy: in.Policy, SessionID: in.ControllerSessionID})
}
