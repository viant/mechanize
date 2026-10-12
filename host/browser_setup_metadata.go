package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

// Native console route only. Selectors choose an already-owned channel; they
// cannot supply a directory, storage digest, process identity or quiescence claim.
func (h *Host) nativeBrowserSetupMetadata(ctx context.Context, p auth.Principal, raw json.RawMessage) (chrome.BrowserSetupMetadataReceipt, error) {
	if !auth.NativeHuman(ctx) {
		return chrome.BrowserSetupMetadataReceipt{}, auth.ErrUnauthorized
	}
	if _, err := h.authorize(ctx, p); err != nil {
		return chrome.BrowserSetupMetadataReceipt{}, err
	}
	var input struct {
		ProfileChannel  string `json:"profileChannel"`
		BrowserInstance string `json:"browserInstance"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.ProfileChannel) == 0 || len(input.ProfileChannel) > 128 || len(input.BrowserInstance) == 0 || len(input.BrowserInstance) > 128 || h.chrome == nil {
		return chrome.BrowserSetupMetadataReceipt{}, errors.New("owned browser setup channel unavailable")
	}
	proof, err := h.chrome.SetupMetadata(ctx, p, input.ProfileChannel, input.BrowserInstance)
	if err != nil {
		return chrome.BrowserSetupMetadataReceipt{}, err
	}
	if err = h.chrome.VerifySetupMetadata(ctx, p, proof); err != nil {
		return chrome.BrowserSetupMetadataReceipt{}, err
	}
	return proof.Metadata(), nil
}
