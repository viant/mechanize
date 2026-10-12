package host

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/darwin"
	"io"
	"strings"
)

type privateNativeAdministration struct {
	helper            *darwin.PrivateAdministration
	chromeRequirement string
	extensions        map[string]bool
}

func configuredPrivateNative(c Config) (*privateNativeAdministration, error) {
	if c.NativeVault == nil || c.NativeVault.WindowProtection != "helper-v1" {
		return nil, nil
	}
	if c.NativeLaunch == nil {
		return nil, darwin.ErrPrivateProof
	}
	helper, e := darwin.NewPrivateAdministration(darwin.Options{Console: c.consoleHelperLaunch(), HelperPath: c.NativeHelper, Requirement: c.NativeLaunch.HelperRequirement, ExpectedUID: c.NativeLaunch.ExpectedUID})
	if e != nil {
		return nil, e
	}
	result := &privateNativeAdministration{helper: helper, extensions: map[string]bool{}}
	if c.Chrome != nil && c.Chrome.ProcessTrust != nil && !c.Chrome.FixtureEnrollment {
		result.chromeRequirement = c.Chrome.ProcessTrust.ChromeRequirement
		for _, g := range c.Chrome.Grants {
			origin := g.ExtensionOrigin
			if strings.HasPrefix(origin, "chrome-extension://") && strings.HasSuffix(origin, "/") {
				result.extensions[strings.TrimSuffix(strings.TrimPrefix(origin, "chrome-extension://"), "/")] = true
			}
		}
	}
	return result, nil
}
func (h *Host) nativeManagementProof(ctx context.Context, raw json.RawMessage) (any, error) {
	p, e := auth.FromContext(ctx)
	if e != nil || !auth.NativeHuman(ctx) || !p.HasScope("consent:admin") || h.privateNative == nil || h.vaultExposure == nil {
		return nil, auth.ErrUnauthorized
	}
	var input struct {
		SessionID string `json:"sessionID"`
		darwin.PrivateManagementRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || !h.privateNative.extensions[input.ExtensionID] {
		return nil, darwin.ErrPrivateProof
	}
	// No setup callback or caller assertion can override the privacy barrier.
	release, e := h.vaultExposure.AcquireExposureContext(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	return h.privateNative.helper.ManagementProof(ctx, h.privateNative.chromeRequirement, input.PrivateManagementRequest)
}
