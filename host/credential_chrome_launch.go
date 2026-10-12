package host

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
)

// Launching the fixed browser without arguments reads no page or credential
// values. This exception is action-specific; it grants no ordinary exposure.
func privateChromeOpen(step model.Step) bool {
	return step.Action == "app.open" && step.Target.Surface == (model.Surface{Kind: "native", BundleID: "com.google.Chrome"}) && len(step.Arguments) == 0 && step.Validate() == nil
}

func chromeLaunchSourceBirths(p auth.Principal, scopes []durable.CredentialProtection) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > 512 {
		return nil, vault.ErrDeliveryProtected
	}
	unique := map[string]bool{}
	for _, snapshot := range scopes {
		sources, e := protectionAbsenceSources(p, snapshot)
		if e != nil {
			return nil, vault.ErrDeliveryProtected
		}
		for _, source := range sources {
			if source.ChromeStartToken == "" {
				return nil, vault.ErrDeliveryProtected
			}
			unique[source.ChromeStartToken] = true
		}
	}
	result := make([]string, 0, len(unique))
	for birth := range unique {
		result = append(result, birth)
	}
	sort.Strings(result)
	return result, nil
}

func (h *Host) authorizeChromeOpenAfterSourceAbsence(ctx context.Context, p auth.Principal, step model.Step) (*consent.Lease, error) {
	if h.durable == nil || h.vaultExposure == nil || !privateChromeOpen(step) {
		return nil, vault.ErrDeliveryProtected
	}
	// Preserve the volatile native-entry/delivery gate and its independent native
	// window check. The new reader reservation also prevents concurrent entry.
	var release func()
	if h.vaultExposure != nil {
		var e error
		release, e = h.vaultExposure.AcquireExposureContext(ctx)
		if e != nil {
			return nil, e
		}
	}
	retained := false
	defer func() {
		if !retained && release != nil {
			release()
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	scopes, e := h.durable.CredentialProtectionRecoverySnapshot(bounded, p)
	if e != nil {
		return nil, e
	}
	births, e := chromeLaunchSourceBirths(p, scopes)
	if e != nil {
		return nil, e
	}
	for _, birth := range births {
		if session.VerifyProcessBirthAbsent(bounded, uint32(os.Getuid()), birth) != nil {
			return nil, vault.ErrDeliveryProtected
		}
	}
	if e = bounded.Err(); e != nil {
		return nil, e
	}
	lease, e := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
	if e != nil {
		return nil, e
	}
	if release != nil {
		previous := lease.Release
		lease.Release = func() { defer release(); previous() }
		retained = true
	}
	return lease, nil
}
