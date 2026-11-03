package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/script"
)

// webReadPolicy is used only after execute has excluded all mutations. It keeps
// current enrollment and signed web-read qualification, without probing unrelated
// native helpers or admitting a control capability. Per-operation consent and
// the actual read's transport/privacy gates remain independent checks.
func (h *Host) webReadPolicy(ctx context.Context, p auth.Principal) (script.Policy, error) {
	policy, err := h.ObservationPolicy(ctx, p)
	if err != nil {
		return script.Policy{}, err
	}
	policy.AllowAllNative = false
	policy.AllowMutation = false
	policy.Capabilities = map[string]bool{}
	if h.chrome == nil {
		return policy, nil
	}
	capabilities, err := h.chrome.ReadCapabilitiesFor(ctx, p)
	if err != nil {
		return script.Policy{}, err
	}
	for _, capability := range capabilities {
		if capability.Supported {
			policy.Capabilities[capability.Surface+":"+capability.Name] = true
		}
	}
	return policy, ctx.Err()
}
