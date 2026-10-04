package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"os"
)

func (h *Host) configureChromeRetirement(c Config) error {
	if c.ChromeRetirement == nil {
		return nil
	}
	if c.Chrome == nil || c.Chrome.ProcessTrust == nil || h.chrome == nil {
		return errors.New("Chrome retirement runtime unavailable")
	}
	path, err := os.Executable()
	if err != nil {
		return err
	}
	if err = nativepeer.VerifyExecutable(path, nativepeer.Options{ExpectedUID: c.Chrome.ProcessTrust.ExpectedUID, DesignatedRequirement: c.ChromeRetirement.BrokerRequirement}); err != nil {
		return errors.New("retirement broker code requirement is not verified")
	}
	h.chromeRetirementEvidence, err = newChromeRetirementEvidenceProvider(c.ChromeRetirement.BrokerRequirement, chromeRetirementEvidencePrimitives{})
	return err
}

// PrepareChromeRetirement is trusted lifecycle infrastructure, not a generic MCP
// dispatch route. Successful preparation keeps the channel input-inhibited.
// Recording retention must be enrolled before a recorded channel can prepare.
func (h *Host) PrepareChromeRetirement(ctx context.Context, requestID, profile, browser string) (string, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || h == nil || !p.HasScope("desktop:control") {
		return "", auth.ErrUnauthorized
	}
	if h.chromeRetirementEvidence == nil {
		return "", errors.New("Chrome retirement evidence is not enrolled")
	}
	return prepareChromeRetirement(ctx, p, requestID, profile, browser, h.durable, h.chrome, h.chromeRetirementEvidence, nil)
}
