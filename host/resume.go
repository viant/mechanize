package host

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
)

func (h *Host) ResumeRun(ctx context.Context, p auth.Principal, sessionID, runID string, revision int, planID, objectiveID string) (*automation.ResumeResult, error) {
	if _, err := h.authorize(ctx, p); err != nil {
		return nil, err
	}
	if h.Runtime == nil {
		return nil, errors.New("Endly resume runtime is unavailable")
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.GrantID == "" || binding.Purpose == "" || binding.SessionID != sessionID {
		return nil, errors.New("resume requires consent bound to the owned session")
	}
	// The generated durable loader admits only known effects and a held fence;
	// each actual backend action independently consumes its exact scoped grant.
	return h.Runtime.ResumeInSession(ctx, p, sessionID, runID, revision, planID, objectiveID)
}
