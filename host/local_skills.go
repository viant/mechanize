package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/skills"
)

func (h *Host) localSkills(ctx context.Context, p auth.Principal) ([]skills.LocalGuide, error) {
	user, err := h.enrolled(ctx, p)
	if err != nil {
		return nil, err
	}
	return skills.LoadLocal(ctx, user.SkillDirectories)
}
