package commitoutcome

import (
	"context"
	"github.com/viant/mechanize/data"
)

// Init validates explicit bound identity against the trusted host scope.
func (input *CommitOutcomeInput) Init(ctx context.Context) error {
	_, err := data.RequireScope(ctx, input.Namespace)
	return err
}
