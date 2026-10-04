package getartifact

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (input *GetArtifactInput) Init(ctx context.Context) error {
	_, err := data.RequireScope(ctx, input.Namespace)
	return err
}
