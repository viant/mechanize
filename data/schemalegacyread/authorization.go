package schemalegacyread

import (
	"context"
	"github.com/viant/mechanize/data/schemaauthority"
)

func (in *SchemaLegacyReadInput) Init(ctx context.Context) error {
	_, e := schemaauthority.Require(ctx, in.Namespace)
	return e
}
