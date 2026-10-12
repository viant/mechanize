package schemasnapshot

import (
	"context"
	"github.com/viant/mechanize/data/schemaauthority"
)

func (in *SchemaSnapshotInput) Init(ctx context.Context) error {
	_, e := schemaauthority.Require(ctx, in.Namespace)
	return e
}
