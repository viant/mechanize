package auditcounts

import (
	"context"
	"github.com/viant/mechanize/internal/datlytest/authority"
)

func (in *AuditCountsInput) Init(ctx context.Context) error {
	return authority.Require(ctx, in.Namespace)
}
