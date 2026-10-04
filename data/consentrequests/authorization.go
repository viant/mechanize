package consentrequests

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (input *ListRequestsInput) Init(ctx context.Context) error {
	if _, err := data.RequireScope(ctx, input.Namespace); err != nil {
		return err
	}
	return data.RequireConsentAuthority(ctx, "read")
}
