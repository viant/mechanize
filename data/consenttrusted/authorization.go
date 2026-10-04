package consenttrusted

import (
	"context"

	"github.com/viant/mechanize/data"
)

func (input *ListTrustedInput) Init(ctx context.Context) error {
	if _, err := data.RequireScope(ctx, input.Namespace); err != nil {
		return err
	}
	return data.RequireConsentClientRead(ctx, input.ClientID)
}
