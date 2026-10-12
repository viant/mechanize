package authority

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

type key struct{}

func With(ctx context.Context, namespace string) (context.Context, error) {
	if _, e := data.RequireScope(ctx, namespace); e != nil {
		return nil, e
	}
	return context.WithValue(ctx, key{}, namespace), nil
}
func Require(ctx context.Context, namespace string) error {
	if value, ok := ctx.Value(key{}).(string); !ok || value != namespace {
		return errors.New("private Datly fixture authority required")
	}
	_, e := data.RequireScope(ctx, namespace)
	return e
}
