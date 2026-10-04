package durable

import (
	"context"
	"errors"
	"reflect"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func (b *Builder) prepareStepAuthority(ctx context.Context, p auth.Principal, step model.Step) (context.Context, int, error) {
	if b.options.PrepareStepAuthority == nil {
		epoch, err := b.options.LeaseEpoch(ctx, p)
		return ctx, epoch, err
	}
	prepared, epoch, err := b.options.PrepareStepAuthority(ctx, p, step)
	if err != nil {
		return nil, 0, err
	}
	if prepared == nil {
		return nil, 0, errors.New("executor authority context missing")
	}
	actual, err := auth.FromContext(prepared)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return nil, 0, auth.ErrUnauthorized
	}
	before, beforeOK := integration.ExecutionFromContext(ctx)
	after, afterOK := integration.ExecutionFromContext(prepared)
	oldBinding, oldOK := auth.ConsentBindingFromContext(ctx)
	newBinding, newOK := auth.ConsentBindingFromContext(prepared)
	if beforeOK != afterOK || !reflect.DeepEqual(before, after) || oldOK != newOK || oldBinding != newBinding {
		return nil, 0, errors.New("executor authority changed execution or consent binding")
	}
	if err := prepared.Err(); err != nil {
		return nil, 0, err
	}
	return prepared, epoch, nil
}
