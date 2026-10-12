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
	// An operator-installed preparation provider may select an existing
	// reusable human grant when the request omitted its ID. Authorization
	// still rechecks that grant before dispatch. It cannot replace an explicit
	// grant or change client/session/purpose/execution identity.
	selectedGrant := oldOK && newOK && oldBinding.GrantID == "" && newBinding.GrantID != "" &&
		oldBinding.SessionID != "" && oldBinding.Purpose != "" && oldBinding.SessionID == newBinding.SessionID && oldBinding.Purpose == newBinding.Purpose
	if beforeOK != afterOK || !reflect.DeepEqual(before, after) || oldOK != newOK || oldBinding != newBinding && !selectedGrant {
		return nil, 0, errors.New("executor authority changed execution or consent binding")
	}
	if err := prepared.Err(); err != nil {
		return nil, 0, err
	}
	return prepared, epoch, nil
}
