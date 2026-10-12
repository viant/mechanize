package credentialpreparationreserve

import (
	context "context"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// PreparationLifecycle customizes role Input.CredentialPreparationReserve.
type PreparationLifecycle struct{}

func PreparationLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*PreparationLifecycle)(nil)).Elem()
}

var (
	PreparationLifecycleHooks = new(PreparationLifecycle)
	PreparationLifecycleDatly = PreparationLifecycleDatlyType()
)

func (hooks *PreparationLifecycle) Init(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationReserveOutput]) error {
	if state.Previous != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
func (hooks *PreparationLifecycle) Validate(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationReserveOutput]) error {
	return data.ValidateCredentialPreparationRow(ctx, entity)
}
func (hooks *PreparationLifecycle) AfterSequence(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationReserveOutput]) error {
	return nil
}
func (hooks *PreparationLifecycle) AfterQueue(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationReserveOutput]) error {
	return nil
}
func (hooks *PreparationLifecycle) Finalize(ctx context.Context, input *CredentialPreparationReserveInput, output *CredentialPreparationReserveOutput, outcome xhandler.Outcome) error {
	return nil
}
