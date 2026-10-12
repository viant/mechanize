package credentialpreparationfinish

import (
	context "context"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// PreparationLifecycle customizes role Input.CredentialPreparationFinish.
type PreparationLifecycle struct{}

func PreparationLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*PreparationLifecycle)(nil)).Elem()
}

var (
	PreparationLifecycleHooks = new(PreparationLifecycle)
	PreparationLifecycleDatly = PreparationLifecycleDatlyType()
)

func (hooks *PreparationLifecycle) Init(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationFinishOutput]) error {
	r, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil || r.ProtectionState != "closed" || state.Previous == nil || entity.Revision == nil || *entity.Revision != r.Revision-1 {
		return data.ErrCredentialDeliveryAuthority
	}
	entity.SetRevision(&r.Revision)
	return nil
}
func (hooks *PreparationLifecycle) Validate(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationFinishOutput]) error {
	return data.ValidateCredentialPreparationClose(ctx, entity, state.Previous)
}
func (hooks *PreparationLifecycle) AfterSequence(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationFinishOutput]) error {
	return nil
}
func (hooks *PreparationLifecycle) AfterQueue(ctx context.Context, entity *Preparation, state xhandler.LifecycleContext[Preparation, xhandler.NoParent, CredentialPreparationFinishOutput]) error {
	return nil
}
func (hooks *PreparationLifecycle) Finalize(ctx context.Context, input *CredentialPreparationFinishInput, output *CredentialPreparationFinishOutput, outcome xhandler.Outcome) error {
	return nil
}
