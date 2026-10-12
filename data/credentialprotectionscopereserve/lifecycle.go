package credentialprotectionscopereserve

import (
	context "context"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// ProtectionScopeLifecycle customizes role Input.CredentialProtectionScopeReserve.
type ProtectionScopeLifecycle struct{}

func ProtectionScopeLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*ProtectionScopeLifecycle)(nil)).Elem()
}

var (
	ProtectionScopeLifecycleHooks = new(ProtectionScopeLifecycle)
	ProtectionScopeLifecycleDatly = ProtectionScopeLifecycleDatlyType()
)

func (hooks *ProtectionScopeLifecycle) Init(ctx context.Context, entity *ProtectionScope, state xhandler.LifecycleContext[ProtectionScope, xhandler.NoParent, CredentialProtectionScopeReserveOutput]) error {
	if state.Previous != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
func (hooks *ProtectionScopeLifecycle) Validate(ctx context.Context, entity *ProtectionScope, state xhandler.LifecycleContext[ProtectionScope, xhandler.NoParent, CredentialProtectionScopeReserveOutput]) error {
	return data.ValidateCredentialProtectionScopeRow(ctx, entity)
}
func (hooks *ProtectionScopeLifecycle) AfterSequence(ctx context.Context, entity *ProtectionScope, state xhandler.LifecycleContext[ProtectionScope, xhandler.NoParent, CredentialProtectionScopeReserveOutput]) error {
	return nil
}
func (hooks *ProtectionScopeLifecycle) AfterQueue(ctx context.Context, entity *ProtectionScope, state xhandler.LifecycleContext[ProtectionScope, xhandler.NoParent, CredentialProtectionScopeReserveOutput]) error {
	return nil
}
func (hooks *ProtectionScopeLifecycle) Finalize(ctx context.Context, input *CredentialProtectionScopeReserveInput, output *CredentialProtectionScopeReserveOutput, outcome xhandler.Outcome) error {
	return nil
}
