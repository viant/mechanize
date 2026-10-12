package credentialdeliveryreserve

import (
	context "context"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// DeliveryLifecycle customizes role Input.CredentialDeliveryReserve.
type DeliveryLifecycle struct{}

func DeliveryLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*DeliveryLifecycle)(nil)).Elem()
}

var (
	DeliveryLifecycleHooks = new(DeliveryLifecycle)
	DeliveryLifecycleDatly = DeliveryLifecycleDatlyType()
)

func (hooks *DeliveryLifecycle) Init(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryReserveOutput]) error {
	if state.Previous != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
func (hooks *DeliveryLifecycle) Validate(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryReserveOutput]) error {
	return data.ValidateCredentialDeliveryRow(ctx, entity, state.Previous, false)
}
func (hooks *DeliveryLifecycle) AfterSequence(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryReserveOutput]) error {
	return nil
}
func (hooks *DeliveryLifecycle) AfterQueue(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryReserveOutput]) error {
	return nil
}
func (hooks *DeliveryLifecycle) Finalize(ctx context.Context, input *CredentialDeliveryReserveInput, output *CredentialDeliveryReserveOutput, outcome xhandler.Outcome) error {
	return nil
}

// AuditLifecycle customizes role Input.CredentialDeliveryReserve.Audit.
type AuditLifecycle struct{}

func AuditLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*AuditLifecycle)(nil)).Elem()
}

var (
	AuditLifecycleHooks = new(AuditLifecycle)
	AuditLifecycleDatly = AuditLifecycleDatlyType()
)

func (hooks *AuditLifecycle) Init(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryReserveOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) Validate(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryReserveOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) AfterSequence(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryReserveOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) AfterQueue(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryReserveOutput]) error {
	return nil
}
