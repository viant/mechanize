package credentialdeliveryfinish

import (
	context "context"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// DeliveryLifecycle customizes role Input.CredentialDeliveryFinish.
type DeliveryLifecycle struct{}

func DeliveryLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*DeliveryLifecycle)(nil)).Elem()
}

var (
	DeliveryLifecycleHooks = new(DeliveryLifecycle)
	DeliveryLifecycleDatly = DeliveryLifecycleDatlyType()
)

func (hooks *DeliveryLifecycle) Init(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryFinishOutput]) error {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil || a.Before == nil || state.Previous == nil || entity.Revision == nil || *entity.Revision != a.Before.Revision {
		return data.ErrCredentialDeliveryAuthority
	}
	next := a.Record.Revision
	entity.SetRevision(&next)
	return nil
}
func (hooks *DeliveryLifecycle) Validate(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryFinishOutput]) error {
	return data.ValidateCredentialDeliveryRow(ctx, entity, state.Previous, true)
}
func (hooks *DeliveryLifecycle) AfterSequence(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryFinishOutput]) error {
	return nil
}
func (hooks *DeliveryLifecycle) AfterQueue(ctx context.Context, entity *Delivery, state xhandler.LifecycleContext[Delivery, xhandler.NoParent, CredentialDeliveryFinishOutput]) error {
	return nil
}
func (hooks *DeliveryLifecycle) Finalize(ctx context.Context, input *CredentialDeliveryFinishInput, output *CredentialDeliveryFinishOutput, outcome xhandler.Outcome) error {
	return nil
}

// AuditLifecycle customizes role Input.CredentialDeliveryFinish.Audit.
type AuditLifecycle struct{}

func AuditLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*AuditLifecycle)(nil)).Elem()
}

var (
	AuditLifecycleHooks = new(AuditLifecycle)
	AuditLifecycleDatly = AuditLifecycleDatlyType()
)

func (hooks *AuditLifecycle) Init(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryFinishOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) Validate(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryFinishOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) AfterSequence(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryFinishOutput]) error {
	return nil
}
func (hooks *AuditLifecycle) AfterQueue(ctx context.Context, entity *Audit, state xhandler.LifecycleContext[Audit, Delivery, CredentialDeliveryFinishOutput]) error {
	return nil
}
