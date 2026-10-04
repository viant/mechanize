package consentconsume

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	"reflect"
)

type AuditLifecycle struct{}

func AuditLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*AuditLifecycle)(nil)).Elem() }

var AuditLifecycleHooks = new(AuditLifecycle)
var AuditLifecycleDatly = AuditLifecycleDatlyType()

func (h *AuditLifecycle) Init(ctx context.Context, e *Audit, s xhandler.LifecycleContext[Audit, Record, ConsumeOnceOutput]) error {
	return nil
}
func (h *AuditLifecycle) Validate(ctx context.Context, e *Audit, s xhandler.LifecycleContext[Audit, Record, ConsumeOnceOutput]) error {
	if e.Namespace == nil || e.RequestId == nil || e.Id == nil || e.ActorId == nil || e.Kind == nil || e.CreatedAt == nil || e.PayloadJson == nil {
		return fmt.Errorf("audit fields required")
	}
	return data.ValidateConsentAudit(ctx, *e.Namespace, *e.RequestId, *e.Id, *e.ActorId, *e.Kind, *e.CreatedAt, *e.PayloadJson, s.Previous != nil)
}
func (h *AuditLifecycle) AfterSequence(ctx context.Context, e *Audit, s xhandler.LifecycleContext[Audit, Record, ConsumeOnceOutput]) error {
	return nil
}
func (h *AuditLifecycle) AfterQueue(ctx context.Context, e *Audit, s xhandler.LifecycleContext[Audit, Record, ConsumeOnceOutput]) error {
	return nil
}
func (h *AuditLifecycle) Finalize(ctx context.Context, input *ConsumeOnceInput, output *ConsumeOnceOutput, outcome xhandler.Outcome) error {
	return nil
}
