package applicationpolicywrite

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// PolicyRecordLifecycle customizes role Input.Applicationpolicywrite.
type PolicyRecordLifecycle struct{}

func PolicyRecordLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*PolicyRecordLifecycle)(nil)).Elem()
}

var (
	PolicyRecordLifecycleHooks = new(PolicyRecordLifecycle)
	PolicyRecordLifecycleDatly = PolicyRecordLifecycleDatlyType()
)

func (hooks *PolicyRecordLifecycle) Init(ctx context.Context, entity *PolicyRecord, state xhandler.LifecycleContext[PolicyRecord, xhandler.NoParent, WriteApplicationPolicyOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("policy namespace required")
	}
	a, err := data.RequireApplicationPolicyAuthority(ctx, *entity.Namespace)
	if err != nil {
		return err
	}
	if state.Previous == nil {
		if a.ExpectedRevision != 0 {
			return fmt.Errorf("application policy CAS conflict")
		}
	} else {
		old := state.Previous
		if old.Revision == nil || *old.Revision != a.ExpectedRevision || old.CreatedAt == nil || *old.CreatedAt != a.CreatedAt || old.Namespace == nil || *old.Namespace != a.Namespace || old.Id == nil || *old.Id != data.ApplicationPolicyID {
			return fmt.Errorf("application policy CAS or immutable identity conflict")
		}
	}
	next := a.ExpectedRevision + 1
	entity.SetRevision(&next)
	return nil
}
func (hooks *PolicyRecordLifecycle) Validate(ctx context.Context, entity *PolicyRecord, state xhandler.LifecycleContext[PolicyRecord, xhandler.NoParent, WriteApplicationPolicyOutput]) error {
	if entity.Namespace == nil || entity.Id == nil || entity.PolicyJson == nil || entity.Revision == nil || entity.CreatedAt == nil || entity.UpdatedAt == nil {
		return fmt.Errorf("complete application policy record required")
	}
	a, err := data.RequireApplicationPolicyAuthority(ctx, *entity.Namespace)
	if err != nil {
		return err
	}
	if *entity.Id != data.ApplicationPolicyID || *entity.PolicyJson != a.PolicyJSON || *entity.Revision != a.ExpectedRevision+1 || *entity.CreatedAt != a.CreatedAt || *entity.UpdatedAt != a.UpdatedAt {
		return fmt.Errorf("application policy write proof mismatch")
	}
	return nil
}
func (hooks *PolicyRecordLifecycle) AfterSequence(ctx context.Context, entity *PolicyRecord, state xhandler.LifecycleContext[PolicyRecord, xhandler.NoParent, WriteApplicationPolicyOutput]) error {
	return nil
}
func (hooks *PolicyRecordLifecycle) AfterQueue(ctx context.Context, entity *PolicyRecord, state xhandler.LifecycleContext[PolicyRecord, xhandler.NoParent, WriteApplicationPolicyOutput]) error {
	return nil
}
func (hooks *PolicyRecordLifecycle) Finalize(ctx context.Context, input *WriteApplicationPolicyInput, output *WriteApplicationPolicyOutput, outcome xhandler.Outcome) error {
	return nil
}
