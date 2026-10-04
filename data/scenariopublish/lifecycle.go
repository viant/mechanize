package scenariopublish

import (
	context "context"
	"errors"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// ScenarioRevisionLifecycle customizes role Input.PublishScenarioDraft.
type ScenarioRevisionLifecycle struct{}

func ScenarioRevisionLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*ScenarioRevisionLifecycle)(nil)).Elem()
}

var (
	ScenarioRevisionLifecycleHooks = new(ScenarioRevisionLifecycle)
	ScenarioRevisionLifecycleDatly = ScenarioRevisionLifecycleDatlyType()
)

func (hooks *ScenarioRevisionLifecycle) Init(ctx context.Context, entity *ScenarioRevision, state xhandler.LifecycleContext[ScenarioRevision, xhandler.NoParent, PublishScenarioDraftOutput]) error {
	return nil
}
func (hooks *ScenarioRevisionLifecycle) Validate(ctx context.Context, entity *ScenarioRevision, state xhandler.LifecycleContext[ScenarioRevision, xhandler.NoParent, PublishScenarioDraftOutput]) error {
	if entity.Namespace == nil || entity.ScenarioId == nil || entity.Revision == nil || entity.ContentHash == nil || entity.ObjectiveHash == nil || entity.ContentJson == nil || entity.PublicationState == nil || entity.CreatedAt == nil || *entity.PublicationState != "draft" {
		return errors.New("complete immutable scenario draft required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	def, err := DecodeCanonical(*entity.ContentJson)
	if err != nil {
		return err
	}
	objectiveHash, err := ObjectiveHash(def.Plan)
	if err != nil {
		return err
	}
	if def.ID != *entity.ScenarioId || def.Revision != *entity.Revision || Digest([]byte(*entity.ContentJson)) != *entity.ContentHash || objectiveHash != *entity.ObjectiveHash {
		return errors.New("scenario canonical identity/hash mismatch")
	}
	return nil
}

func (hooks *ScenarioRevisionLifecycle) AfterSequence(ctx context.Context, entity *ScenarioRevision, state xhandler.LifecycleContext[ScenarioRevision, xhandler.NoParent, PublishScenarioDraftOutput]) error {
	return nil
}
func (hooks *ScenarioRevisionLifecycle) AfterQueue(ctx context.Context, entity *ScenarioRevision, state xhandler.LifecycleContext[ScenarioRevision, xhandler.NoParent, PublishScenarioDraftOutput]) error {
	return nil
}
func (hooks *ScenarioRevisionLifecycle) Finalize(ctx context.Context, input *PublishScenarioDraftInput, output *PublishScenarioDraftOutput, outcome xhandler.Outcome) error {
	return nil
}
