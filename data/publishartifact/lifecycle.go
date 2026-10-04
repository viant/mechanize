package publishartifact

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// ArtifactLifecycle customizes role Input.PublishArtifact.
type ArtifactLifecycle struct{}

func ArtifactLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*ArtifactLifecycle)(nil)).Elem()
}

var (
	ArtifactLifecycleHooks = new(ArtifactLifecycle)
	ArtifactLifecycleDatly = ArtifactLifecycleDatlyType()
)

func (hooks *ArtifactLifecycle) Init(ctx context.Context, entity *Artifact, state xhandler.LifecycleContext[Artifact, xhandler.NoParent, PublishArtifactOutput]) error {
	return nil
}
func (hooks *ArtifactLifecycle) Validate(ctx context.Context, entity *Artifact, state xhandler.LifecycleContext[Artifact, xhandler.NoParent, PublishArtifactOutput]) error {
	if entity.Namespace == nil || entity.Id == nil {
		return fmt.Errorf("scoped identity required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}

	if entity.ContentHash == nil || entity.SizeBytes == nil || entity.MediaType == nil || entity.PublicationState == nil || *entity.PublicationState != "published" {
		return fmt.Errorf("published immutable artifact metadata required")
	}
	ref := data.ArtifactReference{ID: *entity.Id, ContentHash: *entity.ContentHash, SizeBytes: *entity.SizeBytes, MediaType: *entity.MediaType}
	if entity.KeyReference != nil {
		ref.KeyReference = *entity.KeyReference
	}
	if err := data.RequireVerifiedArtifact(ctx, *entity.Namespace, ref); err != nil {
		return err
	}

	return nil
}
func (hooks *ArtifactLifecycle) AfterSequence(ctx context.Context, entity *Artifact, state xhandler.LifecycleContext[Artifact, xhandler.NoParent, PublishArtifactOutput]) error {
	return nil
}
func (hooks *ArtifactLifecycle) AfterQueue(ctx context.Context, entity *Artifact, state xhandler.LifecycleContext[Artifact, xhandler.NoParent, PublishArtifactOutput]) error {
	return nil
}
func (hooks *ArtifactLifecycle) Finalize(ctx context.Context, input *PublishArtifactInput, output *PublishArtifactOutput, outcome xhandler.Outcome) error {
	return nil
}
