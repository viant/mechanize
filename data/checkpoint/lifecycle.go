package checkpoint

import (
	context "context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// CheckpointRunLifecycle customizes role Input.PublishCheckpoint.
type CheckpointRunLifecycle struct{}

func CheckpointRunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*CheckpointRunLifecycle)(nil)).Elem()
}

var (
	CheckpointRunLifecycleHooks = new(CheckpointRunLifecycle)
	CheckpointRunLifecycleDatly = CheckpointRunLifecycleDatlyType()
)

func (hooks *CheckpointRunLifecycle) Init(ctx context.Context, entity *CheckpointRun, state xhandler.LifecycleContext[CheckpointRun, xhandler.NoParent, PublishCheckpointOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *CheckpointRunLifecycle) Validate(ctx context.Context, entity *CheckpointRun, state xhandler.LifecycleContext[CheckpointRun, xhandler.NoParent, PublishCheckpointOutput]) error {
	if entity.Namespace == nil || entity.Id == nil {
		return fmt.Errorf("scoped run identity required")
	}
	if err := data.RequireStateMutationPermit(ctx, *entity.Namespace, *entity.Id); err != nil {
		return err
	}
	if state.Previous == nil || state.Previous.PlanId == nil {
		return fmt.Errorf("authorized checkpoint run not found")
	}
	if state.Previous.Status == nil || (*state.Previous.Status != "paused" && *state.Previous.Status != "new") {
		return fmt.Errorf("checkpoint publication requires paused/new run")
	}
	if len(state.Previous.Unresolved) > 0 {
		return fmt.Errorf("unresolved effects block resumable checkpoint")
	}
	if entity.Has.PlanId || entity.Has.Status {
		return fmt.Errorf("checkpoint cannot change run lifecycle or objective")
	}
	if len(entity.Checkpoints) != 1 {
		return fmt.Errorf("one immutable checkpoint required")
	}
	checkpoint := entity.Checkpoints[0]
	if checkpoint.ManifestJson == nil || len(*checkpoint.ManifestJson) > 1<<20 || checkpoint.ManifestHash == nil {
		return fmt.Errorf("checkpoint manifest required")
	}
	sum := sha256.Sum256([]byte(*checkpoint.ManifestJson))
	if hex.EncodeToString(sum[:]) != *checkpoint.ManifestHash {
		return fmt.Errorf("manifest hash mismatch")
	}
	var manifest data.CheckpointManifest
	if err := json.Unmarshal([]byte(*checkpoint.ManifestJson), &manifest); err != nil {
		return fmt.Errorf("invalid manifest")
	}
	cursor := 0
	for _, event := range state.Previous.LedgerEvents {
		if event.Sequence != nil && *event.Sequence > cursor {
			cursor = *event.Sequence
		}
	}
	if manifest.SchemaVersion != 1 || manifest.Namespace != *entity.Namespace || manifest.RunID != *entity.Id || manifest.PlanID != *state.Previous.PlanId || manifest.RunRevision != *entity.Revision || manifest.EventSequence != cursor {
		return fmt.Errorf("manifest ownership, revision or cursor mismatch")
	}
	if checkpoint.PlanId == nil || *checkpoint.PlanId != manifest.PlanID || checkpoint.RunRevision == nil || *checkpoint.RunRevision != manifest.RunRevision || checkpoint.EventSequence == nil || *checkpoint.EventSequence != cursor {
		return fmt.Errorf("checkpoint metadata mismatch")
	}
	indexed := map[string]*Artifact{}
	for _, artifact := range state.Previous.Artifacts {
		if artifact.Id != nil {
			indexed[*artifact.Id] = artifact
		}
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 128 {
		return fmt.Errorf("bounded artifact references required")
	}
	seen := map[string]bool{}
	for _, ref := range manifest.Artifacts {
		if seen[ref.ID] {
			return fmt.Errorf("duplicate artifact reference")
		}
		seen[ref.ID] = true
		artifact := indexed[ref.ID]
		if artifact == nil || artifact.Namespace == nil || *artifact.Namespace != manifest.Namespace || artifact.ContentHash == nil || *artifact.ContentHash != ref.ContentHash || artifact.SizeBytes == nil || *artifact.SizeBytes != ref.SizeBytes || artifact.MediaType == nil || *artifact.MediaType != ref.MediaType || artifact.PublicationState == nil || *artifact.PublicationState != "published" {
			return fmt.Errorf("published artifact reachability mismatch")
		}
		storedKey := ""
		if artifact.KeyReference != nil {
			storedKey = *artifact.KeyReference
		}
		if storedKey != ref.KeyReference {
			return fmt.Errorf("artifact encryption ownership mismatch")
		}
		if err := data.RequireVerifiedArtifact(ctx, manifest.Namespace, ref); err != nil {
			return err
		}
	}

	return nil
}
func (hooks *CheckpointRunLifecycle) AfterSequence(ctx context.Context, entity *CheckpointRun, state xhandler.LifecycleContext[CheckpointRun, xhandler.NoParent, PublishCheckpointOutput]) error {
	return nil
}
func (hooks *CheckpointRunLifecycle) AfterQueue(ctx context.Context, entity *CheckpointRun, state xhandler.LifecycleContext[CheckpointRun, xhandler.NoParent, PublishCheckpointOutput]) error {
	return nil
}
func (hooks *CheckpointRunLifecycle) Finalize(ctx context.Context, input *PublishCheckpointInput, output *PublishCheckpointOutput, outcome xhandler.Outcome) error {
	return nil
}

// CheckpointLifecycle customizes role Input.PublishCheckpoint.Checkpoints.
type CheckpointLifecycle struct{}

func CheckpointLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*CheckpointLifecycle)(nil)).Elem()
}

var (
	CheckpointLifecycleHooks = new(CheckpointLifecycle)
	CheckpointLifecycleDatly = CheckpointLifecycleDatlyType()
)

func (hooks *CheckpointLifecycle) Init(ctx context.Context, entity *Checkpoint, state xhandler.LifecycleContext[Checkpoint, CheckpointRun, PublishCheckpointOutput]) error {
	return nil
}
func (hooks *CheckpointLifecycle) Validate(ctx context.Context, entity *Checkpoint, state xhandler.LifecycleContext[Checkpoint, CheckpointRun, PublishCheckpointOutput]) error {
	if state.Previous != nil {
		return fmt.Errorf("published checkpoint history is immutable")
	}
	if entity.PublicationState == nil || *entity.PublicationState != "published" {
		return fmt.Errorf("published checkpoint required")
	}

	return nil
}
func (hooks *CheckpointLifecycle) AfterSequence(ctx context.Context, entity *Checkpoint, state xhandler.LifecycleContext[Checkpoint, CheckpointRun, PublishCheckpointOutput]) error {
	return nil
}
func (hooks *CheckpointLifecycle) AfterQueue(ctx context.Context, entity *Checkpoint, state xhandler.LifecycleContext[Checkpoint, CheckpointRun, PublishCheckpointOutput]) error {
	return nil
}
