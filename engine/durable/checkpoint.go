package durable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/checkpoint"
)

var ErrArtifactVerificationUnavailable = errors.New("scoped immutable artifact verification unavailable")

// PublishCheckpoint constructs immutable scoped manifest metadata from durable
// facts. The caller collects workspace observations before this invocation.
func (b *Builder) PublishCheckpoint(ctx context.Context, p auth.Principal, runID string, expectedRevision int, checkpointID string, workspace any, refs []data.ArtifactReference) (State, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return State{}, err
	}
	if b.options.StateMutationGuard == nil {
		return State{}, ErrStatePatchUnavailable
	}
	release, err := b.options.StateMutationGuard(ctx, p, runID)
	if err != nil {
		return State{}, err
	}
	if release == nil {
		return State{}, ErrStatePatchUnavailable
	}
	defer release()
	user.mu.Lock()
	defer user.mu.Unlock()
	ctx, err = data.WithStateMutationPermit(ctx, p.Namespace, runID)
	if err != nil {
		return State{}, err
	}
	current, err := load(ctx, user.server, p, runID)
	if err != nil {
		return State{}, err
	}
	if current.PlanId == nil {
		return State{}, errors.New("durable plan identity unavailable")
	}
	if len(refs) == 0 || len(refs) > 128 {
		return State{}, errors.New("checkpoint requires 1...128 verified artifact references")
	}
	if b.options.VerifyArtifact == nil {
		return State{}, ErrArtifactVerificationUnavailable
	}
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if err = b.options.VerifyArtifact(ctx, p, ref); err != nil {
			return State{}, err
		}
		ids = append(ids, ref.ID)
	}
	ctx, err = data.WithVerifiedArtifacts(ctx, p.Namespace, refs)
	if err != nil {
		return State{}, err
	}
	sequence := 0
	for _, event := range current.Events {
		if event.Sequence != nil && *event.Sequence > sequence {
			sequence = *event.Sequence
		}
	}
	manifest := data.CheckpointManifest{SchemaVersion: 1, Namespace: p.Namespace, RunID: runID, PlanID: *current.PlanId, RunRevision: expectedRevision + 1, EventSequence: sequence, Artifacts: refs, Workspace: workspace}
	content, err := json.Marshal(manifest)
	if err != nil {
		return State{}, err
	}
	sum := sha256.Sum256(content)
	row := &checkpoint.Checkpoint{}
	row.SetNamespace(pointer(p.Namespace))
	row.SetId(pointer(checkpointID))
	row.SetRunId(pointer(runID))
	row.SetPlanId(current.PlanId)
	row.SetRunRevision(pointer(expectedRevision + 1))
	row.SetEventSequence(pointer(sequence))
	row.SetManifestHash(pointer(hex.EncodeToString(sum[:])))
	row.SetManifestJson(pointer(string(content)))
	row.SetPublicationState(pointer("published"))
	row.SetCreatedAt(pointer(now()))
	run := &checkpoint.CheckpointRun{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer(runID))
	run.SetRevision(pointer(expectedRevision))
	run.SetCheckpoints([]*checkpoint.Checkpoint{row})
	input := &checkpoint.PublishCheckpointInput{}
	input.SetNamespace(p.Namespace)
	input.SetArtifactIDs(ids)
	input.SetPublishCheckpoint([]*checkpoint.CheckpointRun{run})
	if _, err = invoke(ctx, user.server, "checkpoint", "PublishCheckpoint", "PATCH", input, true); err != nil {
		return State{}, err
	}
	return stateRead(ctx, user.server, p, runID)
}
