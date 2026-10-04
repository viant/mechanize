package durable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/checkpoint"
	"github.com/viant/mechanize/data/publishartifact"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestTransitionsCorrelationAndVerifiedCheckpoint(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	p, _ := auth.NewPrincipal("fixture:issuer", "", "alice", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	content := []byte("immutable fixture evidence")
	sum := sha256.Sum256(content)
	ref := data.ArtifactReference{ID: "evidence", ContentHash: hex.EncodeToString(sum[:]), SizeBytes: len(content), MediaType: "text/plain"}
	options := Options{SourceRoot: source, StorageRoot: storage, MaxUsers: 2, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(context.Context, auth.Principal, string) (func(), error) { return func() {}, nil }}
	options.VerifyArtifact = func(ctx context.Context, actor auth.Principal, requested data.ArtifactReference) error {
		if actor.Namespace != p.Namespace || (requested.ID != "evidence" && requested.ID != "missing") {
			return auth.ErrUnauthorized
		}
		bytes, err := os.ReadFile(filepath.Join(storage, "users", actor.Namespace, "artifacts", requested.ID))
		if err != nil {
			return err
		}
		hash := sha256.Sum256(bytes)
		if requested.ContentHash != hex.EncodeToString(hash[:]) || requested.SizeBytes != len(bytes) || requested.MediaType != "text/plain" {
			return errors.New("artifact byte verification mismatch")
		}
		return nil
	}
	builder, err := New(options, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(ctx)
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	planID, err := builder.PreparePlan(ctx, p, "run", "session", *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := builder.AttachOperation(ctx, p, "run", 1, "session", "operation")
	if err != nil || state.Revision != 2 {
		t.Fatalf("operation correlation %+v %v", state, err)
	}
	if _, err = builder.AttachOperation(ctx, p, "run", 2, "forged-session", "forged-operation"); err == nil {
		t.Fatal("forged operation correlation admitted")
	}
	state, err = builder.TransitionRun(ctx, p, "run", 2, "paused")
	if err != nil || state.Status != "paused" || state.Revision != 3 {
		t.Fatalf("pause %+v %v", state, err)
	}
	if _, err = builder.TransitionRun(ctx, p, "run", 2, "failed"); err == nil {
		t.Fatal("stale pause token admitted")
	}
	dir := filepath.Join(storage, "users", p.Namespace, "artifacts")
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"evidence", "missing"} {
		if err = os.WriteFile(filepath.Join(dir, id), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	forged := ref
	forged.ContentHash = key("forged-hash")
	if err = builder.PublishArtifact(ctx, p, forged); err == nil {
		t.Fatal("forged artifact hash admitted")
	}
	scoped, user, err := builder.bound(ctx, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	unverified := &publishartifact.Artifact{}
	unverified.SetNamespace(pointer(p.Namespace))
	unverified.SetId(pointer(ref.ID))
	unverified.SetContentHash(pointer(ref.ContentHash))
	unverified.SetSizeBytes(pointer(ref.SizeBytes))
	unverified.SetMediaType(pointer(ref.MediaType))
	unverified.SetPublicationState(pointer("published"))
	publish := &publishartifact.PublishArtifactInput{}
	publish.SetNamespace(p.Namespace)
	publish.SetPublishArtifact([]*publishartifact.Artifact{unverified})
	if _, err = invoke(scoped, user.server, "publishartifact", "PublishArtifact", "POST", publish, true); err == nil {
		t.Fatal("client-forged verification admitted")
	}
	if err = builder.PublishArtifact(ctx, p, ref); err != nil {
		t.Fatal(err)
	}
	missing := ref
	missing.ID = "missing"
	if _, err = builder.PublishCheckpoint(ctx, p, "run", 3, "bad", nil, []data.ArtifactReference{missing}); err == nil {
		t.Fatal("missing database artifact admitted")
	}
	state, err = builder.PublishCheckpoint(ctx, p, "run", 3, "checkpoint", map[string]any{"fixture": "workspace"}, []data.ArtifactReference{ref})
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 4 || len(state.Checkpoints) != 1 || state.Checkpoints[0].PublicationState == nil || *state.Checkpoints[0].PublicationState != "published" {
		t.Fatalf("published checkpoint %+v", state)
	}
	if _, err = builder.PublishCheckpoint(ctx, p, "run", 3, "stale", nil, []data.ArtifactReference{ref}); err == nil {
		t.Fatal("stale checkpoint revision admitted")
	}
	// Prove the component checks ownership even when a trusted invocation has
	// valid byte evidence and a body with an internally consistent content hash.
	scoped, err = data.WithStateMutationPermit(scoped, p.Namespace, "run")
	if err != nil {
		t.Fatal(err)
	}
	scoped, err = data.WithVerifiedArtifacts(scoped, p.Namespace, []data.ArtifactReference{ref})
	if err != nil {
		t.Fatal(err)
	}
	manifest := data.CheckpointManifest{SchemaVersion: 1, Namespace: key("foreign"), RunID: "run", PlanID: planID, RunRevision: 5, EventSequence: 2, Artifacts: []data.ArtifactReference{ref}}
	encoded, _ := json.Marshal(manifest)
	hash := sha256.Sum256(encoded)
	cp := &checkpoint.Checkpoint{}
	cp.SetNamespace(pointer(p.Namespace))
	cp.SetId(pointer("forged"))
	cp.SetRunId(pointer("run"))
	cp.SetPlanId(pointer(planID))
	cp.SetRunRevision(pointer(5))
	cp.SetEventSequence(pointer(2))
	cp.SetManifestHash(pointer(hex.EncodeToString(hash[:])))
	cp.SetManifestJson(pointer(string(encoded)))
	cp.SetPublicationState(pointer("published"))
	cp.SetCreatedAt(pointer(now()))
	root := &checkpoint.CheckpointRun{}
	root.SetNamespace(pointer(p.Namespace))
	root.SetId(pointer("run"))
	root.SetRevision(pointer(4))
	root.SetCheckpoints([]*checkpoint.Checkpoint{cp})
	input := &checkpoint.PublishCheckpointInput{}
	input.SetNamespace(p.Namespace)
	input.SetArtifactIDs([]string{ref.ID})
	input.SetPublishCheckpoint([]*checkpoint.CheckpointRun{root})
	if _, err = invoke(scoped, user.server, "checkpoint", "PublishCheckpoint", "PATCH", input, true); err == nil {
		t.Fatal("forged manifest owner admitted")
	}
	runs, err := builder.ListRuns(ctx, p)
	if err != nil || len(runs) != 1 {
		t.Fatalf("run catalog %d %v", len(runs), err)
	}
	if _, err = builder.LoadPlan(ctx, p, planID); err != nil {
		t.Fatal(err)
	}
	events, err := builder.ListEvents(ctx, p, "run")
	if err != nil || len(events) != 2 {
		t.Fatalf("audit catalog %d %v", len(events), err)
	}
	checkpoints, err := builder.ListCheckpoints(ctx, p, "run")
	if err != nil || len(checkpoints) != 1 {
		t.Fatalf("checkpoint catalog %d %v", len(checkpoints), err)
	}
}
