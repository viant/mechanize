package durable

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestResolveOwnedArtifactUsesGeneratedUserScopedMetadata(t *testing.T) {
	ctx, owner, ref := publicationFixture(t)
	_, file, _, _ := runtime.Caller(0)
	builder, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, VerifyArtifact: func(context.Context, auth.Principal, data.ArtifactReference) error { return nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(ctx)
	if err = builder.PublishArtifact(ctx, owner, ref); err != nil {
		t.Fatal(err)
	}
	got, err := builder.ResolveOwnedArtifact(ctx, owner, ref.ID)
	if err != nil || !reflect.DeepEqual(got, ref) {
		t.Fatalf("published metadata changed: %+v %v", got, err)
	}
	if _, err = builder.ResolveOwnedArtifact(ctx, owner, "missing"); err == nil {
		t.Fatal("missing artifact resolved")
	}
	other, err := auth.NewPrincipal("fixture:issuer", "", "another-video-owner", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = builder.ResolveOwnedArtifact(ctx, other, ref.ID); err == nil {
		t.Fatal("forged owner resolved")
	}
	otherCtx := auth.WithPrincipal(context.Background(), other)
	if _, err = builder.ResolveOwnedArtifact(otherCtx, other, ref.ID); err == nil {
		t.Fatal("second user's connector read owner's artifact")
	}
	for _, id := range []string{"", "../immutable", "/tmp/video.mov", "https://example.test/video", "artifact?secret=value"} {
		if _, err = builder.ResolveOwnedArtifact(ctx, owner, id); err == nil {
			t.Fatal("nonopaque identifier admitted")
		}
	}
}
