package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/getartifact"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func publicationFixture(t *testing.T) (context.Context, auth.Principal, data.ArtifactReference) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture:issuer", "", "artifact-alice", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	ref := data.ArtifactReference{ID: "immutable", ContentHash: key("bytes"), SizeBytes: 17, MediaType: "text/plain", KeyReference: "fixture:key:v1"}
	ctx, err = data.WithVerifiedArtifacts(ctx, p.Namespace, []data.ArtifactReference{ref})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, p, ref
}
func publishedArtifact(namespace string, ref data.ArtifactReference) *getartifact.Artifact {
	return &getartifact.Artifact{Namespace: pointer(namespace), Id: pointer(ref.ID), ContentHash: pointer(ref.ContentHash), SizeBytes: pointer(ref.SizeBytes), MediaType: pointer(ref.MediaType), KeyReference: pointer(ref.KeyReference), PublicationState: pointer("published")}
}

func TestArtifactPublicationCommitAcknowledgementReconciliation(t *testing.T) {
	ctx, p, ref := publicationFixture(t)
	ackLost := errors.New("commit acknowledgement lost")
	readLost := errors.New("database unreadable")
	for _, scenario := range []string{"committed", "absent", "conflict", "unreadable", "no-byte-proof"} {
		t.Run(scenario, func(t *testing.T) {
			reads, writes := 0, 0
			call := func(_ context.Context, pkg, name, method string, input any, commit bool) (any, error) {
				if pkg == "publishartifact" {
					writes++
					if name != "PublishArtifact" || method != "POST" || !commit {
						t.Fatal("wrong writer contract")
					}
					return nil, ackLost
				}
				reads++
				request, ok := input.(*getartifact.GetArtifactInput)
				if !ok || request.Namespace != p.Namespace || request.ArtifactID != ref.ID || name != "GetArtifact" || method != "GET" || commit {
					t.Fatal("unscoped reader")
				}
				output := &getartifact.GetArtifactOutput{}
				if reads == 2 {
					switch scenario {
					case "committed":
						output.Data = []*getartifact.Artifact{publishedArtifact(p.Namespace, ref)}
					case "conflict":
						row := publishedArtifact(p.Namespace, ref)
						row.KeyReference = pointer("changed")
						output.Data = []*getartifact.Artifact{row}
					case "unreadable":
						return nil, readLost
					}
				}
				return output, nil
			}
			invokeCtx := ctx
			if scenario == "no-byte-proof" {
				invokeCtx, _ = data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
			}
			err := publishVerifiedArtifact(invokeCtx, p.Namespace, ref, call)
			if scenario == "committed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("uncertain publication accepted")
			}
			if scenario == "no-byte-proof" {
				if reads != 0 || writes != 0 {
					t.Fatal("database used without byte proof")
				}
				return
			}
			if reads != 2 || writes != 1 {
				t.Fatalf("reads %d writes %d", reads, writes)
			}
			if scenario == "conflict" && !errors.Is(err, ErrArtifactPublicationConflict) {
				t.Fatal(err)
			}
			if scenario == "unreadable" && (!errors.Is(err, ackLost) || !errors.Is(err, readLost)) {
				t.Fatal(err)
			}
		})
	}
}

func TestArtifactPublicationRejectsChangedMetadata(t *testing.T) {
	ctx, p, ref := publicationFixture(t)
	mutations := map[string]func(*getartifact.Artifact){
		"namespace": func(r *getartifact.Artifact) { r.Namespace = pointer(key("foreign")) },
		"id":        func(r *getartifact.Artifact) { r.Id = pointer("foreign") },
		"hash":      func(r *getartifact.Artifact) { r.ContentHash = pointer(key("changed")) },
		"size":      func(r *getartifact.Artifact) { r.SizeBytes = pointer(ref.SizeBytes + 1) },
		"media":     func(r *getartifact.Artifact) { r.MediaType = pointer("image/png") },
		"key":       func(r *getartifact.Artifact) { r.KeyReference = pointer("changed") },
		"state":     func(r *getartifact.Artifact) { r.PublicationState = pointer("pending") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			row := publishedArtifact(p.Namespace, ref)
			mutate(row)
			err := publishVerifiedArtifact(ctx, p.Namespace, ref, func(_ context.Context, pkg, _, _ string, _ any, _ bool) (any, error) {
				if pkg != "getartifact" {
					t.Fatal("conflict attempted write")
				}
				return &getartifact.GetArtifactOutput{Data: []*getartifact.Artifact{row}}, nil
			})
			if !errors.Is(err, ErrArtifactPublicationConflict) {
				t.Fatal(err)
			}
		})
	}
}

func TestArtifactPublicationReplayUsesGeneratedScopedReader(t *testing.T) {
	ctx, p, ref := publicationFixture(t)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	verified := 0
	builder, err := New(Options{SourceRoot: source, StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, VerifyArtifact: func(_ context.Context, actor auth.Principal, requested data.ArtifactReference) error {
		verified++
		if actor.Namespace != p.Namespace {
			return auth.ErrUnauthorized
		}
		return nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(ctx)
	if err = builder.PublishArtifact(ctx, p, ref); err != nil {
		t.Fatal(err)
	}
	if err = builder.PublishArtifact(ctx, p, ref); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	for name, change := range map[string]func(*data.ArtifactReference){
		"hash": func(r *data.ArtifactReference) { r.ContentHash = key("different") }, "size": func(r *data.ArtifactReference) { r.SizeBytes++ }, "media": func(r *data.ArtifactReference) { r.MediaType = "image/png" }, "key": func(r *data.ArtifactReference) { r.KeyReference = "other-key" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := ref
			change(&changed)
			if err := builder.PublishArtifact(ctx, p, changed); !errors.Is(err, ErrArtifactPublicationConflict) {
				t.Fatal(err)
			}
		})
	}
	if verified != 6 {
		t.Fatalf("byte verification count %d", verified)
	}
	foreign, _ := auth.NewPrincipal("fixture:issuer", "", "foreign", []string{"desktop:control"})
	if err = builder.PublishArtifact(ctx, foreign, ref); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	scoped, user, err := builder.bound(ctx, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise a real generated POST followed by a simulated lost reply and a
	// real scoped reader. This proves metadata reconciliation, not just a fake.
	ackRef := ref
	ackRef.ID = "lost-ack"
	verifiedCtx, err := data.WithVerifiedArtifacts(scoped, p.Namespace, []data.ArtifactReference{ackRef})
	if err != nil {
		t.Fatal(err)
	}
	user.mu.Lock()
	err = publishVerifiedArtifact(verifiedCtx, p.Namespace, ackRef, func(ctx context.Context, pkg, name, method string, input any, commit bool) (any, error) {
		result, err := invoke(ctx, user.server, pkg, name, method, input, commit)
		if err == nil && pkg == "publishartifact" {
			return nil, errors.New("injected lost commit acknowledgement")
		}
		return result, err
	})
	user.mu.Unlock()
	if err != nil {
		t.Fatalf("real committed lost acknowledgement: %v", err)
	}
	foreignRead := &getartifact.GetArtifactInput{}
	foreignRead.SetNamespace(foreign.Namespace)
	foreignRead.SetArtifactID(ref.ID)
	if _, err = invoke(scoped, user.server, "getartifact", "GetArtifact", "GET", foreignRead, false); err == nil {
		t.Fatal("foreign reader scope admitted")
	}
	builder.options.VerifyArtifact = nil
	if err = builder.PublishArtifact(ctx, p, ref); !errors.Is(err, ErrArtifactVerificationUnavailable) {
		t.Fatal(err)
	}
}
