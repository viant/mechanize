package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/mechanize/artifact"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/scy"
)

func artifactFixture(t *testing.T) (*ArtifactService, context.Context, auth.Principal, string, *ArtifactOptions) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "key.json")
	content, _ := json.Marshal(map[string][]byte{"key": bytes.Repeat([]byte{19}, 32)})
	if err = os.WriteFile(keyFile, content, 0600); err != nil {
		t.Fatal(err)
	}
	resolver, err := artifact.NewScyResolver(map[string]scy.Resource{"fixture-v1": {URL: keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "artifacts")
	store, err := artifact.New(artifact.Config{Root: root, SourceKeyReference: "fixture-v1", Keys: resolver, MaxBytes: 1024, NamespaceQuotaBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := auth.NewPrincipal("fixture", "tenant", "alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	options := ArtifactOptions{Store: store,
		Authorize: func(_ context.Context, actual auth.Principal) error {
			if actual.Namespace != p.Namespace || !actual.HasScope("desktop:observe") {
				return auth.ErrUnauthorized
			}
			return nil
		},
		Consent: func(ctx context.Context, _ auth.Principal, surface model.Surface) (*consent.Lease, error) {
			if surface.BundleID != "fixture.app" {
				return nil, auth.ErrUnauthorized
			}
			return &consent.Lease{Context: ctx, Release: func() {}}, nil
		},
		Publish: func(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
			return store.Verify(ctx, p.Namespace, ref)
		},
	}
	service, err := NewArtifactService(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, ctx, p, root, &service.options
}

func TestArtifactHostPublication(t *testing.T) {
	service, ctx, p, root, options := artifactFixture(t)
	released, published := false, false
	original := options.Publish
	options.Consent = func(ctx context.Context, _ auth.Principal, surface model.Surface) (*consent.Lease, error) {
		if surface.BundleID != "fixture.app" {
			t.Fatal("source scope changed")
		}
		return &consent.Lease{Context: ctx, Release: func() { released = true }}, nil
	}
	options.Publish = func(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
		if _, err := data.RequireScope(ctx, p.Namespace); err != nil {
			t.Fatal(err)
		}
		if released {
			t.Fatal("lease released before publication")
		}
		published = true
		return original(ctx, p, ref)
	}
	ref, err := service.Publish(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, "text/plain", strings.NewReader("sensitive fixture evidence"))
	if err != nil || !released || !published {
		t.Fatalf("publication %v released=%v published=%v", err, released, published)
	}
	raw, err := os.ReadFile(filepath.Join(root, p.Namespace, ref.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"sensitive fixture evidence", "text/plain", ref.ContentHash, ref.KeyReference} {
		if bytes.Contains(raw, []byte(plain)) {
			t.Fatalf("plaintext persisted: %s", plain)
		}
	}
	got, err := service.Read(ctx, p, ref)
	if err != nil || string(got) != "sensitive fixture evidence" {
		t.Fatalf("read: %s %v", got, err)
	}
	forged := ref
	forged.MediaType = "application/json"
	if err = service.VerifyArtifact(ctx, p, forged); !errors.Is(err, artifact.ErrCorrupt) {
		t.Fatalf("forged metadata: %v", err)
	}
	other, _ := auth.NewPrincipal("fixture", "tenant", "bob", p.Scopes)
	if _, err = service.Read(auth.WithPrincipal(context.Background(), other), p, ref); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("foreign owner: %v", err)
	}
}

func TestArtifactHostFailsClosed(t *testing.T) {
	service, ctx, p, root, options := artifactFixture(t)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	if _, err := service.Publish(context.Background(), p, surface, "text/plain", strings.NewReader("no")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("missing identity: %v", err)
	}
	noScope := p
	noScope.Scopes = nil
	if _, err := service.Publish(auth.WithPrincipal(ctx, noScope), p, surface, "text/plain", strings.NewReader("no")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("caller scope escalation: %v", err)
	}
	foreign, _ := auth.NewPrincipal("fixture", "tenant", "bob", nil)
	foreignContext, _ := data.WithScope(ctx, data.Scope{Namespace: foreign.Namespace})
	if _, err := service.Publish(foreignContext, p, surface, "text/plain", strings.NewReader("no")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("scope overwrite: %v", err)
	}
	if _, err := service.Publish(ctx, p, model.Surface{Kind: "native", BundleID: "foreign.app"}, "text/plain", strings.NewReader("no")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("consent denied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, p.Namespace)); !os.IsNotExist(err) {
		t.Fatalf("denied publication created files: %v", err)
	}
	if _, err := service.Publish(ctx, p, surface, "text/plain", strings.NewReader(strings.Repeat("x", 1025))); !errors.Is(err, artifact.ErrLimit) {
		t.Fatalf("size bound: %v", err)
	}
	options.Consent = func(ctx context.Context, _ auth.Principal, _ model.Surface) (*consent.Lease, error) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		return &consent.Lease{Context: cancelled, Release: func() {}}, nil
	}
	if _, err := service.Publish(ctx, p, surface, "text/plain", strings.NewReader("no")); !errors.Is(err, context.Canceled) {
		t.Fatalf("revoked consent: %v", err)
	}
}

func TestArtifactHostUnknownPublicationRetainsBytes(t *testing.T) {
	service, ctx, p, root, options := artifactFixture(t)
	sentinel := errors.New("commit acknowledgement lost")
	options.Publish = func(context.Context, auth.Principal, data.ArtifactReference) error { return sentinel }
	ref, err := service.Publish(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, "text/plain", strings.NewReader("fixture"))
	var failure *ArtifactPublicationError
	if !errors.As(err, &failure) || !errors.Is(err, sentinel) || failure.Reference != ref {
		t.Fatalf("uncertain publication lost reference: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, p.Namespace, ref.ID)); err != nil {
		t.Fatalf("potentially committed artifact deleted: %v", err)
	}
	if err = service.VerifyArtifact(ctx, p, ref); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactHostUnsupportedCapture(t *testing.T) {
	service, ctx, p, _, options := artifactFixture(t)
	options.Consent = func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error) {
		t.Fatal("unsupported capture consumed consent")
		return nil, nil
	}
	ref, err := service.Capture(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.invalid"})
	var failure *model.MechanizeError
	if !errors.As(err, &failure) || failure.Code != "unsupported" || failure.DispatchState != "notDispatched" || ref.ID != "" {
		t.Fatalf("fabricated capture: %v %v", ref, err)
	}
}
