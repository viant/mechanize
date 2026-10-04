package durable

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestGeneratedLeaseUseExactEpochAndFailClosedSources(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "lease-evidence-owner", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	epoch := 7
	dispatches := 0
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return epoch, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		dispatches++
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	// A reader must not create a new database and call its absence a cleanup proof.
	evidence, err := b.LeaseUse(ctx, p, epoch)
	if err == nil || evidence.CountKnown {
		t.Fatalf("missing source proved zero: %+v %v", evidence, err)
	}
	if _, err = os.Stat(filepath.Join(b.options.StorageRoot, "users", p.Namespace, "state.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("reader created database: %v", err)
	}
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.StringValue, String: "case-1"}}
	// Prepare through actual generated plan/run components; no mutation dispatched.
	if _, err = b.PreparePlan(ctx, p, "prepared-lease-fixture", "session", *plan, nil); err != nil {
		t.Fatal(err)
	}
	evidence, err = b.LeaseUse(ctx, p, epoch)
	if err != nil || !evidence.CountKnown || evidence.IntentsPresent || evidence.Namespace != p.Namespace || evidence.LeaseEpoch != epoch || evidence.ObservedAt.IsZero() {
		t.Fatalf("existing zero-intent source: %+v %v", evidence, err)
	}
	if dispatches != 0 {
		t.Fatal("lease read dispatched an action")
	}
	orchestrator, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
		_, err := b.AttachOperation(ctx, p, run, revision, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := orchestrator.Open(ctx, "lease use fixture")
	if err != nil {
		t.Fatal(err)
	}
	op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = orchestrator.Wait(ctx, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	evidence, err = b.LeaseUse(ctx, p, epoch)
	if err != nil || !evidence.CountKnown || !evidence.IntentsPresent {
		t.Fatalf("committed attempt disappeared: %+v %v", evidence, err)
	}
	evidence, err = b.LeaseUse(ctx, p, epoch+1)
	if err != nil || !evidence.CountKnown || evidence.IntentsPresent {
		t.Fatalf("epoch query widened: %+v %v", evidence, err)
	}
	if dispatches != 1 {
		t.Fatalf("lease read mutated fixture: %d", dispatches)
	}
	other, _ := auth.NewPrincipal("fixture:issuer", "", "lease-other", nil)
	if evidence, err = b.LeaseUse(ctx, other, epoch); !errors.Is(err, auth.ErrUnauthorized) || evidence.CountKnown {
		t.Fatalf("foreign namespace: %+v %v", evidence, err)
	}
	if evidence, err = b.LeaseUse(ctx, p, 0); err == nil || evidence.CountKnown {
		t.Fatal("zero generation proved absence")
	}
	// A corrupt existing file with a SQLite-looking header cannot become proof.
	corruptRoot := t.TempDir()
	dir := filepath.Join(corruptRoot, "users", p.Namespace)
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4096)
	copy(payload, "SQLite format 3\x00")
	if err = os.WriteFile(filepath.Join(dir, "state.sqlite"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	corrupt, err := New(Options{SourceRoot: b.options.SourceRoot, StorageRoot: corruptRoot, LeaseEpoch: b.options.LeaseEpoch}, b.dispatch)
	if err != nil {
		t.Fatal(err)
	}
	defer corrupt.Close(ctx)
	if evidence, err = corrupt.LeaseUse(ctx, p, epoch); err == nil || evidence.CountKnown {
		t.Fatalf("corrupt source proved absence: %+v %v", evidence, err)
	}
}
