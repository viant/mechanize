package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestWindowFrameMetadataPreparationCreatesNoRunOrDispatch(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "frame-metadata", []string{"desktop:control", "desktop:observe"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	_, file, _, _ := runtime.Caller(0)
	dispatches := 0
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("metadata acquired input authority")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		dispatches++
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	foreign := p
	foreign.ClientID = "foreign"
	if err = b.PrepareWindowFrameDispatch(ctx, foreign); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign preparer admitted")
	}
	if err = b.PrepareWindowFrameDispatch(ctx, p); err != nil {
		t.Fatal(err)
	}
	runs, err := b.ListRuns(ctx, p)
	if err != nil || len(runs) != 0 || dispatches != 0 {
		t.Fatalf("metadata created product run/input: runs=%d dispatches=%d err=%v", len(runs), dispatches, err)
	}
}
