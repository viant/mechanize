package durable

import (
	"context"
	"errors"
	"fmt"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestEndlyDatlyIntentOutcomeAndRestartBarrier(t *testing.T) {
	for _, mode := range []string{"verified", "uncertain", "interrupted"} {
		verified := mode == "verified"
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
			storage := t.TempDir()
			p, err := auth.NewPrincipal("fixture:issuer", "", "alice", []string{"desktop:control"})
			if err != nil {
				t.Fatal(err)
			}
			p.ClientID = "fixture-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			var builder *Builder
			var captured context.Context
			var calls atomic.Int32
			dispatch := func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
				calls.Add(1)
				captured = ctx
				metadata, ok := integration.ExecutionFromContext(ctx)
				if !ok {
					return integration.StepResult{}, errors.New("metadata lost")
				}
				// Read through the generated component before touching the fixture. The
				// complete intent must already be visible from its committed transaction.
				user := builder.users[p.Namespace]
				run, err := load(ctx, user.server, p, metadata.RunID)
				if err != nil {
					return integration.StepResult{}, err
				}
				if len(run.Effects) == 1 && (run.Effects[0].BusinessKey == nil || *run.Effects[0].BusinessKey != `{"fixtureCase":{"kind":"string","string":"case-1"}}`) {
					return integration.StepResult{}, errors.New("intent lost exact typed business entity key")
				}
				if len(run.Effects) != 1 || run.Effects[0].State == nil || *run.Effects[0].State != "intent" {
					return integration.StepResult{}, errors.New("native dispatch preceded durable intent")
				}
				if mode == "interrupted" {
					panic("fixture process interrupted after dispatch")
				}
				if verified {
					return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
				}
				return integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("fixture receipt lost after external action")
			}
			options := Options{SourceRoot: source, StorageRoot: storage, MaxUsers: 2, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}
			builder, err = New(options, dispatch)
			if err != nil {
				t.Fatal(err)
			}
			execute := func(ctx context.Context, p auth.Principal, s model.Step, v map[string]model.Value) (result integration.StepResult, err error) {
				defer func() {
					if interrupted := recover(); interrupted != nil {
						err = fmt.Errorf("simulated process interruption: %v", interrupted)
					}
				}()
				return builder.Execute(ctx, p, s, v)
			}
			orchestration, err := integration.NewWithOptions(execute, integration.Options{PreparePlan: builder.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				_, err := builder.AttachOperation(ctx, p, run, revision, session, operation)
				return err
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := orchestration.Open(ctx, "durable fixture")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
			if err != nil {
				t.Fatal(err)
			}
			for i := range plan.Steps {
				if plan.Steps[i].Effect.Class == model.ExternalNonIdempotent {
					plan.Bindings = append(plan.Bindings, model.Binding{Name: "entity", Type: "value", Value: &model.Value{Kind: model.StringValue, String: "case-1"}})
					plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.ReferenceValue, Ref: "binding.entity"}}
				}
			}
			operation, err := orchestration.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			finished, err := orchestration.Wait(wait, session.SessionID, operation.ID)
			if err != nil {
				t.Fatal(err)
			}
			if verified && finished.Status != manager.OperationSucceeded {
				t.Fatalf("verified operation %+v", finished)
			}
			if !verified && finished.Status != manager.OperationFailed {
				t.Fatalf("uncertain operation %+v", finished)
			}
			if calls.Load() != 1 || captured == nil {
				t.Fatalf("dispatch calls %d", calls.Load())
			}
			if err = orchestration.Close(ctx, session.SessionID); err != nil {
				t.Fatal(err)
			}
			if err = builder.Close(ctx); err != nil {
				t.Fatal(err)
			}
			// Recreate only the data/action composition; the durable ledger remains.
			builder, err = New(options, dispatch)
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Close(ctx)
			result, replayErr := builder.Execute(context.WithoutCancel(captured), p, plan.Steps[0], map[string]model.Value{"binding.entity": {Kind: model.StringValue, String: "case-1"}})
			if verified && (replayErr != nil || result.VerificationState != "verified") {
				t.Fatalf("confirmed replay result %+v %v", result, replayErr)
			}
			if !verified && !errors.Is(replayErr, ErrNeedsReconciliation) {
				t.Fatalf("uncertain replay: %v", replayErr)
			}
			if verified {
				if _, changedErr := builder.Execute(context.WithoutCancel(captured), p, plan.Steps[0], map[string]model.Value{"binding.entity": {Kind: model.StringValue, String: "case-2"}}); changedErr != ErrNeedsReconciliation {
					t.Fatalf("replay reused receipt for different business entity: %v", changedErr)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("durable restart duplicated action: %d", calls.Load())
			}
			foreign, _ := auth.NewPrincipal("fixture:issuer", "", "bob", []string{"desktop:control"})
			if _, err = builder.Execute(context.WithoutCancel(captured), foreign, plan.Steps[0], map[string]model.Value{"binding.entity": {Kind: model.StringValue, String: "case-1"}}); err == nil {
				t.Fatal("foreign namespace admitted")
			}
			foreignCtx := auth.WithPrincipal(context.WithoutCancel(captured), foreign)
			if _, err = builder.Execute(foreignCtx, foreign, plan.Steps[0], map[string]model.Value{"binding.entity": {Kind: model.StringValue, String: "case-1"}}); err == nil {
				t.Fatal("authenticated foreign principal read another user's durable run")
			}
			if calls.Load() != 1 {
				t.Fatal("foreign principal dispatched another user's step")
			}

		})
	}
}
