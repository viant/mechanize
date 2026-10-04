package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
)

func TestGeneratedRepairReadbackFailureRetainsConfirmedCommitAndCleanupError(t *testing.T) {
	ctx, p, row, opts := recoveryFixture(t)
	_, file, _, _ := runtime.Caller(0)
	storage := t.TempDir()
	seedRecovery(t, ctx, p, storage, row)
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(scoped, filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), storage, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	readbackErr := errors.New("fixture generated readback unavailable")
	cleanupErr := errors.New("fixture guard release unavailable")
	committed := false
	opts.Invoke = func(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
		if committed && request.Target.Component.Name == "LoadRecovery" {
			return nil, readbackErr
		}
		bound, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
		if err != nil {
			return nil, err
		}
		value, err := server.InvokeComponent(bound, request)
		if err == nil && request.Target.Component.Name == "AdmitRepair" {
			committed = true
		}
		return value, err
	}
	released := 0
	opts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) {
		return func() error { released++; return cleanupErr }, nil
	}
	service, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.Snapshot(ctx, p, "run")
	if err != nil {
		t.Fatal(err)
	}
	patch, err := json.Marshal(patchFrom(before))
	if err != nil {
		t.Fatal(err)
	}
	request := AdmissionRequest{ContextRequest: requestFrom(before), Patch: patch}
	result, err := service.Admit(ctx, p, request)
	if !errors.Is(err, readbackErr) || !errors.Is(err, cleanupErr) || !result.CommitConfirmed || result.Reference == nil || result.ReadyToResume || result.Status != "needsAttention" || released != 1 {
		t.Fatalf("confirmed commit lost on readback/cleanup failure: %+v %v releases=%d", result, err, released)
	}
	// Restore the generated read path and prove that the retained exact reference
	// is adopted without another repair, audit event, or budget reservation.
	committed = false
	opts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) {
		return func() error { return nil }, nil
	}
	service, _ = New(opts)
	after, err := service.Snapshot(ctx, p, "run")
	if err != nil {
		t.Fatal(err)
	}
	if after.Reference.PlanID != result.Reference.NewPlanID || after.Raw.Workflow == nil || value(after.Raw.Workflow.UsedRepairs) != 1 || len(after.Raw.Repairs) != 1 || len(after.Raw.Events) != 1 {
		t.Fatal("confirmed commit was not durably preserved")
	}
	adopted, err := service.Admit(ctx, p, request)
	if err != nil || !adopted.CommitConfirmed || !adopted.ReadyToResume || adopted.Reference == nil || *adopted.Reference != *result.Reference {
		t.Fatalf("exact readback adoption failed: %+v %v", adopted, err)
	}
	final, err := service.Snapshot(ctx, p, "run")
	if err != nil || final.Reference.Revision != after.Reference.Revision || value(final.Raw.Workflow.UsedRepairs) != 1 || len(final.Raw.Repairs) != 1 || len(final.Raw.Events) != 1 {
		t.Fatal("exact adoption consumed another repair or audit")
	}
}
