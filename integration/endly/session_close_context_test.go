package endly

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestClosingSessionAuthorityIsCallbackOnlyAndDoesNotAdmitOperations(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "original-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var runtime *Runtime
	var saved context.Context
	runtime, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{}, nil
	}, Options{OnSessionClose: func(closing context.Context, actor auth.Principal, id string) error {
		saved = closing
		if !errors.Is(runtime.CheckSession(closing, actor, id), auth.ErrUnauthorized) {
			t.Error("ordinary admission remained open during cleanup")
		}
		if runtime.CheckClosingSession(closing, actor, id) != nil {
			t.Error("authenticated lifecycle callback lost its owner")
		}
		foreign := actor
		foreign.ClientID = "foreign-client"
		if runtime.CheckClosingSession(auth.WithPrincipal(closing, foreign), foreign, id) == nil {
			t.Error("foreign client borrowed closing authority")
		}
		if runtime.CheckClosingSession(ctx, actor, id) == nil || runtime.CheckClosingSession(closing, actor, "different-session") == nil {
			t.Error("closing authority was forgeable by normal context/session")
		}
		canceled, cancel := context.WithCancel(closing)
		cancel()
		if runtime.CheckClosingSession(canceled, actor, id) == nil {
			t.Error("canceled cleanup retained authority")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtime.Open(ctx, "Lifecycle fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(ctx, opened.SessionID); err != nil {
		t.Fatal(err)
	}
	if saved == nil || runtime.CheckClosingSession(saved, p, opened.SessionID) == nil {
		t.Fatal("lifecycle authority escaped its callback")
	}
}

func TestClosingSessionAuthorityIsRevokedWhenCallbackPanics(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "original-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var captured context.Context
	runtime, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{}, nil
	}, Options{OnSessionClose: func(closing context.Context, _ auth.Principal, _ string) error {
		captured = closing
		panic("synthetic lifecycle callback failure")
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtime.Open(ctx, "Lifecycle panic fixture")
	if err != nil {
		t.Fatal(err)
	}
	panicked := false
	func() { defer func() { panicked = recover() != nil }(); _ = runtime.Close(ctx, opened.SessionID) }()
	if !panicked || captured == nil {
		t.Fatal("lifecycle fixture did not exercise panic unwinding")
	}
	if runtime.CheckClosingSession(captured, p, opened.SessionID) == nil {
		t.Fatal("cleanup authority survived callback panic")
	}
	if runtime.CheckSession(captured, p, opened.SessionID) == nil {
		t.Fatal("panic reopened ordinary session admission")
	}
	runtime.onSessionClose = nil
	if err = runtime.Close(ctx, opened.SessionID); err != nil {
		t.Fatal(err)
	}
}
