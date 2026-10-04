package endly

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestOwnedSessionCloseHookBlocksAdmissionAndCanRetryCleanup(t *testing.T) {
	ctx := actor(t, "session-close")
	p, _ := auth.FromContext(ctx)
	p.ClientID = "owner-client"
	ctx = auth.WithPrincipal(ctx, p)
	calls := atomic.Int32{}
	failure := errors.New("fixture cleanup unknown")
	var runtime *Runtime
	var err error
	runtime, err = NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{}, nil
	}, Options{OnSessionClose: func(call context.Context, actual auth.Principal, id string) error {
		if actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
			t.Fatal("close owner changed")
		}
		if runtime.CheckSession(call, p, id) == nil {
			t.Fatal("session admitted input during close hook")
		}
		if calls.Add(1) == 1 {
			return failure
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtime.Open(ctx, "close hook")
	if err != nil {
		t.Fatal(err)
	}
	foreign := p
	foreign.ClientID = "other-client"
	if err = runtime.Close(auth.WithPrincipal(ctx, foreign), opened.SessionID); !errors.Is(err, auth.ErrUnauthorized) || calls.Load() != 0 {
		t.Fatal("foreign client ran close callback")
	}
	if err = runtime.Close(ctx, opened.SessionID); !errors.Is(err, failure) || calls.Load() != 1 {
		t.Fatal("cleanup failure lost")
	}
	if runtime.CheckSession(ctx, p, opened.SessionID) == nil {
		t.Fatal("failed cleanup reopened session admission")
	}
	if err = runtime.Close(ctx, opened.SessionID); err != nil || calls.Load() != 2 {
		t.Fatalf("owned cleanup retry: %v", err)
	}
}
