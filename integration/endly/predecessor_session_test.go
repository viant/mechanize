package endly

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestPredecessorSessionStoppedRequiresCompletedOwnerClose(t *testing.T) {
	owner, _ := auth.NewPrincipal("fixture", "", "predecessor", []string{"desktop:control"})
	owner.ClientID = "synthetic-operator"
	successor := owner
	successor.ClientID = "synthetic-successor"
	current := auth.WithPrincipal(context.Background(), successor)
	original := auth.WithPrincipal(context.Background(), owner)
	var r *Runtime
	closingChecked := false
	var err error
	r, err = NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{}, nil
	}, Options{OnSessionClose: func(ctx context.Context, p auth.Principal, id string) error {
		closingChecked = true
		if r.CheckPredecessorSessionStopped(current, successor, owner.Namespace, owner.ClientID, id) == nil {
			t.Fatal("closing owner treated as stopped")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background())
	opened, err := r.Open(original, "generic predecessor")
	if err != nil {
		t.Fatal(err)
	}
	if r.CheckPredecessorSessionStopped(current, successor, owner.Namespace, owner.ClientID, opened.SessionID) == nil {
		t.Fatal("live owner treated as stopped")
	}
	if err = r.Close(original, opened.SessionID); err != nil {
		t.Fatal(err)
	}
	if !closingChecked {
		t.Fatal("closing lifecycle not exercised")
	}
	if err = r.CheckPredecessorSessionStopped(current, successor, owner.Namespace, owner.ClientID, opened.SessionID); err != nil {
		t.Fatal("completed close blocked", err)
	}
	if r.CheckPredecessorSessionStopped(current, successor, "other-user", owner.ClientID, opened.SessionID) == nil {
		t.Fatal("foreign namespace admitted")
	}
	canceled, cancel := context.WithCancel(current)
	cancel()
	if r.CheckPredecessorSessionStopped(canceled, successor, owner.Namespace, owner.ClientID, opened.SessionID) == nil {
		t.Fatal("canceled proof admitted")
	}
}
