package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestCredentialProtectionSnapshotReusesHeldReadAuthorityWithoutNestedLifecycle(t *testing.T) {
	base, p := privateActor(t)
	ctx, cancel := context.WithTimeout(base, 20*time.Second)
	defer cancel()
	_, file, _, _ := runtime.Caller(0)
	b, e := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("metadata reader dispatched input")
		return integration.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(context.Background())
	if snapshots, e := b.CredentialProtectionRecoverySnapshot(ctx, p); e != nil || len(snapshots) != 0 {
		t.Fatal("outside snapshot", e)
	}
	var retained context.Context
	e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		retained = held
		if snapshots, e := b.CredentialProtectionRecoverySnapshot(held, p); e != nil || len(snapshots) != 0 {
			t.Fatal("held snapshot nested lock", e)
		}
		nested := false
		if e := b.WithCredentialDeliveryComponents(held, p, func(context.Context, CredentialDeliveryComponentInvoker) error { nested = true; return nil }); e == nil || nested {
			t.Fatal("lifecycle nesting guard weakened")
		}
		foreign := p
		foreign.ClientID = "other"
		if _, e := b.CredentialProtectionRecoverySnapshot(held, foreign); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("foreign client borrowed held reader", e)
		}
		if _, e := (&Builder{}).CredentialProtectionRecoverySnapshot(held, p); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("foreign builder borrowed held reader", e)
		}
		expired, stop := context.WithCancel(held)
		stop()
		if _, e := b.CredentialProtectionRecoverySnapshot(expired, p); !errors.Is(e, context.Canceled) {
			t.Fatal("canceled held reader accepted", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := b.CredentialProtectionRecoverySnapshot(retained, p); !errors.Is(e, errHeldUserLockExpired) {
		t.Fatal("expired callback context borrowed reader", e)
	}
}
