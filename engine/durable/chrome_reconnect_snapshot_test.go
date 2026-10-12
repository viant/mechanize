package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestChromeReconnectSnapshotRequiresHeldLiveOwnedLifecycle(t *testing.T) {
	base, p := privateActor(t)
	ctx, cancel := context.WithTimeout(base, 20*time.Second)
	defer cancel()
	_, file, _, _ := runtime.Caller(0)
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("read dispatched input")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())
	scope := data.ChromeReconnectBindingReadScope{ProfileChannel: "profile", BrowserInstance: "browser", ScopeHash: strings.Repeat("a", 64)}
	if _, err = b.ChromeReconnectBindingSnapshot(ctx, p); err == nil {
		t.Fatal("unheld/unsealed read accepted")
	}
	var retained context.Context
	err = b.WithChromeRetirementComponents(ctx, p, func(held context.Context, _ RetirementComponentInvoker) error {
		alive := true
		calls := 0
		sealed, e := data.WithChromeReconnectBindingReadAuthority(held, scope, func(context.Context) error {
			calls++
			if !alive {
				return auth.ErrUnauthorized
			}
			return nil
		})
		if e != nil {
			return e
		}
		retained = sealed
		rows, e := b.ChromeReconnectBindingSnapshot(sealed, p)
		if e != nil {
			return e
		}
		if len(rows) != 0 || calls < 4 {
			t.Fatalf("empty snapshot/fresh guard %d %d", len(rows), calls)
		}
		foreign := p
		foreign.ClientID = "foreign"
		if _, e = b.ChromeReconnectBindingSnapshot(sealed, foreign); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("foreign client admitted", e)
		}
		if _, e = (&Builder{}).ChromeReconnectBindingSnapshot(sealed, p); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("foreign builder admitted", e)
		}
		canceled, stop := context.WithCancel(sealed)
		stop()
		if _, e = b.ChromeReconnectBindingSnapshot(canceled, p); !errors.Is(e, context.Canceled) {
			t.Fatal("canceled snapshot admitted", e)
		}
		alive = false
		if rows, e = b.ChromeReconnectBindingSnapshot(sealed, p); !errors.Is(e, auth.ErrUnauthorized) || rows != nil {
			t.Fatal("revoked guard admitted", e)
		}
		alive = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.ChromeReconnectBindingSnapshot(retained, p); !errors.Is(err, errHeldUserLockExpired) {
		t.Fatal("expired held context borrowed snapshot", err)
	}
}
