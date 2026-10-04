package keychain

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/viant/afs"
	"github.com/viant/afs/storage"
	"github.com/viant/scy"
)

func TestTrustedAliasesAndScyProvider(t *testing.T) {
	reads := 0
	m, err := newManager(Options{Items: map[string]Item{"console": {Service: "fixture", Account: "operator"}}}, func(ctx context.Context, item Item) ([]byte, error) {
		reads++
		if item.Service != "fixture" || item.Account != "operator" {
			t.Fatal("lookup escaped enrollment")
		}
		return []byte("fixture-secret"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise Scy's actual public AFS integration with an injected provider;
	// this test never accesses the employee's Keychain.
	afs.GetRegistry().Register(Scheme, func(...storage.Option) (storage.Manager, error) { return m, nil })
	ref, _ := Reference("console")
	secret, err := scy.New().Load(context.Background(), scy.NewResource("", ref, ""))
	if err != nil || secret.String() != "fixture-secret" {
		t.Fatalf("Scy did not resolve trusted provider: %v", err)
	}
	if reads != 1 {
		t.Fatalf("lookup calls: %d", reads)
	}
	for _, raw := range []string{
		Scheme + "://generic-password/unknown", Scheme + "://generic-password/console?service=other",
		Scheme + "://generic-password/console#x", Scheme + "://user@generic-password/console",
		Scheme + "://generic-password/%63onsole", Scheme + "://generic-password/../console",
		Scheme + "://generic-password/console?", Scheme + "://other/console", "file:///tmp/token",
	} {
		if _, err := m.OpenURL(context.Background(), raw); !errors.Is(err, ErrReference) {
			t.Fatalf("accepted invalid reference %q", raw)
		}
	}
	if _, err = m.OpenURL(context.Background(), ref, "untrusted-key-option"); !errors.Is(err, ErrReference) {
		t.Fatal("accepted resource options")
	}
	if reads != 1 {
		t.Fatal("invalid references reached Keychain lookup")
	}
	if err := m.Upload(context.Background(), ref, 0600, nil); !errors.Is(err, ErrReadOnly) {
		t.Fatal("write accepted")
	}
	if err := m.Delete(context.Background(), ref); !errors.Is(err, ErrReadOnly) {
		t.Fatal("delete accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.OpenURL(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled lookup accepted")
	}
	reader, err := m.OpenURL(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if string(data) != "fixture-secret" {
		t.Fatal("incorrect fixture bytes")
	}
}

func TestInvalidEnrollment(t *testing.T) {
	for _, items := range []map[string]Item{nil, {"../other": {Service: "s", Account: "a"}}, {"ok": {Service: "", Account: "a"}}, {"ok": {Service: "s", Account: "a\x00"}}} {
		if _, err := newManager(Options{Items: items}, lookup); !errors.Is(err, ErrReference) {
			t.Fatal("invalid enrollment accepted")
		}
	}
}
