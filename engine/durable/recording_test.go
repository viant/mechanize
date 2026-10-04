package durable

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/recordevents"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestGeneratedRecordingJournalOrderingAndIsolation(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	builder, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(context.Background())
	alice, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), alice)
	for _, sequence := range []int{2, 1} {
		row := &recordevents.RecordedEvent{}
		row.SetNamespace(pointer(alice.Namespace))
		row.SetId(pointer(key("row", string(rune(sequence)))))
		row.SetRecordingId(pointer("demo"))
		row.SetSequence(pointer(sequence))
		row.SetKind(pointer("batch"))
		row.SetPayloadJson(pointer(`{"events":[],"redacted":true}`))
		row.SetCreatedAt(pointer(time.Now().UTC().Format(time.RFC3339Nano)))
		if err = builder.AppendRecordingEvents(ctx, alice, []*recordevents.RecordedEvent{row}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := builder.ReadRecordingEvents(ctx, alice, "demo")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if *rows[0].Sequence != 1 || *rows[1].Sequence != 2 {
		t.Fatal("journal order was not stable")
	}
	bob, _ := auth.NewPrincipal("fixture", "", "bob", []string{"desktop:observe"})
	bobCtx := auth.WithPrincipal(context.Background(), bob)
	isolated, err := builder.ReadRecordingEvents(bobCtx, bob, "demo")
	if err != nil || len(isolated) != 0 {
		t.Fatalf("cross-user recording visible: %v", err)
	}
	if _, err = builder.ReadRecordingEvents(bobCtx, alice, "demo"); err == nil {
		t.Fatal("forged scope accepted")
	}
}
