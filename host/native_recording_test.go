package host

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
)

type passiveRecordingFixture struct {
	mu                            sync.Mutex
	owner                         native.RecordingOwner
	events                        []native.RecordEvent
	cursor                        uint64
	state                         string
	starts, stops, closes, renews int
	reapUnknown                   bool
	startErr                      error
}

func (f *passiveRecordingFixture) batch(after uint64, limit int) native.RecordBatch {
	b := native.RecordBatch{RecordingID: "fixture", State: f.state, Owner: f.owner, LeaseExpiresUnixMS: time.Now().Add(20 * time.Second).UnixMilli(), LastSequence: uint64(len(f.events))}
	for _, e := range f.events {
		if e.Sequence > after && len(b.Events) < limit {
			b.Events = append(b.Events, e)
		}
	}
	return b
}
func (f *passiveRecordingFixture) StartRecording(_ context.Context, in native.RecordingStart) (native.RecordBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.startErr != nil {
		return native.RecordBatch{}, f.startErr
	}
	f.state = "recording"
	b := f.batch(0, 64)
	f.cursor = uint64(len(b.Events))
	return b, nil
}
func (f *passiveRecordingFixture) RenewRecording(_ context.Context, _ string, _ time.Time) (native.RecordBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews++
	return f.batch(0, 64), nil
}
func (f *passiveRecordingFixture) PauseRecording(context.Context, string) (native.RecordBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = "paused"
	b := f.batch(f.cursor, 64)
	if len(b.Events) > 0 {
		f.cursor = b.Events[len(b.Events)-1].Sequence
	}
	return b, nil
}
func (f *passiveRecordingFixture) StopRecording(context.Context, string) (native.RecordBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	f.state = "stopped"
	b := f.batch(f.cursor, 64)
	if len(b.Events) > 0 {
		f.cursor = b.Events[len(b.Events)-1].Sequence
	}
	return b, nil
}
func (f *passiveRecordingFixture) RecordingEvents(_ context.Context, _ string, after uint64, limit int) (native.RecordBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.batch(after, limit)
	if len(b.Events) > 0 {
		f.cursor = b.Events[len(b.Events)-1].Sequence
	}
	return b, nil
}
func (f *passiveRecordingFixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}
func (f *passiveRecordingFixture) WaitStopped(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reapUnknown {
		return errors.New("fixture reap unavailable")
	}
	return nil
}
func passiveFixture(t *testing.T, count int) (*NativeRecordingManager, *passiveRecordingFixture, context.Context, auth.Principal, ConsentBinding, *consent.Lease, context.CancelFunc, *atomic.Int32) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "passive-owner", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	binding := ConsentBinding{GrantID: "grant", SessionID: "session", Purpose: "record fixture"}
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), binding)
	held, cancel := context.WithTimeout(ctx, time.Minute)
	released := new(atomic.Int32)
	lease := &consent.Lease{Context: held, Release: func() { released.Add(1); cancel() }}
	fixture := &passiveRecordingFixture{owner: native.RecordingOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: binding.SessionID}}
	for seq := 1; seq <= count; seq++ {
		fixture.events = append(fixture.events, native.RecordEvent{RecordingID: "fixture", Sequence: uint64(seq), TimestampUnixMS: time.Now().UnixMilli(), Kind: "start", Source: "nativeAX", Lineage: fmt.Sprintf("fixture:native:%d", seq)})
	}
	uid := uint32(501)
	manager, err := NewNativeRecordingManager(NativeRecordingOptions{Owner: context.Background(), HelperPath: "/fixture/helper", Requirement: "fixture signed requirement", ExpectedUID: &uid, Factory: func(actual context.Context, opts native.Options) (NativeRecordingHelper, error) {
		if !opts.AllowRecording || opts.AllowMutations || opts.AllowLaunch || opts.AllowSemantic || opts.Fence != nil || opts.RecordingOwner == nil || *opts.RecordingOwner != fixture.owner {
			t.Error("passive factory borrowed action authority")
		}
		if recordingPrincipal(actual, p) != nil {
			t.Error("factory principal lost")
		}
		return fixture, nil
	}, Revalidate: func(context.Context, auth.Principal) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = manager.Close(context.Background()) })
	return manager, fixture, ctx, p, binding, lease, cancel, released
}
func TestPassiveNativeStopPreservesTrailingPagesAndReleasesAfterFinish(t *testing.T) {
	m, f, ctx, p, binding, lease, _, released := passiveFixture(t, 170)
	batch, err := m.Start(ctx, p, binding, "fixture", lease, 60000, 4096)
	if err != nil || len(batch.Events) != 64 {
		t.Fatalf("start: %v", err)
	}
	batch, err = m.Stop(ctx, p, "fixture")
	if err != nil || batch.Events[0].Sequence != 65 || batch.LastSequence != 170 {
		t.Fatalf("stop dropped trailing events: %+v %v", batch, err)
	}
	if released.Load() != 0 {
		t.Fatal("normal stop released before journal persistence")
	}
	batch, err = m.Events(ctx, p, "fixture", 128, 64)
	if err != nil || len(batch.Events) != 42 || batch.Events[0].Sequence != 129 {
		t.Fatalf("stopped journal drain: %v", err)
	}
	if err = m.Finish(ctx, p, "fixture"); err != nil {
		t.Fatal(err)
	}
	if released.Load() != 1 {
		t.Fatalf("lease release count=%d", released.Load())
	}
	f.mu.Lock()
	closes := f.closes
	f.mu.Unlock()
	if closes != 1 {
		t.Fatalf("helper not reaped: %d", closes)
	}
}
func TestPassiveNativeCancellationStopsReapsAndCachesWithoutMCPPoll(t *testing.T) {
	m, f, ctx, p, binding, lease, cancel, released := passiveFixture(t, 170)
	if _, err := m.Start(ctx, p, binding, "fixture", lease, 60000, 4096); err != nil {
		t.Fatal(err)
	}
	cancel()
	end := time.Now().Add(2 * time.Second)
	for released.Load() == 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatal("lease cancellation needed an MCP poll to stop capture")
	}
	f.mu.Lock()
	stops, closes := f.stops, f.closes
	f.mu.Unlock()
	if stops == 0 || closes == 0 {
		t.Fatal("source did not stop and reap")
	}
	// Completed cache contains all pages in order, including early and trailing.
	after := uint64(0)
	total := 0
	for page := 0; page < 4; page++ {
		batch, err := m.Events(ctx, p, "fixture", after, 64)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range batch.Events {
			if event.Sequence != after+1 {
				t.Fatalf("cache order/gap=%d after=%d", event.Sequence, after)
			}
			after = event.Sequence
			total++
		}
		if after == batch.LastSequence {
			break
		}
	}
	if total != 170 {
		t.Fatalf("cached events=%d", total)
	}
}
func TestPassiveNativeUncertainReapRetainsLeaseAndSignalsGap(t *testing.T) {
	m, f, ctx, p, binding, lease, _, released := passiveFixture(t, 1)
	f.mu.Lock()
	f.reapUnknown = true
	f.startErr = errors.New("fixture start uncertain")
	f.mu.Unlock()
	if _, err := m.Start(ctx, p, binding, "fixture", lease, 60000, 4096); !errors.Is(err, ErrNativeRecordingCleanupUnknown) {
		t.Fatalf("uncertain start cleanup=%v", err)
	}
	if released.Load() != 0 {
		t.Fatal("unreaped helper released grant")
	}
	batch, err := m.Events(ctx, p, "fixture", 0, 64)
	if err != nil || batch.State != "stopUnconfirmed" || len(batch.Gaps) == 0 {
		t.Fatalf("cleanup uncertainty lost %+v %v", batch, err)
	}
	f.mu.Lock()
	f.reapUnknown = false
	f.mu.Unlock()
	_ = m.Finish(ctx, p, "fixture")
	if released.Load() != 1 {
		t.Fatal("late confirmed reap did not release")
	}
}
func TestPassiveNativePrincipalSessionAndLeaseOwnershipAreExact(t *testing.T) {
	m, _, ctx, p, binding, lease, _, _ := passiveFixture(t, 1)
	if _, err := m.Start(ctx, p, binding, "fixture", lease, 60000, 4096); err != nil {
		t.Fatal(err)
	}
	other, _ := auth.NewPrincipal("fixture", "", "other", []string{"desktop:control"})
	if _, err := m.Events(auth.WithPrincipal(context.Background(), other), other, "fixture", 0, 64); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign namespace read")
	}
	changed := binding
	changed.SessionID = "other-session"
	if _, err := m.Pause(auth.WithConsentBinding(ctx, changed), p, "fixture"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign session paused")
	}
	if _, err := m.Start(ctx, p, binding, "second", &consent.Lease{Context: context.Background(), Release: func() {}}, 60000, 4096); err == nil {
		t.Fatal("unbound grant invented")
	}
}
