package recording

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data/recordevents"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
)

type commonBackendFixture struct {
	events                    []record.RecordEvent
	started, stops, finalized int
	duration                  int64
	limit                     int
	missing                   bool
}

func (f *commonBackendFixture) StartRecording(ctx context.Context, p auth.Principal, s model.Surface, id string) (record.RecordBatch, error) {
	f.started++
	return record.RecordBatch{RecordingID: id, State: "recording"}, nil
}
func (f *commonBackendFixture) StartRecordingWithLimits(ctx context.Context, p auth.Principal, s model.Surface, id string, duration int64, limit int) (record.RecordBatch, error) {
	f.duration = duration
	f.limit = limit
	return f.StartRecording(ctx, p, s, id)
}
func (f *commonBackendFixture) PauseRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	return f.page(id, 0, "paused"), nil
}
func (f *commonBackendFixture) StopRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	f.stops++
	return f.page(id, 0, "stopped"), nil
}
func (f *commonBackendFixture) RecordingEvents(ctx context.Context, p auth.Principal, id string, after uint64, limit int) (record.RecordBatch, error) {
	if f.missing {
		return record.RecordBatch{RecordingID: id, State: "stopped", LastSequence: uint64(len(f.events))}, nil
	}
	return f.page(id, after, "stopped"), nil
}
func (f *commonBackendFixture) FinishRecording(context.Context, auth.Principal, string) error {
	f.finalized++
	return nil
}
func (f *commonBackendFixture) page(id string, after uint64, state string) record.RecordBatch {
	batch := record.RecordBatch{RecordingID: id, State: state, LastSequence: uint64(len(f.events))}
	for _, event := range f.events {
		if event.Sequence > after && len(batch.Events) < 64 {
			event.RecordingID = id
			batch.Events = append(batch.Events, event)
		}
	}
	return batch
}
func recordingTestActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "common-recorder", []string{"desktop:observe", "desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "first-agent"
	p.ClientName = "First Agent"
	return auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "record-session", GrantID: "record-grant", Purpose: "Record demonstration"}), p
}
func commonStart() StartRequest {
	return StartRequest{RecordingID: "common-demo", Consent: true, Surface: model.Surface{Kind: "desktop"}, MaxEvents: 256, MaxDurationMs: 60000, Objective: &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "complete", RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000, Scope: model.PredicateScope{Target: &model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.apple.Calculator"}, Cardinality: "one"}}}}
}
func commonNative(sequence uint64, bundle, kind string) record.RecordEvent {
	return record.RecordEvent{EventSurface: "native", Sequence: sequence, Kind: kind, NativeIdentity: &record.NativeIdentity{UID: 501, BundleID: bundle, PID: 101, StartToken: "native-start", WindowID: "12"}, NativeTarget: &record.NativeTarget{Role: "AXButton", IdentifierDigest: strings.Repeat("a", 64), NameWithheld: true}, Source: "nativeAX", Lineage: bundle + "/event", Redacted: true}
}
func memoryComponents(rows *[]*recordevents.RecordedEvent) ComponentFuncs {
	return ComponentFuncs{AppendEvents: func(ctx context.Context, p auth.Principal, input []*recordevents.RecordedEvent) error {
		*rows = append(*rows, input...)
		return nil
	}, ReadEvents: func(ctx context.Context, p auth.Principal, id string) ([]*recordevents.RecordedEvent, error) {
		return *rows, nil
	}}
}
func TestAutomaticStopDrainsMoreThanOnePageAndFinalizes(t *testing.T) {
	ctx, p := recordingTestActor(t)
	backend := &commonBackendFixture{}
	for sequence := uint64(1); sequence <= 130; sequence++ {
		backend.events = append(backend.events, commonNative(sequence, "com.apple.Calculator", "press"))
	}
	var rows []*recordevents.RecordedEvent
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := New(owner, backend, memoryComponents(&rows))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Start(ctx, p, commonStart()); err != nil {
		t.Fatal(err)
	}
	live, err := service.live(ctx, p, "common-demo")
	if err != nil {
		t.Fatal(err)
	}
	live.mu.Lock()
	live.end = time.Now().Add(-time.Second)
	err = service.pollLocked(ctx, live)
	state := live.status
	live.mu.Unlock()
	if err != nil || state.State != "stopped" || state.PersistedEvents != 130 || state.LastSequence != 130 || backend.finalized != 1 || backend.duration != 60000 || backend.limit != 256 {
		t.Fatalf("automaticdrain %+v err=%v finalizers=%d", state, err, backend.finalized)
	}
	restarted, err := New(owner, backend, memoryComponents(&rows))
	if err != nil {
		t.Fatal(err)
	}
	exported, err := restarted.Export(ctx, p, ExportRequest{RecordingID: "common-demo", Reviewed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.DraftActions) != 130 || len(exported.Plan.Steps) != 0 || exported.DraftActions[0].NativeIdentity.StartToken != "native-start" {
		t.Fatalf("nativejournal identity/draft dropped %+v", exported)
	}
}
func TestTerminalPollAndFaultStopShareFinalization(t *testing.T) {
	for _, mode := range []string{"terminal", "gap", "persistence"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := recordingTestActor(t)
			backend := &commonBackendFixture{events: []record.RecordEvent{commonNative(1, "com.apple.Calculator", "press")}}
			var rows []*recordevents.RecordedEvent
			components := memoryComponents(&rows)
			owner, cancel := context.WithCancel(context.Background())
			defer cancel()
			service, _ := New(owner, backend, components)
			if _, err := service.Start(ctx, p, commonStart()); err != nil {
				t.Fatal(err)
			}
			live, _ := service.live(ctx, p, "common-demo")
			if mode == "gap" {
				backend.missing = true
			}
			if mode == "persistence" {
				service.components = ComponentFuncs{AppendEvents: func(context.Context, auth.Principal, []*recordevents.RecordedEvent) error {
					return errors.New("journal outage")
				}, ReadEvents: components.ReadEvents}
			}
			live.mu.Lock()
			err := service.pollLocked(ctx, live)
			state := live.status
			live.mu.Unlock()
			if backend.finalized != 1 {
				t.Fatalf("terminal/fault helperretained finalizers=%d err=%v", backend.finalized, err)
			}
			if mode != "terminal" && (err == nil || state.State != "interrupted" || state.CoverageComplete) {
				t.Fatalf("fault falselycomplete %+v %v", state, err)
			}
		})
	}
}
func TestRecorderChecksClientAndSessionForLiveAndRestartAccess(t *testing.T) {
	ctx, p := recordingTestActor(t)
	backend := &commonBackendFixture{events: []record.RecordEvent{commonNative(1, "com.apple.Calculator", "press")}}
	var rows []*recordevents.RecordedEvent
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, _ := New(owner, backend, memoryComponents(&rows))
	if _, err := service.Start(ctx, p, commonStart()); err != nil {
		t.Fatal(err)
	}
	other := p
	other.ClientID = "other-client"
	other.ClientName = "Other Client"
	otherCtx := auth.WithPrincipal(ctx, other)
	if _, err := service.Stop(otherCtx, other, "common-demo"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("sameuser otherclient controlledrecording %v", err)
	}
	wrongSession := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "another-session"})
	if _, err := service.Status(wrongSession, p, "common-demo"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("foreignsession status %v", err)
	}
	if _, err := service.Stop(ctx, p, "common-demo"); err != nil {
		t.Fatal(err)
	}
	restarted, _ := New(owner, backend, memoryComponents(&rows))
	if _, err := restarted.Export(otherCtx, other, ExportRequest{RecordingID: "common-demo"}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("persistedowner dropped %v", err)
	}
	// Missing legacy client evidence must not silently become same-user approval.
	var intent envelope
	if err := json.Unmarshal([]byte(*rows[0].PayloadJson), &intent); err != nil {
		t.Fatal(err)
	}
	intent.VerifiedClientID = ""
	encoded, _ := json.Marshal(intent)
	text := string(encoded)
	rows[0].PayloadJson = &text
	if _, err := restarted.Status(ctx, p, "common-demo"); err == nil {
		t.Fatal("legacyunownedjournal became privateclientrecord")
	}
}
func TestNativeAndWebEnvelopeSurvivesGeneratedDatlyRestart(t *testing.T) {
	ctx, p := recordingTestActor(t)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	storage := t.TempDir()
	newBuilder := func() *durable.Builder {
		builder, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
			return automation.StepResult{}, errors.New("recordingfixturecannotdispatch")
		})
		if err != nil {
			t.Fatal(err)
		}
		return builder
	}
	builder := newBuilder()
	backend := &commonBackendFixture{events: []record.RecordEvent{commonNative(1, "com.apple.Calculator", "press"), commonNative(2, "com.apple.finder", "fill"), {EventSurface: "web", Sequence: 3, Kind: "press", Identity: &chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 4, DocumentID: "doc", Generation: 1}, Origin: "https://example.test", Locator: &chrome.Locator{Strategy: "testId", Value: "submit", Exact: true}, Source: "chromeDOM", Trusted: true, Lineage: "web/event"}}}
	owner, cancel := context.WithCancel(context.Background())
	service, err := New(owner, backend, ComponentFuncs{AppendEvents: builder.AppendRecordingEvents, ReadEvents: builder.ReadRecordingEvents})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Start(ctx, p, commonStart()); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Stop(ctx, p, "common-demo"); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = builder.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := newBuilder()
	defer recovered.Close(context.Background())
	restarted, err := New(context.Background(), backend, ComponentFuncs{AppendEvents: recovered.AppendRecordingEvents, ReadEvents: recovered.ReadRecordingEvents})
	if err != nil {
		t.Fatal(err)
	}
	exported, err := restarted.Export(ctx, p, ExportRequest{RecordingID: "common-demo", Reviewed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.DraftActions) != 3 || len(exported.Plan.Steps) != 1 || exported.DraftActions[1].NativeIdentity.BundleID != "com.apple.finder" || exported.DraftActions[2].CapturedKind != "press" {
		t.Fatalf("generatedrestart envelope lost %+v", exported)
	}
	other, _ := auth.NewPrincipal("fixture", "", "other-user", p.Scopes)
	other.ClientID = p.ClientID
	other.ClientName = p.ClientName
	otherCtx := auth.WithPrincipal(ctx, other)
	if _, err = restarted.Export(otherCtx, other, ExportRequest{RecordingID: "common-demo"}); err == nil {
		t.Fatal("crossnamespace journalvisible")
	}
}
