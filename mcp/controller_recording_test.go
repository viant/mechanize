package mcp

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data/recordevents"
	"github.com/viant/mechanize/engine/recording"
	"github.com/viant/mechanize/model"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type controllerRecorder struct{ calls atomic.Int32 }

func (b *controllerRecorder) StartRecording(_ context.Context, _ auth.Principal, s model.Surface, id string) (chrome.RecordBatch, error) {
	value := "private-recording-value-canary"
	return chrome.RecordBatch{RecordingID: id, State: "recording", LastSequence: 1, Events: []chrome.RecordEvent{{Sequence: 1, Kind: "fill", Trusted: true, Identity: chrome.Identity{ProfileChannel: "fixture", BrowserInstance: "browser", TabID: 1, DocumentID: "doc", Generation: 1}, Origin: s.Origin, Value: &value, Locator: &chrome.Locator{Strategy: "testId", Value: "field"}}}}, nil
}
func (b *controllerRecorder) PauseRecording(_ context.Context, _ auth.Principal, id string) (chrome.RecordBatch, error) {
	b.calls.Add(1)
	return chrome.RecordBatch{RecordingID: id, State: "paused", LastSequence: 1}, nil
}
func (b *controllerRecorder) StopRecording(_ context.Context, _ auth.Principal, id string) (chrome.RecordBatch, error) {
	b.calls.Add(1)
	return chrome.RecordBatch{RecordingID: id, State: "stopped", LastSequence: 1}, nil
}
func (b *controllerRecorder) RecordingEvents(_ context.Context, _ auth.Principal, id string, _ uint64, _ int) (chrome.RecordBatch, error) {
	return chrome.RecordBatch{RecordingID: id, State: "recording", LastSequence: 1}, nil
}

func TestControllerOwnedRecordingControlsCanonicalRoundtrip(t *testing.T) {
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var rows []*recordevents.RecordedEvent
	components := recording.ComponentFuncs{AppendEvents: func(_ context.Context, _ auth.Principal, v []*recordevents.RecordedEvent) error {
		mu.Lock()
		defer mu.Unlock()
		rows = append(rows, v...)
		return nil
	}, ReadEvents: func(context.Context, auth.Principal, string) ([]*recordevents.RecordedEvent, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]*recordevents.RecordedEvent(nil), rows...), nil
	}}
	backend := &controllerRecorder{}
	service, err := recording.New(owner, backend, components)
	if err != nil {
		t.Fatal(err)
	}
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) { deps.Recording = service })
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "recording"}))["sessionId"].(string)
	grant := auth.ConsentBinding{SessionID: session, GrantID: "fixture-grant", Purpose: "Record fixture"}
	req := recording.StartRequest{RecordingID: "fixture", Consent: true, Surface: model.Surface{Kind: "web", Origin: "https://fixture.invalid", TabID: "fixture/browser/1"}, MaxDurationMs: 10000, MaxEvents: 64, Objective: &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "recorded"}, TimeoutMs: 1000, FreshnessMs: 100, RequiredAuthority: "authoritative"}}
	if _, err = service.Start(auth.WithConsentBinding(ctx, grant), id.Principal, req); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mechanize_record_status", "mechanize_record_pause", "mechanize_record_stop"} {
		out := controllerCall(t, d, ctx, id, name, RecordingRef{RecordingID: "fixture", SessionID: session})
		if out.IsError != nil && *out.IsError {
			t.Fatalf("%s failed: %+v", name, out)
		}
		body := controllerBody(t, out)
		raw, _ := json.Marshal(body)
		if len(body) > 6 || strings.Contains(string(raw), "canary") || body["recordingId"] != "fixture" {
			t.Fatal("recording private data escaped", string(raw))
		}
	}
	if backend.calls.Load() != 2 {
		t.Fatal("unexpected input count")
	}
	otherSession := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "different"}))["sessionId"].(string)
	for _, sessionID := range []string{"foreign-session", otherSession} {
		out := controllerCall(t, d, ctx, id, "mechanize_record_pause", RecordingRef{RecordingID: "fixture", SessionID: sessionID})
		if out.IsError == nil || !*out.IsError {
			t.Fatal("foreign recording session admitted")
		}
	}
	foreign := id
	foreign.Principal.ClientID = "controller:foreign"
	foreignCtx := auth.WithPrincipal(context.Background(), foreign.Principal)
	own := controllerBody(t, controllerCall(t, d, foreignCtx, foreign, "mechanize_session_open", map[string]any{"name": "foreign"}))["sessionId"].(string)
	for _, name := range []string{"mechanize_record_status", "mechanize_record_pause", "mechanize_record_stop"} {
		out := controllerCall(t, d, foreignCtx, foreign, name, RecordingRef{RecordingID: "fixture", SessionID: own})
		if out.IsError == nil || !*out.IsError {
			t.Fatal("foreign client admitted")
		}
	}
	if backend.calls.Load() != 2 {
		t.Fatal("denied ownership reached recorder")
	}
	// Persisted/restarted status retains the same client+session authority.
	restarted, _ := recording.New(owner, backend, components)
	if _, err := restarted.Status(auth.WithConsentBinding(foreignCtx, auth.ConsentBinding{SessionID: own}), foreign.Principal, "fixture"); err == nil {
		t.Fatal("restart lost client ownership")
	}
}

func TestControllerManualResumeCanonicalClosedContract(t *testing.T) {
	var calls atomic.Int32
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.CredentialResumeManual = func(c context.Context, p auth.Principal, in CredentialRefInput) (CredentialResult, error) {
			calls.Add(1)
			if auth.NativeHuman(c) || p.ClientID != "controller:fixture" {
				t.Fatal("principal changed")
			}
			return CredentialResult{PreparationID: in.PreparationID, State: "needsNativeAction", AttentionCode: "manualPrivacySourceTabPresent"}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "manual"}))["sessionId"].(string)
	out := controllerCall(t, d, ctx, id, "mechanize_credential_resume_manual", CredentialRefInput{SessionID: session, PreparationID: strings.Repeat("a", 64)})
	if out.IsError != nil && *out.IsError {
		t.Fatalf("manual status rejected: %+v", out)
	}
	if controllerBody(t, out)["attentionCode"] != "manualPrivacySourceTabPresent" {
		t.Fatal("closed reason lost")
	}
	out = controllerCall(t, d, ctx, id, "mechanize_credential_resume_manual", CredentialRefInput{SessionID: "foreign", PreparationID: strings.Repeat("a", 64)})
	if out.IsError == nil || !*out.IsError || calls.Load() != 1 {
		t.Fatal("foreign session reached private callback")
	}
	out = controllerCall(t, d, ctx, id, "mechanize_credential_resume_manual", map[string]any{"sessionId": session, "preparationId": strings.Repeat("a", 64), "password": "private-canary"})
	if out.IsError == nil || !*out.IsError || calls.Load() != 1 {
		t.Fatal("extra private input admitted")
	}
}
