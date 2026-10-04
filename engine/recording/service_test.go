package recording

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data/recordevents"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

type fixtureBackend struct{ stopErr error }

func (f fixtureBackend) StartRecording(ctx context.Context, p auth.Principal, s model.Surface, id string) (chrome.RecordBatch, error) {
	secret := "SEEDED_RAW_SECRET"
	return chrome.RecordBatch{RecordingID: id, State: "recording", LastSequence: 1, Events: []chrome.RecordEvent{{Sequence: 1, Kind: "fill", Trusted: true, Identity: chrome.Identity{ProfileChannel: "fixture", BrowserInstance: "browser", TabID: 1, DocumentID: "doc", Generation: 1}, Origin: s.Origin, Value: &secret, Locator: &chrome.Locator{Strategy: "testId", Value: "field"}}}}, nil
}
func (f fixtureBackend) PauseRecording(context.Context, auth.Principal, string) (chrome.RecordBatch, error) {
	return chrome.RecordBatch{State: "paused", LastSequence: 1}, nil
}
func (f fixtureBackend) StopRecording(context.Context, auth.Principal, string) (chrome.RecordBatch, error) {
	return chrome.RecordBatch{State: "stopped", LastSequence: 1}, f.stopErr
}
func (f fixtureBackend) RecordingEvents(context.Context, auth.Principal, string, uint64, int) (chrome.RecordBatch, error) {
	return chrome.RecordBatch{State: "recording", LastSequence: 1}, nil
}
func TestCapturePersistsRedactedAndRestartIsConservative(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:read", "desktop:control"})
	p.ClientID = "recording-agent"
	p.ClientName = "Recording Agent"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "fixture-session", GrantID: "fixture-grant", Purpose: "Record fixture"})
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rows []*recordevents.RecordedEvent
	components := ComponentFuncs{AppendEvents: func(_ context.Context, _ auth.Principal, v []*recordevents.RecordedEvent) error {
		rows = append(rows, v...)
		return nil
	}, ReadEvents: func(_ context.Context, _ auth.Principal, id string) ([]*recordevents.RecordedEvent, error) {
		return rows, nil
	}}
	s, _ := New(owner, fixtureBackend{stopErr: errors.New("offline")}, components)
	req := StartRequest{RecordingID: "fixture", Consent: true, Surface: model.Surface{Kind: "web", Origin: "https://fixture.invalid", TabID: "fixture/browser/1"}, MaxDurationMs: 10000, MaxEvents: 64, Objective: &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "recorded"}, TimeoutMs: 1000, FreshnessMs: 100, RequiredAuthority: "authoritative"}}
	if _, e := s.Start(ctx, p, req); e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "SEEDED_RAW_SECRET") {
		t.Fatal("raw text persisted")
	}
	restarted, _ := New(owner, fixtureBackend{}, components)
	status, e := restarted.Status(ctx, p, "fixture")
	if e != nil || status.State != "interrupted" || status.CoverageComplete {
		t.Fatalf("restart: %+v %v", status, e)
	}
	status, e = s.Stop(ctx, p, "fixture")
	if e == nil || status.State != "interrupted" || !strings.Contains(status.Reason, "controlUnconfirmed") {
		t.Fatalf("failed stop: %+v %v", status, e)
	}
	out, e := s.Export(ctx, p, ExportRequest{RecordingID: "fixture", Reviewed: true})
	if e != nil || len(out.Report.Gaps) == 0 || out.Report.BusinessSuccess {
		t.Fatalf("export: %+v %v", out, e)
	}
	other, _ := auth.NewPrincipal("fixture", "", "bob", p.Scopes)
	if _, e = s.Status(ctx, other, "fixture"); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatalf("cross namespace: %v", e)
	}
}
