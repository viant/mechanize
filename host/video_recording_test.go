package host

import (
	"bytes"
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
	"image"
	"image/jpeg"
	"testing"
	"time"
)

func videoFixture(t *testing.T) (*VideoFrameIngestor, context.Context, []byte) {
	artifacts, ctx, p, _, _ := artifactFixture(t)
	p.ClientID = "fixture-client"
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "video demo"}
	ctx = auth.WithConsentBinding(auth.WithPrincipal(ctx, p), binding)
	leaseCtx, cancel := context.WithTimeout(ctx, time.Minute)
	t.Cleanup(cancel)
	var pixels bytes.Buffer
	if err := jpeg.Encode(&pixels, image.NewRGBA(image.Rect(0, 0, 2, 2)), nil); err != nil {
		t.Fatal(err)
	}
	v, err := NewVideoFrameIngestor(VideoIngestOptions{Artifacts: artifacts, Principal: p, Binding: binding, Lease: &consent.Lease{Context: leaseCtx, Release: func() {}}, Surface: model.Surface{Kind: "desktop"}, RecordingID: "demo", MaxDuration: time.Minute, MaxBytes: 1024, MaxFrames: 2, VerifyRecord: func(context.Context, auth.Principal, auth.ConsentBinding, model.Surface) error { return nil }, Redact: func(_ context.Context, b []byte) ([]byte, error) { return b, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return v, ctx, pixels.Bytes()
}
func TestVideoEncryptedFramePublicationAndOwnership(t *testing.T) {
	v, ctx, pixels := videoFixture(t)
	foreign, _ := auth.NewPrincipal("fixture", "tenant", "bob", nil)
	foreign.ClientID = "fixture-client"
	if v.Ingest(auth.WithPrincipal(ctx, foreign), record.VideoFrameEvidence{Sequence: 1, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil {
		t.Fatal("foreign identity accepted")
	}
	if err := v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 1, TimestampUnixMS: time.Now().UnixMilli()}, pixels); err != nil {
		t.Fatal(err)
	}
	snapshot := v.Snapshot()
	if len(snapshot.Frames) != 1 || snapshot.Frames[0].Artifact.KeyReference == "" {
		t.Fatalf("missing encrypted artifact %+v", snapshot)
	}
	got, err := v.options.Artifacts.Read(ctx, v.options.Principal, snapshot.Frames[0].Artifact)
	if err != nil || !bytes.Equal(got, pixels) {
		t.Fatalf("artifact read %v", err)
	}
	v.Revoke()
	if v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 2, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil {
		t.Fatal("revoked ingest accepted")
	}
	v.Stop(false)
	if v.Snapshot().State != "stopUnconfirmed" {
		t.Fatal("cleanup uncertainty hidden")
	}
}
func TestVideoRedactionAndUnknownPublicationPause(t *testing.T) {
	v, ctx, pixels := videoFixture(t)
	v.options.Redact = func(context.Context, []byte) ([]byte, error) { return nil, nil }
	if v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 1, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil || len(v.Snapshot().Frames) != 0 || v.Snapshot().State != "paused" {
		t.Fatal("redaction did not fail closed")
	}
	v, ctx, pixels = videoFixture(t)
	v.options.Artifacts.options.Publish = func(context.Context, auth.Principal, data.ArtifactReference) error { return errors.New("unknown") }
	if v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 1, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil || len(v.Snapshot().Frames) != 1 || v.Snapshot().State != "paused" {
		t.Fatal("unknown publication lost durable artifact or allowed retry")
	}
}

func TestVideoInvalidLineageAndGrantFailBeforePersistence(t *testing.T) {
	v, ctx, pixels := videoFixture(t)
	if v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 2, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil || len(v.Snapshot().Frames) != 0 {
		t.Fatal("invalid lineage persisted")
	}
	v, ctx, pixels = videoFixture(t)
	v.options.VerifyRecord = func(context.Context, auth.Principal, auth.ConsentBinding, model.Surface) error {
		return auth.ErrUnauthorized
	}
	if v.Ingest(ctx, record.VideoFrameEvidence{Sequence: 1, TimestampUnixMS: time.Now().UnixMilli()}, pixels) == nil || len(v.Snapshot().Frames) != 0 || v.Snapshot().State != "paused" {
		t.Fatal("withdrawn grant persisted")
	}
	v, ctx, _ = videoFixture(t)
	v.options.VerifyRecord = func(context.Context, auth.Principal, auth.ConsentBinding, model.Surface) error {
		return auth.ErrUnauthorized
	}
	if _, err := NewVideoFrameIngestor(v.options); err == nil {
		t.Fatal("unverified pixel-record grant started")
	}
}
