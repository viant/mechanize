package record

import (
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

func timelineFixture() VideoTimeline {
	return VideoTimeline{RecordingID: "demo", State: "stopped", Frames: []VideoFrameEvidence{{Sequence: 1, TimestampUnixMS: 1000, OffsetNanoseconds: 0, DisplayID: 1, Artifact: data.ArtifactReference{ID: "frame", ContentHash: strings.Repeat("a", 64), SizeBytes: 100, MediaType: "image/jpeg", KeyReference: "key"}}}}
}
func TestVideoCorrelationRejectsMixedRecordingAndClockClaims(t *testing.T) {
	video := timelineFixture()
	events := []RecordEvent{{EventSurface: "native", RecordingID: "demo", Sequence: 1, TimestampUnixMS: 1000, Kind: "start", Lineage: "demo:native:1"}}
	links, err := CorrelateVideo(events, video, 100)
	if err != nil || len(links[0].Frames) != 1 || links[0].Correlation != "temporalContextOnly" {
		t.Fatalf("%+v %v", links, err)
	}
	events[0].RecordingID = "foreign"
	if _, err = CorrelateVideo(events, video, 100); err == nil {
		t.Fatal("foreign recording accepted")
	}
	video.Frames = append(video.Frames, video.Frames[0])
	video.Frames[1].Sequence = 2
	video.Frames[1].OffsetNanoseconds = 1000000
	if video.Validate() == nil {
		t.Fatal("clock inconsistency accepted")
	}
	video = timelineFixture()
	video.AudioCaptured = true
	if video.Validate() == nil {
		t.Fatal("audio accepted")
	}
}
func TestBusinessDraftPreservesObservedAndProposedBoundaries(t *testing.T) {
	batch := RecordBatch{RecordingID: "demo", State: "stopped", Events: []RecordEvent{{EventSurface: "native", RecordingID: "demo", Sequence: 1, TimestampUnixMS: 1000, Kind: "press", Lineage: "demo:native:1", Source: "nativeAX", NativeIdentity: &NativeIdentity{BundleID: "com.example.App", PID: 1, StartToken: "token", WindowID: "42"}, NativeTarget: &NativeTarget{Role: "AXButton", NameWithheld: true}}}}
	draft, err := DraftBusinessFlow("Submit reviewed order", Request{Name: "demo", Surface: model.Surface{Kind: "desktop"}}, batch, timelineFixture())
	if err != nil {
		t.Fatal(err)
	}
	if draft.BusinessSuccess || draft.SystemRollbackAvailable || draft.Qualification != "unqualified" || len(draft.Decisions) != 0 || draft.GoalStatus != "userDeclared" {
		t.Fatalf("unsupported business claim %+v", draft)
	}
	if len(draft.Steps) != 1 || draft.Steps[0].Status != "observedUnattested" || len(draft.Steps[0].Evidence.Frames) != 1 {
		t.Fatalf("missing evidence %+v", draft.Steps)
	}
}
