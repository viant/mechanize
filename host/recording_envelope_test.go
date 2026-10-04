package host

import (
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

func TestNativeRecordingEnvelopePreservesIdentityAndWithheldTarget(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	p.ClientID = "verified-client"
	window, digest := "42", strings.Repeat("a", 64)
	batch := native.RecordBatch{Owner: native.RecordingOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "owned-session"}, RecordingID: "demo", State: "recording", LastSequence: 1, Events: []native.RecordEvent{{RecordingID: "demo", Sequence: 1, Kind: "fill", Redacted: true, ParameterRequired: true, Source: "nativeAX", NativeIdentity: &native.RecordNativeIdentity{UID: 501, BundleID: "com.apple.finder", PID: 12, StartToken: "process-start", WindowID: &window}, Target: &native.RecordNativeTarget{Role: "AXTextField", IdentifierDigest: &digest, NameWithheld: true}}}, Gaps: []native.RecordGap{{Kind: "gap", Reason: "unsupportedAction", FromSequence: 1, ToSequence: 1, UnknownExtent: true}}}
	got, err := nativeRecordingEnvelope(batch, p, "owned-session", 501)
	if err != nil {
		t.Fatal(err)
	}
	e := got.Events[0]
	if e.NativeIdentity == nil || e.NativeIdentity.WindowID != window || e.NativeIdentity.StartToken != "process-start" || e.NativeTarget == nil || e.NativeTarget.IdentifierDigest != digest || !e.ParameterRequired || e.Identity != nil || e.Value != nil || e.Trusted || e.SourceAttested || len(got.Gaps) != 1 || !got.Gaps[0].UnknownExtent {
		t.Fatalf("lost native evidence or promoted trust: %+v", got)
	}
	for _, owner := range []native.RecordingOwner{
		{Namespace: p.Namespace, ClientID: "other-client", SessionID: "owned-session"},
		{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "other-session"},
	} {
		batch.Owner = owner
		if _, err := nativeRecordingEnvelope(batch, p, "owned-session", 501); err == nil {
			t.Fatal("foreign recording owner accepted")
		}
	}
	batch.Owner = native.RecordingOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "owned-session"}
	if _, err := nativeRecordingEnvelope(batch, p, "owned-session", 502); err == nil {
		t.Fatal("foreign desktop user accepted")
	}
}
