package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
	"time"
)

func recordingFixtureOwner() (context.Context, RecordingOwner) {
	p, _ := auth.NewPrincipal("fixture", "", "record-owner", nil)
	p.ClientID = "fixture-client"
	return auth.WithPrincipal(context.Background(), p), RecordingOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "owned-session"}
}
func recordingFixtureBatch(owner RecordingOwner, id string, from, to, last uint64, state string) RecordBatch {
	batch := RecordBatch{Owner: owner, RecordingID: id, State: state, LeaseExpiresUnixMS: time.Now().Add(time.Second * 20).UnixMilli(), LastSequence: last}
	for seq := from; seq <= to; seq++ {
		batch.Events = append(batch.Events, RecordEvent{RecordingID: id, Sequence: seq, TimestampUnixMS: time.Now().UnixMilli(), Kind: "start", Source: "nativeAX", Lineage: fmt.Sprintf("%s:native:%d", id, seq)})
	}
	return batch
}
func TestNativeRecordingDeliveryCursorDoesNotConsumeRenewAndDrainsTrailing(t *testing.T) {
	ctx, owner := recordingFixtureOwner()
	id := "owned-recording"
	var nonce string
	stopped := false
	pollAfter := []uint64{}
	transport := newRecordingTransport(owner, 501, func(_ context.Context, req Request) (Reply, error) {
		if req.Method == "doctor" {
			return Reply{HelperEpoch: "epoch"}, nil
		}
		var params map[string]any
		_ = json.Unmarshal(req.Params, &params)
		if params["namespace"] != owner.Namespace || params["clientId"] != owner.ClientID || params["sessionId"] != owner.SessionID {
			t.Fatal("request-selected recording owner")
		}
		actual := params["consentNonce"].(string)
		if nonce == "" {
			nonce = actual
		}
		if actual != nonce || len(nonce) != 64 {
			t.Fatal("nonce correlation changed")
		}
		after := uint64(0)
		if value, ok := params["afterSequence"].(float64); ok {
			after = uint64(value)
		}
		if req.Method == "record.stop" {
			stopped = true
		}
		if req.Method == "record.events" || req.Method == "record.stop" {
			pollAfter = append(pollAfter, after)
		}
		end := after + 64
		if end > 150 {
			end = 150
		}
		state := "recording"
		if stopped {
			state = "stopped"
		}
		b := recordingFixtureBatch(owner, id, after+1, end, 150, state)
		payload, _ := json.Marshal(b)
		return Reply{HelperEpoch: "epoch", Result: payload}, nil
	})
	b, err := transport.start(ctx, RecordingStart{RecordingID: id, MaxEvents: 4096, MaxDurationMS: 60000, GrantExpiresAt: time.Now().Add(time.Minute)})
	if err != nil || len(b.Events) != 64 {
		t.Fatalf("start %v", err)
	}
	if _, err = transport.control(ctx, id, "record.renew", 0, 64, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	b, err = transport.control(ctx, id, "record.stop", 0, 64, time.Time{})
	if err != nil || b.Events[0].Sequence != 65 || b.Events[63].Sequence != 128 {
		t.Fatalf("trailing stop lost events: %v", err)
	}
	b, err = transport.control(ctx, id, "record.events", 128, 64, time.Time{})
	if err != nil || len(b.Events) != 22 || b.Events[0].Sequence != 129 || b.LastSequence != 150 {
		t.Fatalf("drain %v", err)
	}
	if len(pollAfter) != 2 || pollAfter[0] != 64 || pollAfter[1] != 128 {
		t.Fatalf("cursor %v", pollAfter)
	}
	wrong, _ := auth.NewPrincipal("fixture", "", "other", nil)
	if _, err = transport.control(auth.WithPrincipal(context.Background(), wrong), id, "record.stop", 0, 64, time.Time{}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign principal stopped recording")
	}
}
func TestNativeRecordingRejectsRawValuesAndPreservesNativeMetadata(t *testing.T) {
	_, owner := recordingFixtureOwner()
	b := recordingFixtureBatch(owner, "fixture", 1, 1, 1, "recording")
	digest := strings.Repeat("a", 64)
	window := "42"
	b.Events[0].Kind = "fill"
	b.Events[0].Redacted = true
	b.Events[0].ParameterRequired = true
	b.Events[0].NativeIdentity = &RecordNativeIdentity{UID: 501, BundleID: "com.example.Editor", PID: 44, StartToken: "1790000000:1", WindowID: &window}
	b.Events[0].Target = &RecordNativeTarget{Role: "AXTextField", IdentifierDigest: &digest, NameWithheld: true}
	b.Events[0].Locator = &RecordLocator{Strategy: "idDigest", Value: digest, Exact: true}
	payload, _ := json.Marshal(b)
	decoded, err := decodeRecordBatch(payload, owner, 501, "fixture", 0, 64)
	if err != nil || decoded.Events[0].NativeIdentity.WindowID == nil || *decoded.Events[0].Target.IdentifierDigest != digest || !decoded.Events[0].ParameterRequired {
		t.Fatalf("native metadata dropped %v", err)
	}
	var object map[string]any
	_ = json.Unmarshal(payload, &object)
	event := object["events"].([]any)[0].(map[string]any)
	for _, field := range []string{"value", "text", "clipboard", "identity"} {
		event[field] = "private-data"
		raw, _ := json.Marshal(object)
		if result, err := decodeRecordBatch(raw, owner, 501, "fixture", 0, 64); err == nil || len(result.Events) != 0 {
			t.Fatalf("raw/foreignfield %s leaked", field)
		}
		delete(event, field)
	}
	event["trusted"] = true
	raw, _ := json.Marshal(object)
	if _, err = decodeRecordBatch(raw, owner, 501, "fixture", 0, 64); err == nil {
		t.Fatal("physical provenance invented")
	}
}
func TestRecordingProfileRequiresTrustOwnerAndExcludesActions(t *testing.T) {
	_, owner := recordingFixtureOwner()
	for _, opts := range []Options{{HelperPath: "/must-not-launch", AllowRecording: true}, {HelperPath: "/must-not-launch", AllowRecording: true, RecordingOwner: &owner}, {HelperPath: "/must-not-launch", AllowRecording: true, RecordingOwner: &owner, AllowSemantic: true}} {
		client, err := NewClient(context.Background(), opts)
		if client != nil || err == nil {
			t.Fatal("recording profile gate bypass")
		}
	}
}
