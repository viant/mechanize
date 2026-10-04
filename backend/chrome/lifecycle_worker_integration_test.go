package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/mechanize/data"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLifecycleJournalActualWorkerContract(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for actual worker contract fixture")
	}
	fence := LifecycleJournalFence{"broker", "channel", strings.Repeat("a", 64)}
	channel := LifecycleJournalChannel{"p1", "b1"}
	identity := Identity{ProfileChannel: "p1", BrowserInstance: "b1"}
	envelope := LifecycleJournalEnvelope{Version: 2, Complete: true, Executors: []data.ChromeRetirementManifest{}}
	preparation := LifecycleJournalPreparation{TransitionID: "transition", Manifest: envelope, EnvelopeDigest: data.ChromeRetirementDigest(envelope), HostResolutionDigest: strings.Repeat("b", 64)}
	commands := []any{}
	for index, action := range []string{"retirement.intend", "retirement.prepare", "retirement.status"} {
		args := map[string]any{"channel": channel, "transitionId": "transition", "oldFence": fence, "expectedRevision": index}
		if index == 1 {
			args["manifest"] = envelope
			args["envelopeDigest"] = preparation.EnvelopeDigest
			args["hostResolutionDigest"] = preparation.HostResolutionDigest
		}
		if index == 2 {
			args = map[string]any{"profileChannel": "p1", "browserInstance": "b1"}
		}
		id := []string{"intend", "prepare", "status"}[index]
		commands = append(commands, struct {
			Command
			Type    string `json:"type"`
			GuardID string `json:"lifecycleGuardId"`
		}{Command: Command{RequestID: id, Action: action, Identity: identity, BrokerEpoch: fence.BrokerEpoch, ChannelEpoch: fence.ChannelEpoch, ScopeHash: fence.ScopeHash, DeadlineUnixMS: time.Now().Add(20 * time.Second).UnixMilli(), Args: args}, Type: "lifecycle", GuardID: "guard"})
	}
	raw, err := json.Marshal(map[string]any{"grant": fence, "commands": commands})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "testdata/worker_journal.cjs")
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("actual worker fixture failed", err)
	}
	var replies []json.RawMessage
	if err = json.Unmarshal(output, &replies); err != nil || len(replies) != 3 {
		t.Fatalf("missing worker replies: %v count=%d", err, len(replies))
	}
	for i, reply := range replies {
		id := []string{"intend", "prepare", "status"}[i]
		phase := "prepared"
		var expected *LifecycleJournalPreparation = &preparation
		if i == 0 {
			phase = "intended"
			expected = nil
		}
		result, err := decodeLifecycleJournal(reply, id, identity, fence, "transition", phase, expected)
		if err != nil || !result.Confirmed || !result.Inhibited || result.Record == nil || result.Record.Phase != phase {
			t.Fatalf("worker/Go journal contract mismatch at %s: %v", id, err)
		}
	}
}
