package chrome

import (
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/viant/mechanize/backend/chrome/playwrightipc"
)

// Uses the shipped generic Node fixture with real extension transport/worker,
// then feeds its native frames through the production broker's bounded queue.
// No browser, native host, user profile, or authenticated service is involved.
func TestPlaywrightUnusedEventBurstCannotRevokeOperation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	raw, err := exec.Command(node, filepath.Join("..", "..", "extension", "chrome", "test", "fixtures", "playwright-event-burst.cjs")).Output()
	if err != nil {
		t.Fatal("generic event fixture:", err)
	}
	var fixture struct {
		Unrelated []json.RawMessage `json:"unrelated"`
		Required  []json.RawMessage `json:"required"`
		Counters  struct {
			Burst              int  `json:"burst"`
			EventChecks        int  `json:"eventChecks"`
			UnrelatedForwarded int  `json:"unrelatedForwarded"`
			RequiredForwarded  int  `json:"requiredForwarded"`
			CommandSucceeded   bool `json:"commandSucceeded"`
		} `json:"counters"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	execution := &playwrightExecution{conn: local, relayID: "fixture-relay", pending: map[string]chan json.RawMessage{}, events: make(chan playwrightipc.Event, 128)}
	channel := &channel{conn: local, playwright: execution}
	broker := &Broker{}
	for _, frame := range fixture.Unrelated {
		if !broker.acceptPlaywrightFrame(channel, local, frame) {
			t.Fatal("fixture frame not consumed")
		}
	}
	t.Logf("burst=%d currentChecks=%d forwarded=%d queued=%d revoked=%t", fixture.Counters.Burst, fixture.Counters.EventChecks, fixture.Counters.UnrelatedForwarded, len(execution.events), execution.revoked)
	if execution.revoked || len(execution.events) != 0 || fixture.Counters.EventChecks != 0 || fixture.Counters.UnrelatedForwarded != 0 {
		t.Fatal("unused root events incurred authority checks or overflowed the bounded relay")
	}
	if !fixture.Counters.CommandSucceeded {
		t.Fatal("burst made a valid command unusable")
	}
	if len(fixture.Required) != 1 || fixture.Counters.RequiredForwarded != 1 {
		t.Fatal("required lifecycle event lost")
	}
	if !broker.acceptPlaywrightFrame(channel, local, fixture.Required[0]) {
		t.Fatal("required frame not consumed")
	}
	event := <-execution.events
	if event.Method != "Page.lifecycleEvent" || event.RelayID != execution.relayID || execution.revoked {
		t.Fatal("required delivery changed", event)
	}
	// Keep the bounded queue's conservative behavior for admitted event overload.
	for n := 0; n < 129; n++ {
		broker.acceptPlaywrightFrame(channel, local, fixture.Required[0])
	}
	if !execution.revoked || len(execution.events) != 128 {
		t.Fatal("required-event overflow policy changed")
	}
}
