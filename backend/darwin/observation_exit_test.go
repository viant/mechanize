package darwin

import (
	"errors"
	"os"
	"testing"

	"github.com/viant/mechanize/session"
)

func TestObservationExitRequiresExactIndependentProcessProof(t *testing.T) {
	for _, mode := range []string{"dead", "reused", "alive", "unknown", "missing-birth", "wrong-pid", "wrong-owner", "untrusted", "action-profile", "raw-input", "business-input", "recording"} {
		t.Run(mode, func(t *testing.T) {
			id := session.ProcessIdentity{PID: 777, StartToken: "fixture-birth", UID: uint32(os.Getuid()), Executable: "/fixture/helper"}
			c := &Client{observationOnly: true, consoleChild: &consoleChild{pid: 777}, verifiedIdentity: &id}
			current := id
			alive := true
			var failure error
			switch mode {
			case "dead":
				alive = false
			case "reused":
				current.StartToken = "replacement-birth"
			case "unknown":
				failure = errors.New("inspection unavailable")
			case "missing-birth":
				current.StartToken = ""
			case "wrong-pid":
				current.PID = 778
				current.StartToken = "replacement-birth"
			case "wrong-owner":
				id.UID++
			case "untrusted":
				c.verifiedIdentity = nil
			case "action-profile":
				c.observationOnly = false
				alive = false
			case "raw-input":
				c.inputPossible = true
				alive = false
			case "business-input":
				c.businessPossible = true
				alive = false
			case "recording":
				c.recording = &recordingTransport{}
				alive = false
			}
			got := c.observationExitConfirmed(func(pid int) (session.ProcessIdentity, bool, error) {
				if pid != 777 {
					t.Fatal("wrong lookup")
				}
				return current, alive, failure
			})
			if got != (mode == "dead" || mode == "reused") {
				t.Fatal("incorrect exit proof", mode, got)
			}
			if c.consoleChild.reaped.Load() {
				t.Fatal("process absence forged console reaping receipt")
			}
		})
	}
}
