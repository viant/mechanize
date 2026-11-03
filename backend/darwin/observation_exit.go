package darwin

import (
	"os"

	"github.com/viant/mechanize/session"
)

func (c *Client) observationExitConfirmed(inspect session.ProcessInspector) bool {
	if !c.observationOnly || c.inputPossible || c.businessPossible || c.recording != nil || c.consoleChild == nil || c.verifiedIdentity == nil || inspect == nil {
		return false
	}
	original := *c.verifiedIdentity
	if original.PID <= 0 || original.PID != c.consoleChild.pid || original.StartToken == "" || original.UID != uint32(os.Getuid()) || original.Executable == "" {
		return false
	}
	current, alive, err := inspect(original.PID)
	if err != nil {
		return false
	}
	if !alive {
		return true
	}
	// A reused PID proves the original process gone only with an independently
	// observed nonempty different kernel birth token. No process is signalled.
	return current.PID == original.PID && current.StartToken != "" && current.StartToken != original.StartToken
}
