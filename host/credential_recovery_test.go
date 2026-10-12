package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/data/stateget"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

func TestCredentialRecoveryRequiresImmutableVerifiedExactQuit(t *testing.T) {
	verified := "verified"
	state := durable.State{Progress: []*stateget.Milestone{{State: &verified}}}
	surface := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 123, ProcessStartToken: "123:456"}
	step := model.Step{ID: "quit", Action: "app.quit", TimeoutMs: 1000, Target: model.Selector{Surface: surface, Cardinality: "one"}, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"task": {Kind: model.StringValue, String: "retire"}}}}
	raw, _ := json.Marshal(map[string]any{"plan": model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, "inputs": map[string]model.Value{}})
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	actual, e := credentialRecoverySurface(state, string(raw), hash)
	if e != nil || actual != surface {
		t.Fatal("valid exact quit rejected", e)
	}
	if _, e = credentialRecoverySurface(state, string(raw)+" ", hash); e == nil {
		t.Fatal("modified plan accepted")
	}
	unverified := "unknown"
	state.Progress[0].State = &unverified
	if _, e = credentialRecoverySurface(state, string(raw), hash); e == nil {
		t.Fatal("unknown quit accepted")
	}
	state.Progress[0].State = &verified
	state.UnresolvedEffects = []*stateget.UnresolvedEffect{{}}
	if _, e = credentialRecoverySurface(state, string(raw), hash); e == nil {
		t.Fatal("unresolved effect accepted")
	}
}

func TestCredentialRecoveryRechecksOriginalKernelBirth(t *testing.T) {
	surface := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 123, ProcessStartToken: "123:456"}
	for _, mode := range []string{"gone", "reusedPID", "alive", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			inspector := func(pid int) (session.ProcessIdentity, bool, error) {
				if pid != surface.ProcessID {
					t.Fatal("inspected a caller substitute")
				}
				switch mode {
				case "gone":
					return session.ProcessIdentity{}, false, nil
				case "reusedPID":
					return session.ProcessIdentity{PID: 123, StartToken: "234:567"}, true, nil
				case "alive":
					return session.ProcessIdentity{PID: 123, StartToken: surface.ProcessStartToken}, true, nil
				default:
					return session.ProcessIdentity{}, false, errors.New("PRIVATE-CANARY")
				}
			}
			e := credentialOriginalProcessGone(surface, inspector)
			if (e == nil) != (mode == "gone" || mode == "reusedPID") {
				t.Fatal("incorrect retirement evidence")
			}
			if e != nil && e.Error() != "private credential operation unavailable" {
				t.Fatal("private provider diagnostic escaped")
			}
		})
	}
}
