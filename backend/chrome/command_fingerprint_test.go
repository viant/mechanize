package chrome

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fingerprintCommand() Command {
	return Command{Action: "element.press", Identity: Identity{ProfileChannel: "profile-1", BrowserInstance: "browser-1", TabID: 7, FrameID: 0, DocumentID: "doc-1", Generation: 1}, BrokerEpoch: "broker-1", ChannelEpoch: "channel-1", ScopeHash: strings.Repeat("a", 64), AttemptID: "attempt-1", Locator: &Locator{Strategy: "id", Value: "save", Exact: true}, ControlLease: &Lease{ID: "lease-1", Generation: 1}}
}
func TestCommandFingerprintV2CrossLanguageCanonicalVectors(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../testdata/chrome-command-fingerprint-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int `json:"version"`
		Cases   []struct {
			Name      string          `json:"name"`
			Command   json.RawMessage `json:"command"`
			Canonical string          `json:"canonical"`
			SHA256    string          `json:"sha256"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			var command Command
			decoder := json.NewDecoder(bytes.NewReader(test.Command))
			decoder.DisallowUnknownFields()
			decoder.UseNumber()
			if err := decoder.Decode(&command); err != nil {
				t.Fatal(err)
			}
			canonical, err := logicalMutationEnvelopeV2(command)
			if err != nil || string(canonical) != test.Canonical {
				t.Fatal("logical envelope differs from independent canonical vector")
			}
			fingerprint, err := FingerprintMutationV2(command)
			if err != nil || fingerprint.Version != 2 || fingerprint.SHA256 != test.SHA256 {
				t.Fatal("fingerprint differs from independent SHA256 vector")
			}
		})
	}
}
func TestCommandFingerprintV2RejectsMalformedUnsupportedOrUnsafeEnvelope(t *testing.T) {
	for _, mode := range []string{"navigation", "missing lease", "missing locator", "child frame", "unsafe generation", "zero lease", "bad scope", "unknown args", "float value", "nonUTF8", "invalid scalarUTF8", "nonexact", "CSS", "role name on id"} {
		t.Run(mode, func(t *testing.T) {
			c := fingerprintCommand()
			switch mode {
			case "navigation":
				c.Action = "browser.navigate"
			case "missing lease":
				c.ControlLease = nil
			case "missing locator":
				c.Locator = nil
			case "child frame":
				c.Identity.FrameID = 1
			case "unsafe generation":
				c.Identity.Generation = 9007199254740992
			case "zero lease":
				c.ControlLease.Generation = 0
			case "bad scope":
				c.ScopeHash = "unqualified"
			case "unknown args":
				c.Args = map[string]any{"script": "private value"}
			case "float value":
				c.Action = "element.fill"
				c.Args = map[string]any{"value": 1.5}
			case "nonUTF8":
				c.Action = "element.fill"
				c.Args = map[string]any{"value": string([]byte{0xff})}
			case "invalid scalarUTF8":
				c.Locator.Value = string([]byte{0xed, 0xa0, 0x80})
			case "nonexact":
				c.Locator.Exact = false
			case "CSS":
				c.Locator.Strategy = "css"
			case "role name on id":
				name := "private value"
				c.Locator.Name = &name
			}
			f, err := FingerprintMutationV2(c)
			if err == nil || f.SHA256 != "" || f.Version != 0 || strings.Contains(err.Error(), "private value") {
				t.Fatal("invalid logical payload generated a fingerprint or leaked data")
			}
		})
	}
}
func TestCommandFingerprintV2TransportFieldsExcludedLogicalFieldsRetained(t *testing.T) {
	c := fingerprintCommand()
	original, _ := FingerprintMutationV2(c)
	c.RequestID = "new-request"
	c.DeadlineUnixMS = 999999999999
	c.Args = map[string]any{}
	same, err := FingerprintMutationV2(c)
	if err != nil || original != same {
		t.Fatal("transport details changed logical identity")
	}
	for _, mode := range []string{"document", "fence", "lease", "attempt", "locator"} {
		changed := c
		locator := *c.Locator
		lease := *c.ControlLease
		changed.Locator = &locator
		changed.ControlLease = &lease
		switch mode {
		case "document":
			changed.Identity.DocumentID = "new-doc"
		case "fence":
			changed.ChannelEpoch = "new-channel"
		case "lease":
			changed.ControlLease.Generation++
		case "attempt":
			changed.AttemptID = "new-attempt"
		case "locator":
			changed.Locator.Value = "other"
		}
		f, err := FingerprintMutationV2(changed)
		if err != nil || f == original {
			t.Fatal("logical authority/target change retained fingerprint")
		}
	}
}
