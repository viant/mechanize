package chrome

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MutationFingerprint is an unwired versioned logical identity, not dispatch
// authority. Existing renderer v1 fingerprints and receipts remain unchanged.
type MutationFingerprint struct {
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

var fingerprintV2ID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var fingerprintV2Hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

const fingerprintV2MaxInteger = uint64(9007199254740991)

func fingerprintV2Text(value string, maximum int, empty bool) bool {
	return utf8.ValidString(value) && (empty || value != "") && len(utf16.Encode([]rune(value))) <= maximum
}

func logicalMutationEnvelopeV2(command Command) ([]byte, error) {
	failure := func() ([]byte, error) { return nil, errors.New("invalid qualified logical mutation envelope") }
	if command.Action != "element.press" && command.Action != "element.fill" {
		return failure()
	}
	i := command.Identity
	for _, id := range []string{i.ProfileChannel, i.BrowserInstance, i.DocumentID, command.BrokerEpoch, command.ChannelEpoch, command.AttemptID} {
		if !fingerprintV2ID.MatchString(id) {
			return failure()
		}
	}
	if !fingerprintV2Hash.MatchString(command.ScopeHash) || i.TabID < 1 || i.TabID > 2147483647 || i.FrameID != 0 || i.Generation < 1 || i.Generation > fingerprintV2MaxInteger || command.ControlLease == nil || !fingerprintV2ID.MatchString(command.ControlLease.ID) || command.ControlLease.Generation < 1 || command.ControlLease.Generation > fingerprintV2MaxInteger {
		return failure()
	}
	l := command.Locator
	if l == nil || !l.Exact || !fingerprintV2Text(l.Value, 1024, false) {
		return failure()
	}
	switch l.Strategy {
	case "id", "testId", "role", "label":
	default:
		return failure()
	}
	var name any
	if l.Name != nil {
		if l.Strategy != "role" || !fingerprintV2Text(*l.Name, 1024, false) {
			return failure()
		}
		name = *l.Name
	}
	args := map[string]any{}
	if command.Action == "element.press" {
		if len(command.Args) != 0 {
			return failure()
		}
	} else {
		if len(command.Args) != 1 {
			return failure()
		}
		value, ok := command.Args["value"].(string)
		if !ok || !fingerprintV2Text(value, 16384, true) {
			return failure()
		}
		args["value"] = value
	}
	envelope := map[string]any{"version": 2, "action": command.Action, "identity": map[string]any{"profileChannel": i.ProfileChannel, "browserInstance": i.BrowserInstance, "tabId": i.TabID, "frameId": i.FrameID, "documentId": i.DocumentID, "documentGeneration": i.Generation}, "brokerEpoch": command.BrokerEpoch, "channelEpoch": command.ChannelEpoch, "scopeHash": command.ScopeHash, "controlLease": map[string]any{"id": command.ControlLease.ID, "generation": command.ControlLease.Generation}, "attemptId": command.AttemptID, "locator": map[string]any{"strategy": l.Strategy, "value": l.Value, "name": name, "exact": true}, "args": args}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return nil, errors.New("logical mutation encoding unavailable")
	}
	return []byte(strings.TrimSuffix(out.String(), "\n")), nil
}

// FingerprintMutationV2 returns only version and SHA256. It must not be wired to
// dispatch or historical comparison until negotiated versioned bindings exist.
func FingerprintMutationV2(command Command) (MutationFingerprint, error) {
	raw, err := logicalMutationEnvelopeV2(command)
	if err != nil {
		return MutationFingerprint{}, err
	}
	digest := sha256.Sum256(raw)
	return MutationFingerprint{Version: 2, SHA256: hex.EncodeToString(digest[:])}, nil
}
