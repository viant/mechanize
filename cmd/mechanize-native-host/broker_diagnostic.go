package main

import (
	"bytes"
	"encoding/json"
	"io"
)

type brokerStartupFailure struct{ code string }

func (e *brokerStartupFailure) Error() string { return "broker startup: " + e.code }

func brokerStartupCodeAllowed(code string) bool {
	switch code {
	case "brokerPeerUnavailable", "brokerPeerAuditUnavailable", "brokerProcessUnqualified", "brokerHelloUnavailable", "brokerHelloRejected", "brokerEnrollmentRefused", "brokerChannelBusy", "brokerScopeUnqualified":
		return true
	}
	return false
}

func decodeBrokerStartupDiagnostic(raw []byte) string {
	var frame struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}
	if json.Unmarshal(raw, &frame) == nil && frame.Type == "nativeHostError" && brokerStartupCodeAllowed(frame.Code) {
		canonical, _ := json.Marshal(frame)
		// Exact closed, canonical broker-generated shape excludes duplicate keys.
		if bytes.Equal(raw, canonical) {
			return frame.Code
		}
	}
	return "brokerHandshakeUnavailable"
}

func writeBrokerStartupDiagnostic(writer io.Writer, code string) error {
	frame, _ := json.Marshal(struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}{"nativeHostError", code})
	return WriteFrame(writer, frame)
}
