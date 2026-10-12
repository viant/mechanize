package chrome

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"time"
)

// Only already-owned opaque credential continuations cross a quarantined channel.
// This decoder never invokes the general controller argument decoder, and the
// original private frame is wiped before canonical dispatch sees reconstructed IDs.
func decodePrivateControllerRequest(raw []byte, now time.Time) *controllerRequest {
	if len(raw) > 4096 || !uniqueCredentialJSON(raw) {
		return nil
	}
	var r controllerRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Type != "controllerRequest" || r.Operation != "tools/call" || r.Params == nil || !controllerID.MatchString(r.RequestID) || !controllerID.MatchString(r.SessionID) || !controllerID.MatchString(r.DocumentID) || !controllerOrigin(r.Origin) || r.Deadline <= now.UnixMilli() || r.Deadline > now.Add(10*time.Second).UnixMilli() {
		return nil
	}
	switch r.Params.Name {
	case "mechanize_credential_apply", "mechanize_credential_submit", "mechanize_credential_status", "mechanize_session_close":
	default:
		return nil
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, key := range []string{"params", "type", "requestId", "operation", "deadlineUnixMs", "origin", "documentId", "sessionId", "brokerEpoch", "channelEpoch", "scopeHash"} {
		if _, ok := fields[key]; !ok {
			return nil
		}
	}
	if len(fields) != 11 {
		return nil
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(fields["params"], &params) != nil || len(params) != 2 || params["name"] == nil || params["arguments"] == nil {
		return nil
	}
	var args struct {
		SessionID     string `json:"sessionId"`
		PreparationID string `json:"preparationId,omitempty"`
	}
	d = json.NewDecoder(bytes.NewReader(r.Params.Arguments))
	d.DisallowUnknownFields()
	var argFields map[string]json.RawMessage
	if d.Decode(&args) != nil || d.Decode(new(any)) != io.EOF || json.Unmarshal(r.Params.Arguments, &argFields) != nil || argFields["sessionId"] == nil || !controllerID.MatchString(args.SessionID) {
		return nil
	}
	if r.Params.Name == "mechanize_session_close" {
		if len(argFields) != 1 || args.PreparationID != "" {
			return nil
		}
	} else if len(argFields) != 2 || argFields["preparationId"] == nil || !fingerprintV2Hash.MatchString(args.PreparationID) {
		return nil
	}
	canonical, _ := json.Marshal(args)
	r.Params.Arguments = canonical
	r.privateContinuation = true
	r.privateSession = args.SessionID
	return &r
}
func (b *Broker) privateControllerAllowedLocked(c *channel, conn net.Conn, r *controllerRequest) bool {
	if !r.privateContinuation || c.conn != conn || c.privateConsent.SessionID == "" || c.privateConsent.SessionID != r.privateSession {
		return false
	}
	s := c.controllerSessions[r.SessionID]
	return s != nil && s.identity.Principal.Namespace == c.privateOwner.Namespace && s.identity.Principal.ClientID == c.privateOwner.ClientID && s.identity.ConversationID == r.SessionID
}
func quarantinedChannel(c *channel) bool {
	return c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil || c.privacyPending != nil || c.privacy != nil && !c.privacy.active
}
