package darwin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// RecordingOwner is supplied only by the authenticated broker's helper factory.
// Namespace/client/session never come from recording request parameters.
type RecordingOwner struct {
	Namespace string `json:"namespace"`
	ClientID  string `json:"clientId"`
	SessionID string `json:"sessionId"`
}

func (o RecordingOwner) Validate() error {
	raw, err := hex.DecodeString(o.Namespace)
	if err != nil || len(raw) != 32 || strings.ToLower(o.Namespace) != o.Namespace || !recordingBounded(o.ClientID, 128) || !recordingBounded(o.SessionID, 128) {
		return errors.New("verified bounded recording owner required")
	}
	return nil
}

type RecordingStart struct {
	RecordingID    string
	MaxEvents      int
	MaxDurationMS  int
	GrantExpiresAt time.Time
}
type RecordNativeIdentity struct {
	UID        uint32  `json:"uid"`
	BundleID   string  `json:"bundleID"`
	PID        int32   `json:"pid"`
	StartToken string  `json:"startToken"`
	WindowID   *string `json:"windowID,omitempty"`
}
type RecordNativeTarget struct {
	Role                string  `json:"role"`
	Identifier          *string `json:"identifier,omitempty"`
	IdentifierDigest    *string `json:"identifierDigest,omitempty"`
	IdentifierQualified bool    `json:"identifierQualified"`
	NameWithheld        bool    `json:"nameWithheld"`
}
type RecordLocator struct {
	Strategy string `json:"strategy"`
	Value    string `json:"value"`
	Exact    bool   `json:"exact"`
}
type RecordEvent struct {
	RecordingID        string                `json:"recordingId"`
	Sequence           uint64                `json:"sequence"`
	TimestampUnixMS    int64                 `json:"timestampUnixMs"`
	Kind               string                `json:"kind"`
	NativeIdentity     *RecordNativeIdentity `json:"nativeIdentity,omitempty"`
	Target             *RecordNativeTarget   `json:"target,omitempty"`
	Locator            *RecordLocator        `json:"locator,omitempty"`
	Redacted           bool                  `json:"redacted"`
	ParameterRequired  bool                  `json:"parameterRequired"`
	SelectorConfidence string                `json:"selectorConfidence"`
	Lineage            string                `json:"lineage"`
	Source             string                `json:"source"`
	Trusted            bool                  `json:"trusted"`
	Reason             string                `json:"reason,omitempty"`
}
type RecordGap struct {
	Kind          string `json:"kind"`
	Reason        string `json:"reason"`
	FromSequence  uint64 `json:"fromSequence"`
	ToSequence    uint64 `json:"toSequence"`
	Lost          uint64 `json:"lost"`
	UnknownExtent bool   `json:"unknownExtent"`
}

// RecordBatch is native typed transport, not a Chrome alias. Native identity and
// redacted target metadata survive decoding. No captured value/text field exists.
type RecordBatch struct {
	RecordingID        string         `json:"recordingId"`
	State              string         `json:"state"`
	LeaseExpiresUnixMS int64          `json:"leaseExpiresUnixMs"`
	Events             []RecordEvent  `json:"events"`
	Gaps               []RecordGap    `json:"gaps"`
	LastSequence       uint64         `json:"lastSequence"`
	Truncated          bool           `json:"truncated"`
	Owner              RecordingOwner `json:"owner"`
}
type recordingTransport struct {
	mu               sync.Mutex
	owner            RecordingOwner
	uid              uint32
	call             func(context.Context, Request) (Reply, error)
	id, nonce, epoch string
	lastDelivered    uint64
}

func newRecordingTransport(owner RecordingOwner, uid uint32, call func(context.Context, Request) (Reply, error)) *recordingTransport {
	return &recordingTransport{owner: owner, uid: uid, call: call}
}
func recordingBounded(s string, max int) bool {
	if strings.TrimSpace(s) == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func recordingIDValid(s string) bool {
	if !recordingBounded(s, 128) {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func recordingTTL(expiry time.Time) (int64, error) {
	remaining := time.Until(expiry).Milliseconds()
	if remaining < 1000 {
		return 0, errors.New("live recording consent with at least one second remaining required")
	}
	if remaining > 30000 {
		remaining = 30000
	}
	return remaining, nil
}
func (r *recordingTransport) authorize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || p.Namespace != r.owner.Namespace || p.ClientID != r.owner.ClientID {
		return auth.ErrUnauthorized
	}
	return nil
}
func (c *Client) ownedRecording() (*recordingTransport, error) {
	if c == nil || c.recording == nil || c.verifiedIdentity == nil {
		return nil, errors.New("signed owned recording-only client required")
	}
	return c.recording, nil
}
func (c *Client) StartRecording(ctx context.Context, in RecordingStart) (RecordBatch, error) {
	r, err := c.ownedRecording()
	if err != nil {
		return RecordBatch{}, err
	}
	return r.start(ctx, in)
}
func (c *Client) RenewRecording(ctx context.Context, id string, expiry time.Time) (RecordBatch, error) {
	r, err := c.ownedRecording()
	if err != nil {
		return RecordBatch{}, err
	}
	return r.control(ctx, id, "record.renew", 0, 64, expiry)
}
func (c *Client) PauseRecording(ctx context.Context, id string) (RecordBatch, error) {
	r, err := c.ownedRecording()
	if err != nil {
		return RecordBatch{}, err
	}
	return r.control(ctx, id, "record.pause", 0, 64, time.Time{})
}
func (c *Client) StopRecording(ctx context.Context, id string) (RecordBatch, error) {
	r, err := c.ownedRecording()
	if err != nil {
		return RecordBatch{}, err
	}
	return r.control(ctx, id, "record.stop", 0, 64, time.Time{})
}
func (c *Client) RecordingEvents(ctx context.Context, id string, after uint64, limit int) (RecordBatch, error) {
	r, err := c.ownedRecording()
	if err != nil {
		return RecordBatch{}, err
	}
	return r.control(ctx, id, "record.events", after, limit, time.Time{})
}
func (r *recordingTransport) start(ctx context.Context, in RecordingStart) (RecordBatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorize(ctx); err != nil {
		return RecordBatch{}, err
	}
	if r.id != "" || !recordingIDValid(in.RecordingID) || in.MaxEvents < 4 || in.MaxEvents > 4096 || in.MaxDurationMS < 1000 || in.MaxDurationMS > 900000 {
		return RecordBatch{}, errors.New("bounded unique recording start required")
	}
	ttl, err := recordingTTL(in.GrantExpiresAt)
	if err != nil {
		return RecordBatch{}, err
	}
	// Doctor is a separate read, never recording activation. Pin its helper epoch.
	doctor, err := r.call(ctx, Request{RequestID: requestID(), Method: "doctor", DeadlineRemainingMS: 2000})
	if err != nil {
		return RecordBatch{}, err
	}
	if doctor.HelperEpoch == "" {
		return RecordBatch{}, errors.New("native helper epoch missing")
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return RecordBatch{}, err
	}
	ttl, err = recordingTTL(in.GrantExpiresAt)
	if err != nil {
		return RecordBatch{}, err
	}
	r.id = in.RecordingID
	r.nonce = hex.EncodeToString(random)
	r.epoch = doctor.HelperEpoch
	params := r.params()
	params["expectedUID"] = r.uid
	params["maxEvents"] = in.MaxEvents
	params["maxDurationMs"] = in.MaxDurationMS
	params["grantRemainingMs"] = ttl
	return r.invoke(ctx, "record.start", params, 0, 64)
}
func (r *recordingTransport) params() map[string]any {
	return map[string]any{"recordingId": r.id, "namespace": r.owner.Namespace, "clientId": r.owner.ClientID, "sessionId": r.owner.SessionID, "consentNonce": r.nonce}
}
func (r *recordingTransport) control(ctx context.Context, id, method string, after uint64, limit int, expiry time.Time) (RecordBatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorize(ctx); err != nil {
		return RecordBatch{}, err
	}
	if r.id == "" || id != r.id || limit < 1 || limit > 64 {
		return RecordBatch{}, errors.New("exact owned recording and bounded poll required")
	}
	params := r.params()
	if method == "record.pause" || method == "record.stop" {
		after = r.lastDelivered
	}
	if method == "record.events" || method == "record.pause" || method == "record.stop" {
		params["afterSequence"] = after
		params["limit"] = limit
	}
	if method == "record.renew" {
		ttl, err := recordingTTL(expiry)
		if err != nil {
			return RecordBatch{}, err
		}
		params["grantRemainingMs"] = ttl
	}
	return r.invoke(ctx, method, params, after, limit)
}
func (r *recordingTransport) invoke(ctx context.Context, method string, params map[string]any, after uint64, limit int) (RecordBatch, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return RecordBatch{}, err
	}
	reply, err := r.call(ctx, Request{RequestID: requestID(), Method: method, HelperEpoch: r.epoch, DeadlineRemainingMS: 3000, Params: body})
	if err != nil {
		return RecordBatch{}, err
	}
	if reply.HelperEpoch != r.epoch {
		return RecordBatch{}, errors.New("recording helper epoch changed")
	}
	batch, err := decodeRecordBatch(reply.Result, r.owner, r.uid, r.id, after, limit)
	if err != nil {
		return RecordBatch{}, err
	}
	if method != "record.renew" && len(batch.Events) > 0 {
		r.lastDelivered = batch.Events[len(batch.Events)-1].Sequence
	}
	return batch, nil
}
func decodeRecordBatch(raw []byte, owner RecordingOwner, uid uint32, id string, after uint64, limit int) (RecordBatch, error) {
	var batch RecordBatch
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return RecordBatch{}, errors.New("invalid native recording batch")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return RecordBatch{}, errors.New("trailing recording payload")
	}
	if batch.Owner != owner || batch.RecordingID != id || len(batch.Events) > limit || len(batch.Gaps) > 8 || batch.LastSequence < after || batch.LastSequence > 4096 || batch.LeaseExpiresUnixMS <= 0 || batch.LeaseExpiresUnixMS > time.Now().Add(16*time.Minute).UnixMilli() {
		return RecordBatch{}, errors.New("native recording batch identity or bounds mismatch")
	}
	switch batch.State {
	case "recording", "paused", "stopped", "stopUnconfirmed":
	default:
		return RecordBatch{}, errors.New("invalid native recording state")
	}
	previous := after
	for _, e := range batch.Events {
		if e.RecordingID != id || e.Sequence <= previous || e.Sequence > batch.LastSequence || e.Source != "nativeAX" || e.Trusted || e.Lineage != fmt.Sprintf("%s:native:%d", id, e.Sequence) || e.TimestampUnixMS <= 0 || e.TimestampUnixMS > time.Now().Add(time.Minute).UnixMilli() {
			return RecordBatch{}, errors.New("native recording provenance mismatch")
		}
		switch e.Kind {
		case "start", "stop", "gap":
		case "app.activate", "press", "fill", "select":
			if e.NativeIdentity == nil {
				return RecordBatch{}, errors.New("native recording event identity missing")
			}
		default:
			return RecordBatch{}, errors.New("unsupported native recording kind")
		}
		if e.NativeIdentity != nil {
			identity := e.NativeIdentity
			if identity.UID != uid || identity.PID <= 0 || !recordingMachineIdentifier(identity.BundleID, 256) || !recordingBounded(identity.StartToken, 128) {
				return RecordBatch{}, errors.New("native recording target user mismatch")
			}
			if identity.WindowID != nil {
				window, err := strconv.ParseUint(*identity.WindowID, 10, 32)
				if err != nil || window == 0 {
					return RecordBatch{}, errors.New("native recording window identity invalid")
				}
			}
		}
		if e.Kind == "fill" && (!e.Redacted || !e.ParameterRequired) {
			return RecordBatch{}, errors.New("native input intent must be withheld")
		}
		if e.Target != nil {
			if !e.Target.NameWithheld || !recordingRole(e.Target.Role) || e.Target.Identifier != nil && (!e.Target.IdentifierQualified || !recordingMachineIdentifier(*e.Target.Identifier, 256)) || e.Target.IdentifierDigest != nil && (!recordingDigest(*e.Target.IdentifierDigest) || e.Target.Identifier != nil) {
				return RecordBatch{}, errors.New("native recording target redaction invalid")
			}
		}
		if (e.Kind == "press" || e.Kind == "fill" || e.Kind == "select") && e.Target == nil {
			return RecordBatch{}, errors.New("native semantic target missing")
		}
		if e.Locator != nil {
			if !recordingBounded(e.Locator.Value, 512) || !e.Locator.Exact || (e.Locator.Strategy != "id" && e.Locator.Strategy != "idDigest" && e.Locator.Strategy != "role") {
				return RecordBatch{}, errors.New("native recording locator invalid")
			}
			if e.Target == nil {
				return RecordBatch{}, errors.New("native locator target missing")
			}
			target := e.Target
			switch e.Locator.Strategy {
			case "id":
				if target.Identifier == nil || e.Locator.Value != *target.Identifier {
					return RecordBatch{}, errors.New("native identifier locator differs")
				}
			case "idDigest":
				if target.IdentifierDigest == nil || e.Locator.Value != *target.IdentifierDigest {
					return RecordBatch{}, errors.New("native digest locator differs")
				}
			case "role":
				if target.Identifier != nil || target.IdentifierDigest != nil || e.Locator.Value != target.Role {
					return RecordBatch{}, errors.New("native role locator differs")
				}
			}
		}
		previous = e.Sequence
	}
	for _, gap := range batch.Gaps {
		if gap.Kind != "gap" || !recordingBounded(gap.Reason, 64) || gap.FromSequence == 0 || gap.ToSequence < gap.FromSequence || gap.ToSequence > batch.LastSequence {
			return RecordBatch{}, errors.New("native recording gap invalid")
		}
	}
	return batch, nil
}

func recordingMachineIdentifier(value string, maximum int) bool {
	if !recordingBounded(value, maximum) {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
func recordingDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}
func recordingRole(value string) bool {
	switch value {
	case "AXApplication", "AXWindow", "AXButton", "AXTextField", "AXTextArea", "AXStaticText", "AXComboBox", "AXPopUpButton", "AXCheckBox", "AXRadioButton", "AXMenu", "AXMenuItem", "AXMenuBar", "AXTabGroup", "AXTable", "AXRow", "AXCell", "AXOutline", "AXGroup", "AXScrollArea", "AXSlider", "AXToolbar", "AXLink", "AXUnknown":
		return true
	}
	return false
}
