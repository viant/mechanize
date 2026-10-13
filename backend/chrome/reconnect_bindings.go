package chrome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/viant/mechanize/auth"
)

// ReconnectBindingScope is populated only from an authenticated enrolled port.
// It is metadata read authority, never a renderer/input lease.
type ReconnectFence struct {
	BrokerEpoch  string `json:"brokerEpoch"`
	ChannelEpoch string `json:"channelEpoch"`
	ScopeHash    string `json:"scopeHash"`
}
type ReconnectBindingScope struct {
	ProfileChannel, BrowserInstance, ScopeHash, PendingDigest string
	Fences                                                    []ReconnectFence
}
type ReconnectBinding struct {
	Identity      Identity       `json:"identity"`
	Fence         ReconnectFence `json:"fence"`
	AttemptID     string         `json:"attemptId"`
	Fingerprint   string         `json:"fingerprintSHA256"`
	DispatchState string         `json:"dispatchState"`
	ControlLease  *Lease         `json:"controlLease,omitempty"`
}
type ReconnectBindingsProvider func(context.Context, auth.Principal, ReconnectBindingScope, func(context.Context) error, func([]ReconnectBinding) error) error

type reconnectBindingExchange struct {
	requestID                string
	conn                     net.Conn
	finish                   chan reconnectBindingProgress
	ready                    bool
	published                bool
	prepared                 chan struct{}
	cancel                   context.CancelFunc
	deadline                 time.Time
	retirements              map[string]Command
	targetRetirementAttempts []string
}
type reconnectBindingsRequest struct {
	Type              string          `json:"type"`
	ExecutorChallenge string          `json:"executorChallenge"`
	RequestID         string          `json:"requestId"`
	BrokerEpoch       string          `json:"brokerEpoch"`
	ChannelEpoch      string          `json:"channelEpoch"`
	ScopeHash         string          `json:"scopeHash"`
	DeadlineUnixMS    int64           `json:"deadlineUnixMs"`
	Pending           json.RawMessage `json:"pending"`
}

var errReconnectBindings = errors.New("complete reconnect binding proof unavailable")

type reconnectBindingProgress struct {
	NextOffset int
	Complete   bool
	Done       bool
}

// Credential replies contain no arrays; reconnect lineage does. Keep this
// array-aware closed parser local rather than broadening the private decoder.
func uniqueReconnectJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	nodes := 0
	var value func(int) bool
	value = func(depth int) bool {
		nodes++
		if depth > 20 || nodes > 32768 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func reconnectTopFields(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if !uniqueReconnectJSON(raw) || json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func decodeReconnectClosed(raw []byte, out any) error {
	if !uniqueReconnectJSON(raw) {
		return errReconnectBindings
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errReconnectBindings
	}
	return nil
}

// The journal itself stays extension-local. Its exact bytes bind the request;
// only bounded old/new fence lineage is admitted to the generated DB reader.
func reconnectBindingLineage(raw json.RawMessage, scope string) ([]ReconnectFence, string, error) {
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return nil, "", errReconnectBindings
	}
	var walk func(json.RawMessage, int) error
	seenNonce := map[string]bool{}
	seenFence := map[ReconnectFence]bool{}
	fences := []ReconnectFence{}
	add := func(f ReconnectFence) error {
		if !receiptOpaqueID.MatchString(f.BrokerEpoch) || !receiptOpaqueID.MatchString(f.ChannelEpoch) || f.ScopeHash != scope {
			return errReconnectBindings
		}
		if !seenFence[f] {
			seenFence[f] = true
			fences = append(fences, f)
		}
		if len(fences) > 1024 {
			return errReconnectBindings
		}
		return nil
	}
	walk = func(value json.RawMessage, depth int) error {
		if depth >= 6 {
			return errReconnectBindings
		}
		var r struct {
			Version int            `json:"version"`
			Phase   string         `json:"phase"`
			Nonce   string         `json:"nonce"`
			Old     ReconnectFence `json:"oldFence"`
			New     ReconnectFence `json:"newFence"`
			History []struct {
				Nonce     string          `json:"nonce"`
				Old       ReconnectFence  `json:"oldFence"`
				New       ReconnectFence  `json:"newFence"`
				Executors json.RawMessage `json:"executors"`
			} `json:"history"`
			Recovery *struct {
				Kind      string          `json:"kind"`
				Original  json.RawMessage `json:"originalPending,omitempty"`
				Reference json.RawMessage `json:"originalPendingRef,omitempty"`
			} `json:"recovery,omitempty"`
			Archive json.RawMessage `json:"archive,omitempty"`
			Sources json.RawMessage `json:"sourceInventory,omitempty"`
		}
		if decodeReconnectClosed(value, &r) != nil || r.Phase != "pending" || r.Version < 1 || r.Version > 6 || !setupHash.MatchString(r.Nonce) || seenNonce[r.Nonce] || r.Old == r.New || len(r.History) > 64 {
			return errReconnectBindings
		}
		seenNonce[r.Nonce] = true
		if add(r.Old) != nil || add(r.New) != nil {
			return errReconnectBindings
		}
		for _, h := range r.History {
			if !setupHash.MatchString(h.Nonce) || add(h.Old) != nil || add(h.New) != nil {
				return errReconnectBindings
			}
		}
		// Archived predecessor fences are covered by the all-epochs channel/scope
		// snapshot. The extension independently validates its immutable archive
		// chain before sending this request and again before committing.
		if len(r.Archive) > 0 && string(r.Archive) != "null" {
			var archive struct {
				Digest   string         `json:"digest"`
				Segments int            `json:"segments"`
				EndFence ReconnectFence `json:"endFence"`
				Nonce    string         `json:"nonce"`
			}
			if decodeReconnectClosed(r.Archive, &archive) != nil || !setupHash.MatchString(archive.Digest) || !setupHash.MatchString(archive.Nonce) || archive.Segments < 1 || archive.Segments > 1024 || add(archive.EndFence) != nil {
				return errReconnectBindings
			}
		}
		if r.Recovery != nil {
			if r.Recovery.Kind != "emptySetupDocuments" && r.Recovery.Kind != "verifiedCurrentDocuments" {
				return errReconnectBindings
			}
			if (len(r.Recovery.Original) == 0) == (len(r.Recovery.Reference) == 0) {
				return errReconnectBindings
			}
			if len(r.Recovery.Reference) > 0 {
				var ref struct {
					Digest  string         `json:"digest"`
					Bytes   int            `json:"bytes"`
					Version int            `json:"version"`
					Nonce   string         `json:"nonce"`
					Old     ReconnectFence `json:"oldFence"`
					New     ReconnectFence `json:"newFence"`
				}
				if !reconnectTopFields(r.Recovery.Reference, "digest", "bytes", "version", "nonce", "oldFence", "newFence") || decodeReconnectClosed(r.Recovery.Reference, &ref) != nil || !setupHash.MatchString(ref.Digest) || !setupHash.MatchString(ref.Nonce) || seenNonce[ref.Nonce] || ref.Bytes < 1 || ref.Bytes > MaxFrameBytes || ref.Version < 1 || ref.Version != r.Version-1 || ref.Old == ref.New || add(ref.Old) != nil || add(ref.New) != nil {
					return errReconnectBindings
				}
				// The complete channel snapshot covers every historical epoch.
				// This reference is metadata only: the worker verifies the exact
				// immutable predecessor bytes and full lineage before publication.
				seenNonce[ref.Nonce] = true
				return nil
			}
			return walk(r.Recovery.Original, depth+1)
		}
		if r.Version != 1 {
			return errReconnectBindings
		}
		return nil
	}
	if walk(raw, 0) != nil {
		return nil, "", errReconnectBindings
	}
	digest := sha256.Sum256(raw)
	return fences, hex.EncodeToString(digest[:]), nil
}

// Called by the single authenticated port reader; callbacks run independently
// so their completion frame can drain without blocking the native read loop.
func (b *Broker) acceptReconnectBindings(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return false
	}
	if kind.Type == "reconnectBindingsDone" || kind.Type == "reconnectBindingsNext" {
		var progress reconnectBindingProgress
		var requestID string
		valid := false
		if kind.Type == "reconnectBindingsDone" {
			var v struct {
				Type      string `json:"type"`
				RequestID string `json:"requestId"`
				Complete  bool   `json:"complete"`
			}
			valid = reconnectTopFields(raw, "type", "requestId", "complete") && decodeReconnectClosed(raw, &v) == nil
			requestID = v.RequestID
			progress = reconnectBindingProgress{Done: true, Complete: v.Complete}
		} else {
			var v struct {
				Type       string `json:"type"`
				RequestID  string `json:"requestId"`
				NextOffset int    `json:"nextOffset"`
			}
			valid = reconnectTopFields(raw, "type", "requestId", "nextOffset") && decodeReconnectClosed(raw, &v) == nil && v.NextOffset > 0 && v.NextOffset <= 4096
			requestID = v.RequestID
			progress.NextOffset = v.NextOffset
		}
		if valid {
			b.mu.Lock()
			x := c.reconnectBindings
			if x != nil && x.conn == conn && x.requestID == requestID {
				select {
				case x.finish <- progress:
				default:
				}
			}
			b.mu.Unlock()
		}
		return true
	}
	if kind.Type != "reconnectBindings" {
		return false
	}
	var envelope struct {
		reconnectBindingsRequest
		TargetRetirementAttempts []string `json:"targetRetirementAttempts,omitempty"`
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	keys := []string{"type", "requestId", "executorChallenge", "brokerEpoch", "channelEpoch", "scopeHash", "deadlineUnixMs", "pending"}
	if _, exists := fields["targetRetirementAttempts"]; exists {
		keys = append(keys, "targetRetirementAttempts")
	}
	if !reconnectTopFields(raw, keys...) || decodeReconnectClosed(raw, &envelope) != nil || !receiptOpaqueID.MatchString(envelope.ExecutorChallenge) || !setupHash.MatchString(envelope.RequestID) || envelope.DeadlineUnixMS <= time.Now().UnixMilli() || envelope.DeadlineUnixMS > time.Now().Add(10*time.Second).UnixMilli() || len(envelope.TargetRetirementAttempts) > 512 {
		return true
	}
	requested := map[string]bool{}
	for _, id := range envelope.TargetRetirementAttempts {
		if !fingerprintV2ID.MatchString(id) || requested[id] {
			return true
		}
		requested[id] = true
	}
	request := envelope.reconnectBindingsRequest
	fences, digest, e := reconnectBindingLineage(request.Pending, request.ScopeHash)
	if e != nil {
		return true
	}
	b.mu.Lock()
	valid := b.reconnectBindings != nil && c.conn == conn && !c.fixtureOnly && c.reconnectBindings == nil && (envelope.TargetRetirementAttempts == nil || c.playwrightTargetRetirementVersion == 1) && request.ExecutorChallenge == c.executorChallenge && request.BrokerEpoch == b.epoch && request.ChannelEpoch == c.epoch && request.ScopeHash == c.scopeHash && channelScopeQualified(c) && !c.executorQualified
	if !valid {
		b.mu.Unlock()
		return true
	}
	p := c.grant.Principal
	ctx, cancel := context.WithDeadline(auth.WithPrincipal(context.Background(), p), time.UnixMilli(request.DeadlineUnixMS))
	x := &reconnectBindingExchange{requestID: request.RequestID, conn: conn, finish: make(chan reconnectBindingProgress, 1), prepared: make(chan struct{}), cancel: cancel, deadline: time.UnixMilli(request.DeadlineUnixMS)}
	x.targetRetirementAttempts = append([]string(nil), envelope.TargetRetirementAttempts...)
	c.reconnectBindings = x
	scope := ReconnectBindingScope{c.grant.ProfileChannel, c.grant.BrowserInstance, c.scopeHash, digest, fences}
	evidence := c.processEvidence
	provider := b.reconnectBindings
	targetRetirement := c.playwrightTargetRetirementVersion == 1
	b.mu.Unlock()
	go func() {
		defer cancel()
		defer func() {
			b.mu.Lock()
			if c.reconnectBindings == x {
				if !x.published && c.conn == conn {
					c.executorChallenge = newID()
				}
				c.reconnectBindings = nil
			}
			b.mu.Unlock()
		}()
		check := func(ctx context.Context) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if b.verifyChannelProcess(ctx, c) != nil {
				return errReconnectBindings
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.closed || b.channels[channelKey(scope.ProfileChannel, scope.BrowserInstance)] != c || c.processEvidence == nil || c.processEvidence != evidence || c.conn != conn || c.reconnectBindings != x || c.executorChallenge != request.ExecutorChallenge || b.epoch != request.BrokerEpoch || c.epoch != request.ChannelEpoch || c.scopeHash != request.ScopeHash || !channelScopeQualified(c) || c.executorQualified != x.published || c.lifecycleInhibited || !reconnectRetirementPendingOnlyLocked(c) || len(c.unknown) > 0 && !targetRetirement || c.playwright != nil || c.privateFlow != nil || c.privacy != nil || c.privateInspection != nil || c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil || c.manualPending != nil {
				return errReconnectBindings
			}
			return nil
		}
		send := func(value any) error {
			if check(ctx) != nil {
				return errReconnectBindings
			}
			for !c.writeMu.TryLock() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
			defer c.writeMu.Unlock()
			if check(ctx) != nil {
				return errReconnectBindings
			}
			_ = conn.SetWriteDeadline(time.UnixMilli(request.DeadlineUnixMS))
			e := WriteFrame(conn, value)
			_ = conn.SetWriteDeadline(time.Time{})
			return e
		}
		e := provider(ctx, p, scope, check, func(rows []ReconnectBinding) error {
			if rows == nil {
				rows = []ReconnectBinding{}
			}
			if len(rows) > 4096 {
				return errReconnectBindings
			}
			// The immutable original lease is metadata for target retirement, never
			// a fresh input lease. Legacy workers retain their closed row shape.
			if !targetRetirement {
				original := rows
				rows = make([]ReconnectBinding, len(original))
				copy(rows, original)
				for i := range rows {
					rows[i].ControlLease = nil
				}
			}
			encoded, err := json.Marshal(rows)
			if err != nil {
				return errReconnectBindings
			}
			sum := sha256.Sum256(encoded)
			bindingDigest := hex.EncodeToString(sum[:])
			for offset := 0; ; {
				next := offset + 128
				if next > len(rows) {
					next = len(rows)
				}
				reply := struct {
					Type           string             `json:"type"`
					RequestID      string             `json:"requestId"`
					PendingDigest  string             `json:"pendingDigest"`
					BindingsDigest string             `json:"bindingsDigest"`
					Total          int                `json:"total"`
					Offset         int                `json:"offset"`
					NextOffset     int                `json:"nextOffset"`
					Bindings       []ReconnectBinding `json:"bindings"`
				}{"reconnectBindingsResult", request.RequestID, digest, bindingDigest, len(rows), offset, next, rows[offset:next]}
				if err = send(reply); err != nil {
					return err
				}
				select {
				case progress := <-x.finish:
					if next == len(rows) {
						if !progress.Done || !progress.Complete {
							return errReconnectBindings
						}
						if check(ctx) != nil {
							return errReconnectBindings
						}
						if targetRetirement {
							if err := b.retireReconnectTargets(ctx, c, x, rows, check); err != nil {
								return err
							}
						}
						b.mu.Lock()
						x.ready = true
						b.mu.Unlock()
						// Keep the Host user admission lock through the actual
						// local commit and normal executorPrepared boundary.
						if err := send(struct {
							Type      string `json:"type"`
							RequestID string `json:"requestId"`
							Complete  bool   `json:"complete"`
						}{"reconnectBindingsCommitReady", request.RequestID, true}); err != nil {
							return err
						}
						select {
						case <-x.prepared:
							return check(ctx)
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if progress.Done || progress.NextOffset != next {
						return errReconnectBindings
					}
					offset = next
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
		if e != nil {
			_ = send(struct {
				Type      string `json:"type"`
				RequestID string `json:"requestId"`
				Reason    string `json:"reason"`
			}{"reconnectBindingsFailure", request.RequestID, "historyUnavailable"})
		}
	}()
	return true
}
