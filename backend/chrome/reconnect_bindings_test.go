package chrome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func reconnectPendingFixture(scope string) json.RawMessage {
	v := map[string]any{"version": 1, "phase": "pending", "nonce": strings.Repeat("b", 64), "oldFence": ReconnectFence{"old-broker", "old-channel", scope}, "newFence": ReconnectFence{"partial-broker", "partial-channel", scope}, "history": []any{}}
	r, _ := json.Marshal(v)
	return r
}
func TestReconnectBindingLineageClosedAndScopeBound(t *testing.T) {
	for _, mode := range []string{"valid", "foreign", "extra", "badNonce", "archive"} {
		t.Run(mode, func(t *testing.T) {
			scope := strings.Repeat("a", 64)
			raw := reconnectPendingFixture(scope)
			var m map[string]any
			json.Unmarshal(raw, &m)
			switch mode {
			case "foreign":
				m["oldFence"] = ReconnectFence{"old", "old", strings.Repeat("c", 64)}
			case "extra":
				m["privateValue"] = "SECRET-CANARY"
			case "badNonce":
				m["nonce"] = "short"
			case "archive":
				m["archive"] = map[string]any{"digest": strings.Repeat("d", 64), "nonce": strings.Repeat("e", 64), "segments": 1, "endFence": ReconnectFence{"archive-broker", "archive-channel", scope}}
			}
			raw, _ = json.Marshal(m)
			f, d, e := reconnectBindingLineage(raw, scope)
			if mode == "valid" || mode == "archive" {
				if e != nil || len(f) < 2 || len(d) != 64 {
					t.Fatal("valid bounded lineage denied", e)
				}
			} else if e == nil {
				t.Fatal("untrusted lineage accepted")
			}
		})
	}
}
func TestReconnectBindingsHoldsAuthenticatedCallbackUntilWorkerCompletion(t *testing.T) {
	for _, mode := range []string{"complete", "cancel", "replacement", "challenge", "unknown", "private", "writerDeadline"} {
		t.Run(mode, func(t *testing.T) {
			g, p, _, c, conn := setupFixture(t)
			b := g.broker
			called := make(chan bool, 1)
			finished := make(chan error, 1)
			b.mu.Lock()
			b.reconnectBindings = func(ctx context.Context, actual auth.Principal, scope ReconnectBindingScope, check func(context.Context) error, consume func([]ReconnectBinding) error) error {
				if actual.Namespace != p.Namespace || scope.ProfileChannel != c.grant.ProfileChannel || scope.ScopeHash != c.scopeHash {
					t.Error("foreign read authority")
				}
				called <- true
				if e := check(ctx); e != nil {
					finished <- e
					return e
				}
				e := consume([]ReconnectBinding{})
				finished <- e
				return e
			}
			if mode == "unknown" {
				c.unknown["original"] = true
			}
			if mode == "private" {
				c.privateFlow = &credentialFlow{}
			}
			b.mu.Unlock()
			if mode == "writerDeadline" {
				c.writeMu.Lock()
				defer c.writeMu.Unlock()
			}
			deadline := time.Now().Add(400 * time.Millisecond)
			q := reconnectBindingsRequest{"reconnectBindings", c.executorChallenge, strings.Repeat("a", 64), b.epoch, c.epoch, c.scopeHash, deadline.UnixMilli(), reconnectPendingFixture(c.scopeHash)}
			if e := WriteFrame(conn, q); e != nil {
				t.Fatal(e)
			}
			select {
			case <-called:
			case <-time.After(time.Second):
				t.Fatal("callback not reached")
			}
			if mode == "unknown" || mode == "private" || mode == "writerDeadline" {
				select {
				case e := <-finished:
					if e == nil {
						t.Fatal("barrier released")
					}
				case <-time.After(time.Second):
					t.Fatal("bounded callback did not finish")
				}
				return
			}
			raw, e := ReadFrame(conn)
			if e != nil {
				t.Fatal(e)
			}
			var reply struct {
				Type      string
				RequestID string
				Bindings  []ReconnectBinding
			}
			if json.Unmarshal(raw, &reply) != nil || reply.Type != "reconnectBindingsResult" {
				t.Fatal("closed metadata reply unavailable")
			}
			select {
			case <-finished:
				t.Fatal("user lock callback released before proof")
			default:
			}
			if mode == "replacement" {
				b.mu.Lock()
				copy := *c.processEvidence
				copy.ChromeParent.StartToken = "different"
				c.processEvidence = &copy
				b.mu.Unlock()
			}
			if mode == "challenge" {
				b.mu.Lock()
				c.executorChallenge = newID()
				b.mu.Unlock()
			}
			if e = WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": q.RequestID, "complete": mode != "cancel"}); e != nil {
				t.Fatal(e)
			}
			if mode == "complete" {
				raw, e = ReadFrame(conn)
				if e != nil || !strings.Contains(string(raw), "reconnectBindingsCommitReady") {
					t.Fatal("commit readiness missing", e)
				}
				select {
				case <-finished:
					t.Fatal("admission released before local commit")
				default:
				}
				b.mu.Lock()
				qualified := c.executorQualified
				challenge := c.executorChallenge
				b.mu.Unlock()
				if qualified {
					t.Fatal("ready message granted executor")
				}
				if e = WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2}); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case e = <-finished:
				if (e == nil) != (mode == "complete") {
					t.Fatal("wrong terminal proof", mode, e)
				}
			case <-time.After(time.Second):
				t.Fatal("completion blocked")
			}

			b.mu.Lock()
			defer b.mu.Unlock()
			if c.executorQualified != (mode == "complete") || c.inventoryComplete {
				t.Fatal("metadata callback granted executor")
			}
		})
	}
}

func TestReconnectBindingsChunkedCoverageAndCursorRefusal(t *testing.T) {
	for _, mode := range []int{0, 130, 4096, -130} {
		badCursor := mode < 0
		count := mode
		if count < 0 {
			count = -count
		}
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			g, _, _, c, conn := setupFixture(t)
			b := g.broker
			done := make(chan error, 1)
			rows := make([]ReconnectBinding, count)
			for i := range rows {
				rows[i] = ReconnectBinding{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "absent", Generation: 1}, Fence: ReconnectFence{"old", "old", c.scopeHash}, AttemptID: fmt.Sprintf("%064x", i+1), Fingerprint: strings.Repeat("f", 64), DispatchState: "dispatched"}
			}
			b.mu.Lock()
			b.reconnectBindings = func(ctx context.Context, _ auth.Principal, _ ReconnectBindingScope, check func(context.Context) error, consume func([]ReconnectBinding) error) error {
				e := check(ctx)
				if e == nil {
					e = consume(rows)
				}
				done <- e
				return e
			}
			b.mu.Unlock()
			q := reconnectBindingsRequest{"reconnectBindings", c.executorChallenge, strings.Repeat("e", 64), b.epoch, c.epoch, c.scopeHash, time.Now().Add(2 * time.Second).UnixMilli(), reconnectPendingFixture(c.scopeHash)}
			if e := WriteFrame(conn, q); e != nil {
				t.Fatal(e)
			}
			collected := []ReconnectBinding{}
			var digest string
			pages := (count + 127) / 128
			if pages == 0 {
				pages = 1
			}
			for page := 0; page < pages; page++ {
				raw, e := ReadFrame(conn)
				if e != nil {
					t.Fatal(e)
				}
				var reply struct {
					Type, RequestID, PendingDigest, BindingsDigest string
					Total, Offset, NextOffset                      int
					Bindings                                       []ReconnectBinding
				}
				if json.Unmarshal(raw, &reply) != nil || reply.Type != "reconnectBindingsResult" || reply.Total != count || reply.Offset != len(collected) || len(reply.Bindings) > 128 {
					t.Fatal("incomplete page")
				}
				collected = append(collected, reply.Bindings...)
				if digest != "" && digest != reply.BindingsDigest {
					t.Fatal("digest drift")
				}
				digest = reply.BindingsDigest
				if page < pages-1 {
					offset := reply.NextOffset
					if badCursor {
						offset++
					}
					WriteFrame(conn, map[string]any{"type": "reconnectBindingsNext", "requestId": q.RequestID, "nextOffset": offset})
					if badCursor {
						if e = <-done; e == nil {
							t.Fatal("invalid cursor accepted")
						}
						return
					}
				}
			}
			raw, _ := json.Marshal(collected)
			sum := sha256.Sum256(raw)
			if len(collected) != count || hex.EncodeToString(sum[:]) != digest {
				t.Fatal("coverage lost")
			}
			select {
			case <-done:
				t.Fatal("released before final proof")
			default:
			}
			WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": q.RequestID, "complete": true})
			ready, e := ReadFrame(conn)
			if e != nil || !strings.Contains(string(ready), "reconnectBindingsCommitReady") {
				t.Fatal("commit readiness missing", e)
			}
			select {
			case <-done:
				t.Fatal("released before original journal commit")
			default:
			}
			b.mu.Lock()
			challenge := c.executorChallenge
			b.mu.Unlock()
			WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2})
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestReconnectClosedRejectsDuplicateKeysAndCapacity(t *testing.T) {
	for _, raw := range []string{`{"type":"x","type":"y"}`, `{"nested":[{"a":1,"a":2}]}`, strings.Repeat("[", 22) + "0" + strings.Repeat("]", 22), `{} {}`} {
		if uniqueReconnectJSON([]byte(raw)) {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	if !uniqueReconnectJSON([]byte(`{"nested":[{"a":1},{"a":2}]}`)) {
		t.Fatal("separate array objects rejected")
	}
}

func TestReconnectBindingsCommitReadinessNeverPublishesWithoutCurrentPrepared(t *testing.T) {
	for _, mode := range []string{"missingPrepared", "earlyPrepared", "staleDone", "duplicateDone", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			g, _, _, c, conn := setupFixture(t)
			b := g.broker
			done := make(chan error, 1)
			b.mu.Lock()
			b.reconnectBindings = func(ctx context.Context, _ auth.Principal, _ ReconnectBindingScope, _ func(context.Context) error, consume func([]ReconnectBinding) error) error {
				e := consume(nil)
				done <- e
				return e
			}
			challenge := c.executorChallenge
			b.mu.Unlock()
			q := reconnectBindingsRequest{"reconnectBindings", c.executorChallenge, strings.Repeat("f", 64), b.epoch, c.epoch, c.scopeHash, time.Now().Add(180 * time.Millisecond).UnixMilli(), reconnectPendingFixture(c.scopeHash)}
			if e := WriteFrame(conn, q); e != nil {
				t.Fatal(e)
			}
			raw, e := ReadFrame(conn)
			if e != nil || !strings.Contains(string(raw), `"bindings":[]`) {
				t.Fatal("empty snapshot is not canonical", e)
			}
			switch mode {
			case "earlyPrepared":
				WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2})
			case "staleDone":
				WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": strings.Repeat("0", 64), "complete": true})
			case "disconnect":
				conn.Close()
			default:
				WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": q.RequestID, "complete": true})
				raw, e = ReadFrame(conn)
				if e != nil || !strings.Contains(string(raw), "reconnectBindingsCommitReady") {
					t.Fatal("commit acknowledgement missing", e)
				}
				if mode == "duplicateDone" {
					WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": q.RequestID, "complete": true})
				}
			}
			select {
			case e = <-done:
				if e == nil {
					t.Fatal("uncommitted proof accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("guard did not release within deadline")
			}
			waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.reconnectBindings == nil })
			b.mu.Lock()
			qualified := c.executorQualified
			newChallenge := c.executorChallenge
			b.mu.Unlock()
			if qualified {
				t.Fatal("missing/stale completion granted executor")
			}
			if mode != "disconnect" && mode != "earlyPrepared" {
				if challenge == newChallenge {
					t.Fatal("expired proof retained original publication challenge")
				}
				WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2})
				waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.conn == nil })
				b.mu.Lock()
				qualified = c.executorQualified
				b.mu.Unlock()
				if qualified {
					t.Fatal("late prepared reply granted executor")
				}
			}
		})
	}
}

func TestReconnectRequestExactChallengeAndTopScalarSchema(t *testing.T) {
	g, _, _, c, _ := setupFixture(t)
	b := g.broker
	b.mu.Lock()
	b.reconnectBindings = func(context.Context, auth.Principal, ReconnectBindingScope, func(context.Context) error, func([]ReconnectBinding) error) error {
		t.Error("invalid request reached lifecycle")
		return nil
	}
	server := c.conn
	challenge := c.executorChallenge
	b.mu.Unlock()
	for _, mode := range []string{"challenge", "missingChallenge", "nullChallenge", "deadlineString", "extra", "nullPending", "duplicate"} {
		request := reconnectBindingsRequest{"reconnectBindings", challenge, strings.Repeat("a", 64), b.epoch, c.epoch, c.scopeHash, time.Now().Add(time.Second).UnixMilli(), reconnectPendingFixture(c.scopeHash)}
		raw, _ := json.Marshal(request)
		var object map[string]any
		json.Unmarshal(raw, &object)
		switch mode {
		case "challenge":
			object["executorChallenge"] = "old"
		case "missingChallenge":
			delete(object, "executorChallenge")
		case "nullChallenge":
			object["executorChallenge"] = nil
		case "deadlineString":
			object["deadlineUnixMs"] = "999999999"
		case "extra":
			object["privateValue"] = "PRIVATE-CANARY"
		case "nullPending":
			object["pending"] = nil
		}
		raw, _ = json.Marshal(object)
		if mode == "duplicate" {
			raw = append([]byte(`{"executorChallenge":"old",`), raw[1:]...)
		}
		if !b.acceptReconnectBindings(c, server, raw) {
			t.Fatal("request not classified")
		}
		b.mu.Lock()
		present := c.reconnectBindings != nil
		b.mu.Unlock()
		if present {
			t.Fatal("invalid request installed guard", mode)
		}
	}
}
func TestReconnectLineageSupportsWriterFrameBudgetAbove128KiB(t *testing.T) {
	scope := strings.Repeat("a", 64)
	var pending map[string]any
	json.Unmarshal(reconnectPendingFixture(scope), &pending)
	rows := make([]map[string]any, 200)
	for i := range rows {
		rows[i] = map[string]any{"identity": Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: i + 1, FrameID: 0, DocumentID: strings.Repeat("d", 128), Generation: 1}, "receiptRevision": 0, "receiptCount": 0}
	}
	history := []any{}
	for i := 0; i < 3; i++ {
		history = append(history, map[string]any{"nonce": fmt.Sprintf("%064x", i+10), "oldFence": ReconnectFence{fmt.Sprint("old", i), fmt.Sprint("old", i), scope}, "newFence": ReconnectFence{fmt.Sprint("old", i+1), fmt.Sprint("old", i+1), scope}, "executors": rows})
	}
	pending["history"] = history
	raw, _ := json.Marshal(pending)
	if len(raw) <= 128*1024 || len(raw) >= MaxFrameBytes {
		t.Fatal("fixture not in writer-reader gap", len(raw))
	}
	if _, _, e := reconnectBindingLineage(raw, scope); e != nil {
		t.Fatal("writer-sized lineage denied", e)
	}
	if _, _, e := reconnectBindingLineage(make([]byte, MaxFrameBytes+1), scope); e == nil {
		t.Fatal("unbounded lineage admitted")
	}
}

func TestReconnectPendingArchiveReferenceClosedScopeAndBounds(t *testing.T) {
	scope := strings.Repeat("a", 64)
	for _, mode := range []string{"valid", "both", "missing", "null", "foreign", "version", "bytes", "nonce", "extra"} {
		var value map[string]any
		json.Unmarshal(reconnectPendingFixture(scope), &value)
		value["version"] = 2
		ref := map[string]any{"digest": strings.Repeat("d", 64), "bytes": 155503, "version": 1, "nonce": strings.Repeat("e", 64), "oldFence": ReconnectFence{"original", "original", scope}, "newFence": ReconnectFence{"abandoned", "abandoned", scope}}
		recovery := map[string]any{"kind": "verifiedCurrentDocuments", "originalPendingRef": ref}
		value["recovery"] = recovery
		switch mode {
		case "both":
			recovery["originalPending"] = json.RawMessage(reconnectPendingFixture(scope))
		case "missing":
			delete(recovery, "originalPendingRef")
		case "null":
			recovery["originalPendingRef"] = nil
		case "foreign":
			ref["oldFence"] = ReconnectFence{"original", "original", strings.Repeat("f", 64)}
		case "version":
			ref["version"] = 2
		case "bytes":
			ref["bytes"] = MaxFrameBytes + 1
		case "nonce":
			ref["nonce"] = value["nonce"]
		case "extra":
			ref["private"] = "PRIVATE_CANARY"
		}
		raw, _ := json.Marshal(value)
		fences, digest, err := reconnectBindingLineage(raw, scope)
		if mode == "valid" {
			if err != nil || len(fences) != 4 || len(digest) != 64 {
				t.Fatal("exact archived pending metadata refused", err)
			}
		} else if err == nil {
			t.Fatal("invalid archived predecessor accepted", mode)
		}
	}
}

func TestProductionWorkerPendingArchiveRestartThroughBindingTransport(t *testing.T) {
	g, p, _, c, conn := setupFixture(t)
	command := map[string]any{"type": "processQualified", "brokerEpoch": g.broker.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash, "executorChallenge": c.executorChallenge, "mutationFingerprintVersion": 2, "fixtureOnly": false, "trustScope": "desktop", "scopeQualified": true, "profileQualified": false, "executorQualified": false}
	input, _ := json.Marshal(map[string]any{"command": command})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "node", "testdata/worker_pending_archive.cjs")
	child.Stdin = bytes.NewReader(input)
	output, e := child.CombinedOutput()
	if e != nil {
		t.Fatalf("production worker archived recovery failed: %v %s", e, output)
	}
	var result struct {
		Pending       json.RawMessage `json:"pending"`
		OriginalBytes int             `json:"originalBytes"`
		Preserved     bool            `json:"preserved"`
		Restarted     bool            `json:"restarted"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Preserved || !result.Restarted || result.OriginalBytes < 128<<10 {
		t.Fatal("bounded original predecessor proof missing")
	}
	if _, _, e = reconnectBindingLineage(result.Pending, c.scopeHash); e != nil {
		t.Fatal("actual worker reference rejected", e)
	}
	finished := make(chan error, 1)
	g.broker.mu.Lock()
	g.broker.reconnectBindings = func(ctx context.Context, actual auth.Principal, scope ReconnectBindingScope, check func(context.Context) error, consume func([]ReconnectBinding) error) error {
		if actual.Namespace != p.Namespace || scope.ScopeHash != c.scopeHash {
			return auth.ErrUnauthorized
		}
		e := check(ctx)
		if e == nil {
			e = consume(nil)
		}
		finished <- e
		return e
	}
	g.broker.mu.Unlock()
	request := reconnectBindingsRequest{"reconnectBindings", c.executorChallenge, strings.Repeat("f", 64), g.broker.epoch, c.epoch, c.scopeHash, time.Now().Add(2 * time.Second).UnixMilli(), result.Pending}
	if e = WriteFrame(conn, request); e != nil {
		t.Fatal(e)
	}
	raw, e := ReadFrame(conn)
	if e != nil || !bytes.Contains(raw, []byte(`"bindings":[]`)) {
		t.Fatal("exact reference did not reach empty authenticated snapshot", e)
	}
	if e = WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": request.RequestID, "complete": false}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("snapshot guard not released after cancellation")
	}
	g.broker.mu.Lock()
	qualified := c.executorQualified
	g.broker.mu.Unlock()
	if qualified {
		t.Fatal("metadata reference granted executor authority")
	}
}
