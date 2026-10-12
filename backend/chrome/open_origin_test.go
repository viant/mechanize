package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func TestOpenOriginNoSourceDocumentAndRetainedProtection(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.openOriginVersion = 1
	c.executorQualified = true
	c.privateFlow = &credentialFlow{}
	g.broker.mu.Unlock()
	admitted, epoch, err := g.PrepareOpenOrigin(ctx, p, c.grant.Origins[0])
	if err != nil || epoch <= 0 {
		t.Fatal(epoch, err)
	}
	done := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			done <- e
			return
		}
		var r openOriginRequest
		json.Unmarshal(raw, &r)
		if strings.Contains(string(raw), "identity") || strings.Contains(string(raw), "lease") {
			done <- errors.New("renderer authority leaked")
			return
		}
		done <- WriteFrame(conn, openOriginReply{Type: "browser.openOriginResult", RequestID: r.RequestID, AttemptID: r.AttemptID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, DispatchState: "dispatched", TabID: 77, ErrorCode: "none"})
	}()
	calls := 0
	result, err := g.ExecuteOpenOrigin(admitted, p, c.grant.Origins[0], strings.Repeat("c", 64), func(context.Context) error { calls++; return nil })
	if err != nil || result.DispatchState != "dispatched" || result.Value == nil || !strings.HasSuffix(result.Value.String, "/77") {
		t.Fatal(result, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	g.broker.mu.Lock()
	protected := c.privateFlow != nil && len(c.documents) == 0
	g.broker.mu.Unlock()
	if calls != 2 || !protected {
		t.Fatal("source protection changed")
	}
	if _, err = g.ExecuteOpenOrigin(admitted, p, c.grant.Origins[0], strings.Repeat("d", 64), func(context.Context) error { return nil }); err == nil {
		t.Fatal("admission replay")
	}
}
func TestOpenOriginUnknownLostReplyAndGuards(t *testing.T) {
	for _, mode := range []string{"lost", "extra", "epoch", "denied", "unknown", "unsupported", "readOnlyEnrollment"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.openOriginVersion = 1
			c.executorQualified = true
			if mode == "unknown" {
				c.unknown["prior"] = true
			}
			if mode == "unsupported" {
				c.openOriginVersion = 0
			}
			if mode == "readOnlyEnrollment" {
				c.grant.Principal.Scopes = []string{"desktop:observe"}
			}
			g.broker.mu.Unlock()
			ctx, cancel := context.WithTimeout(base, 100*time.Millisecond)
			defer cancel()
			admitted, _, err := g.PrepareOpenOrigin(ctx, p, c.grant.Origins[0])
			if mode == "unknown" || mode == "unsupported" || mode == "readOnlyEnrollment" {
				if err == nil {
					t.Fatal("barrier accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "epoch" {
				g.broker.mu.Lock()
				c.epoch = "replacement"
				g.broker.mu.Unlock()
			}
			if mode == "extra" || mode == "lost" {
				go func() {
					raw, _ := ReadFrame(conn)
					if mode == "extra" {
						var r openOriginRequest
						json.Unmarshal(raw, &r)
						WriteFrame(conn, map[string]any{"type": "browser.openOriginResult", "requestId": r.RequestID, "url": "PRIVATE-CANARY"})
					}
				}()
			}
			result, err := g.ExecuteOpenOrigin(admitted, p, c.grant.Origins[0], strings.Repeat("e", 64), func(context.Context) error {
				if mode == "denied" {
					return errors.New("denied")
				}
				return nil
			})
			if err == nil {
				t.Fatal("failure accepted")
			}
			expected := "notDispatched"
			if mode == "lost" || mode == "extra" {
				expected = "unknown"
			}
			if result.DispatchState != expected {
				t.Fatal(result)
			}
			if expected == "unknown" {
				g.broker.mu.Lock()
				retained := c.unknown[strings.Repeat("e", 64)]
				g.broker.mu.Unlock()
				if !retained {
					t.Fatal("unknown lost")
				}
			}
		})
	}
}

func TestOpenOriginWriteLaneDeadlineDoesNotDispatch(t *testing.T) {
	g, p, base, c, _ := setupFixture(t)
	g.broker.mu.Lock()
	c.openOriginVersion = 1
	c.executorQualified = true
	g.broker.mu.Unlock()
	ctx, cancel := context.WithTimeout(base, 40*time.Millisecond)
	defer cancel()
	pinned, _, err := g.PrepareOpenOrigin(ctx, p, c.grant.Origins[0])
	if err != nil {
		t.Fatal(err)
	}
	c.writeMu.Lock()
	start := time.Now()
	out, err := g.ExecuteOpenOrigin(pinned, p, c.grant.Origins[0], strings.Repeat("f", 64), func(context.Context) error { return nil })
	c.writeMu.Unlock()
	if err == nil || out.DispatchState != "notDispatched" || time.Since(start) > 250*time.Millisecond {
		t.Fatal("unbounded lane wait", out, err)
	}
}

func TestOpenOriginAuthenticatedNegativePreservesClosedReason(t *testing.T) {
	for _, code := range []string{"authorityChanged", "permissionUnavailable", "windowUnavailable", "receiptCapacity", "unknownEffect", "lifecycleInhibited", "creationUnavailable", "receiptUnavailable", "attemptConflict"} {
		t.Run(code, func(t *testing.T) {
			g, p, ctx, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.openOriginVersion = 1
			c.executorQualified = true
			g.broker.mu.Unlock()
			held, _, e := g.PrepareOpenOrigin(ctx, p, c.grant.Origins[0])
			if e != nil {
				t.Fatal(e)
			}
			go func() {
				raw, e := ReadFrame(conn)
				if e != nil {
					return
				}
				var q openOriginRequest
				json.Unmarshal(raw, &q)
				WriteFrame(conn, openOriginReply{Type: q.Type + "Result", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "notDispatched", ErrorCode: code})
			}()
			result, e := g.ExecuteOpenOrigin(held, p, c.grant.Origins[0], strings.Repeat("d", 64), func(context.Context) error { return nil })
			var reason *model.MechanizeError
			if !errors.As(e, &reason) || reason.Code != code || reason.DispatchState != "notDispatched" || result.DispatchState != "notDispatched" {
				t.Fatal("native reason collapsed", result, e)
			}
			g.broker.mu.Lock()
			unknown := len(c.unknown)
			g.broker.mu.Unlock()
			if unknown != 0 {
				t.Fatal("negative caused unknown")
			}
		})
	}
}
