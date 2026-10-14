package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/model"
)

func TestPreWriteCancellationRetainsChannelAndOriginalHistoryWithoutLateDispatch(t *testing.T) {
	for _, mutation := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "mutation"}[mutation], func(t *testing.T) {
			f := newReadFixture(t)
			b := f.g.broker
			c := b.channels[channelKey("p1", "b1")]
			b.mu.Lock()
			originalConn := c.conn
			original := Command{AttemptID: "historical-original", Identity: readTargetIdentity()}
			c.retiredTargets = map[string]Command{original.AttemptID: original}
			c.attempts[original.AttemptID] = original
			c.receipts[original.AttemptID] = Reply{AttemptID: original.AttemptID, DispatchState: "unknown", EffectState: "unknown"}
			history, _ := json.Marshal([]any{c.retiredTargets, c.attempts, c.receipts, c.unknown})
			b.mu.Unlock()
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			entered, release, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var checks int
			done := make(chan error, 1)
			command := Command{Action: "executor.acquire", Identity: readTargetIdentity()}
			if mutation {
				command.Action, command.AttemptID = "element.press", "unsent-original"
			}
			go func() {
				_, err := b.call(ctx, c, command, mutation, func() error {
					checks++
					if checks == 1 {
						return nil
					}
					close(entered)
					<-release // Deliberately ignores cancellation until the test drains it.
					defer close(drained)
					return nil
				})
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("async pre-write check not reached")
			}
			cancel()
			select {
			case err := <-done:
				var detail *model.MechanizeError
				if !errors.As(err, &detail) || detail.DispatchState != "notDispatched" {
					t.Error("proven unsent cancellation lost absence", err)
				}
				if !mutation {
					phase, reason := ControlFailureDiagnostic(err)
					if phase != "acquirePreWrite" || reason != "cancelled" {
						t.Error("wrong cancellation boundary", phase, reason)
					}
				}
			case <-time.After(time.Second):
				t.Error("caller waited for uncooperative pre-write guard")
			}
			b.mu.Lock()
			pending := len(c.pending)
			connected := c.conn == originalConn
			retained, _ := json.Marshal([]any{c.retiredTargets, c.attempts, c.receipts, c.unknown})
			b.mu.Unlock()
			if pending != 0 || !connected || string(history) != string(retained) {
				t.Error("unsent cleanup changed shared channel or original history")
			}
			close(release)
			<-drained
			fresh, err := b.call(f.ctx, c, Command{Action: "read", Identity: readTargetIdentity()}, false)
			if err != nil || fresh.Value == nil || f.reads.Load() != 1 || f.acquireCalls.Load() != 0 || f.mutations.Load() != 0 {
				t.Fatal("fresh distinct call failed or cancelled command wrote late", err)
			}
		})
	}
}

// A blocking transport proves the started-write side of the boundary, including
// partial framing. It is installed only in a fixture's existing connection slot.
type cancellationWriteConn struct {
	net.Conn
	partial bool
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	writes  atomic.Int32
}

type completedWriteConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	closed  atomic.Bool
}

func (c *completedWriteConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		close(c.entered)
		<-c.release
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *completedWriteConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *cancellationWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) != 1 {
		return c.Conn.Write(p)
	}
	n := 0
	if c.partial {
		var err error
		n, err = c.Conn.Write(p[:1])
		if err != nil {
			return n, err
		}
	}
	close(c.entered)
	<-c.closed
	return n, net.ErrClosed
}

func (c *cancellationWriteConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestCancellationAfterWriteStartsClosesTransportAndRetainsMutationUnknown(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "started", true: "partialHeader"}[partial], func(t *testing.T) {
			f := newReadFixture(t)
			b := f.g.broker
			c := b.channels[channelKey("p1", "b1")]
			b.mu.Lock()
			conn := &cancellationWriteConn{Conn: c.conn, partial: partial, entered: make(chan struct{}), closed: make(chan struct{})}
			c.conn, c.fixtureOnly = conn, true
			b.mu.Unlock()
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := b.call(ctx, c, Command{Action: "element.press", Identity: readTargetIdentity(), AttemptID: "started-original"}, true)
				done <- err
			}()
			select {
			case <-conn.entered:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			cancel()
			select {
			case err := <-done:
				var detail *model.MechanizeError
				if !errors.As(err, &detail) || detail.DispatchState != "unknown" {
					t.Fatal("started write lost original uncertainty", err)
				}
			case <-time.After(time.Second):
				t.Fatal("started write cancellation did not return")
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("possibly partial frame retained transport")
			}
			b.mu.Lock()
			unknown := c.unknown["started-original"]
			_, retained := c.attempts["started-original"]
			b.mu.Unlock()
			if !unknown || !retained || conn.writes.Load() != 1 {
				t.Fatal("started request was erased or replayed")
			}
		})
	}
}

func TestCancellationAfterCompletedWriteKeepsOriginalLateReceipt(t *testing.T) {
	f := newReadFixture(t)
	b := f.g.broker
	c := b.channels[channelKey("p1", "b1")]
	f.publicReadDelay.Store(150)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := b.call(ctx, c, Command{Action: "element.press", Identity: readTargetIdentity(), AttemptID: "late-original"}, true)
		done <- err
	}()
	waitControl(t, func() bool { return f.mutations.Load() == 1 })
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled receipt wait unexpectedly succeeded")
	}
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return !c.unknown["late-original"] && c.receipts["late-original"].DispatchState == "dispatched" && len(c.pending) == 0
	})
	b.mu.Lock()
	connected := c.conn != nil
	b.mu.Unlock()
	if !connected || f.mutations.Load() != 1 {
		t.Fatal("completed original frame was replayed or lost transport")
	}
}

func TestQueuedPreWriteDeadlinePreservesConcurrentOwnerAndPreventsLateWrite(t *testing.T) {
	f := newReadFixture(t)
	b := f.g.broker
	c := b.channels[channelKey("p1", "b1")]
	b.mu.Lock()
	originalConn := c.conn
	b.mu.Unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	var checks int
	go func() {
		_, err := b.call(f.ctx, c, Command{Action: "executor.acquire", Identity: readTargetIdentity()}, false, func() error {
			checks++
			if checks == 2 {
				close(entered)
				<-release
			}
			return nil
		})
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first owner did not reach async guard")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() {
		_, err := b.call(ctx, c, Command{Action: "read", Identity: readTargetIdentity()}, false)
		second <- err
	}()
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(c.pending) == 2
	})
	select {
	case err := <-second:
		var detail *model.MechanizeError
		if !errors.As(err, &detail) || detail.Code != "dispatchGateExpired" || detail.DispatchState != "notDispatched" {
			t.Error("queued unsent deadline lost absence", err)
		}
	case <-time.After(time.Second):
		t.Error("queued caller waited beyond deadline for write lock")
	}
	b.mu.Lock()
	retained := c.conn == originalConn && len(c.pending) == 1
	b.mu.Unlock()
	if !retained {
		t.Error("queued cancellation removed independent pending owner")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal("independent original owner failed", err)
	}
	if _, err := b.call(f.ctx, c, Command{Action: "read", Identity: readTargetIdentity()}, false); err != nil || f.reads.Load() != 1 || f.acquireCalls.Load() != 1 {
		t.Fatal("cancelled queued command wrote late or fresh call failed", err)
	}
}

func TestCancellationBetweenCompletedFrameAndOuterConsumptionRetainsConnection(t *testing.T) {
	f := newReadFixture(t)
	b := f.g.broker
	c := b.channels[channelKey("p1", "b1")]
	f.publicReadDelay.Store(150)
	b.mu.Lock()
	conn := &completedWriteConn{Conn: c.conn, entered: make(chan struct{}), release: make(chan struct{})}
	c.conn, c.fixtureOnly = conn, true
	b.mu.Unlock()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := b.call(ctx, c, Command{Action: "element.press", Identity: readTargetIdentity(), AttemptID: "complete-original"}, true)
		done <- err
	}()
	select {
	case <-conn.entered: // WriteFrame succeeded; written cannot yet be published.
	case <-time.After(time.Second):
		t.Fatal("complete frame did not reach delayed outer publication")
	}
	cancel()
	select {
	case err := <-done:
		var detail *model.MechanizeError
		if !errors.As(err, &detail) || detail.DispatchState != "unknown" {
			t.Error("receipt-wait cancellation lost original uncertainty", err)
		}
	case <-time.After(time.Second):
		t.Error("completed-frame cancellation waited for writer publication")
	}
	if conn.closed.Load() {
		t.Error("proven complete framing unnecessarily closed connection")
	}
	close(conn.release)
	// Restore the same physical connection after the transport hook drains.
	c.writeMu.Lock()
	b.mu.Lock()
	c.conn, c.fixtureOnly = conn.Conn, false
	b.mu.Unlock()
	c.writeMu.Unlock()
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return c.receipts["complete-original"].DispatchState == "dispatched" && !c.unknown["complete-original"]
	})
	f.publicReadDelay.Store(0)
	if _, err := b.call(f.ctx, c, Command{Action: "read", Identity: readTargetIdentity()}, false); err != nil || f.mutations.Load() != 1 || f.reads.Load() != 1 {
		t.Fatal("original receipt lost, request replayed or same-connection read failed", err)
	}
}
