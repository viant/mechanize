package localrpc

import (
	"testing"
	"time"
)

func TestRepeatedCloseJoinsOutstandingNativeWorker(t *testing.T) {
	server := &Server{closed: true}
	server.wg.Add(1) // First closer has marked closed; a transaction is still alive.
	done := make(chan struct{})
	go func() { _ = server.Close(); close(done) }()
	select {
	case <-done:
		server.wg.Done()
		t.Fatal("repeated Close falsely reported native transaction quiescence")
	case <-time.After(20 * time.Millisecond):
	}
	server.wg.Done()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("repeated Close did not finish after native worker stopped")
	}
}
