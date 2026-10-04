package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/viant/jsonrpc"
	"github.com/viant/jsonrpc/transport"
)

type connection interface {
	transport.Transport
	Close() error
}
type connectionGeneration struct {
	client connection
	number uint64
}

// recoveringTransport creates a new MCP session for a subsequent request after
// a failed connection. It never resends the request whose outcome was uncertain.
// Only the protocol handshake is repeated; tool/session/workflow operations are
// never retained for replay. Old-generation errors cannot invalidate a new peer.
type recoveringTransport struct {
	owner            context.Context
	create           func(context.Context) (connection, error)
	mu               sync.Mutex
	current          *connectionGeneration
	generation       uint64
	initializeParams json.RawMessage
	initialized      bool
	closed           bool
	reconnectLane    chan struct{}
}

func newRecoveringTransport(owner context.Context, initial connection, create func(context.Context) (connection, error)) *recoveringTransport {
	return &recoveringTransport{owner: owner, create: create, current: &connectionGeneration{client: initial, number: 1}, generation: 1, reconnectLane: make(chan struct{}, 1)}
}
func (r *recoveringTransport) invalidate(generation *connectionGeneration) {
	r.mu.Lock()
	matched := r.current == generation
	if matched {
		r.current = nil
	}
	r.mu.Unlock()
	if matched {
		generation.client.Close()
	}
}
func (r *recoveringTransport) acquire(ctx context.Context) (*connectionGeneration, error) {
	r.mu.Lock()
	current, closed := r.current, r.closed
	r.mu.Unlock()
	if closed || r.owner.Err() != nil {
		return nil, errors.New("MCP relay closed")
	}
	if current != nil {
		return current, ctx.Err()
	}
	select {
	case r.reconnectLane <- struct{}{}:
		defer func() { <-r.reconnectLane }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.owner.Done():
		return nil, r.owner.Err()
	}
	r.mu.Lock()
	current, closed = r.current, r.closed
	params := bytes.Clone(r.initializeParams)
	initialized := r.initialized
	r.generation++
	number := r.generation
	r.mu.Unlock()
	if closed || r.owner.Err() != nil {
		return nil, errors.New("MCP relay closed")
	}
	if current != nil {
		return current, ctx.Err()
	}
	client, err := r.create(r.owner)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			client.Close()
		}
	}()
	if initialized {
		reply, err := client.Send(ctx, &jsonrpc.Request{Id: fmt.Sprintf("mechanize-relay-initialize-%d", number), Jsonrpc: "2.0", Method: "initialize", Params: params})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, errMCPProtocolReconnect
		}
		if reply == nil || reply.Error != nil {
			return nil, errMCPProtocolReconnect
		}
		if err = client.Notify(ctx, &jsonrpc.Notification{Jsonrpc: "2.0", Method: "notifications/initialized", Params: json.RawMessage(`{}`)}); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, errMCPProtocolReconnect
		}
	}
	generation := &connectionGeneration{client: client, number: number}
	r.mu.Lock()
	if r.closed || r.owner.Err() != nil {
		r.mu.Unlock()
		return nil, errors.New("MCP relay closed")
	}
	r.current = generation
	r.mu.Unlock()
	keep = true
	return generation, nil
}
func (r *recoveringTransport) Send(ctx context.Context, request *jsonrpc.Request) (*jsonrpc.Response, error) {
	generation, err := r.acquire(ctx)
	if err != nil {
		return nil, err
	}
	reply, err := generation.client.Send(ctx, request)
	if err != nil {
		r.invalidate(generation)
		return nil, err
	}
	if request.Method == "initialize" && reply != nil && reply.Error == nil {
		r.mu.Lock()
		if r.current == generation {
			r.initializeParams = bytes.Clone(request.Params)
			r.initialized = true
		}
		r.mu.Unlock()
	}
	return reply, nil
}
func (r *recoveringTransport) Notify(ctx context.Context, notification *jsonrpc.Notification) error {
	// A cancellation refers to an existing operation, never a request to establish
	// new authority/session. Only a later Send is allowed to reconnect.
	r.mu.Lock()
	generation, closed := r.current, r.closed
	r.mu.Unlock()
	if generation == nil || closed {
		return errors.New("MCP connection unavailable")
	}
	err := generation.client.Notify(ctx, notification)
	if err != nil {
		r.invalidate(generation)
	}
	return err
}
func (r *recoveringTransport) Close() error {
	r.mu.Lock()
	r.closed = true
	generation := r.current
	r.current = nil
	r.mu.Unlock()
	if generation != nil {
		return generation.client.Close()
	}
	return nil
}
