// Package containerbrowser connects the browser-only host to its private Node
// runtime. Unlike desktop playwrightipc, this worker owns independent contexts
// concurrently and requires no extension callbacks or desktop authority.
package containerbrowser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/model"
)

var ErrUnavailable = errors.New("browser worker unavailable")

type WorkerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Outcome string `json:"outcome"`
}

func (e *WorkerError) Error() string { return e.Code + ": " + e.Message }

type response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *WorkerError    `json:"error"`
}
type Worker struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan response
	serial  atomic.Uint64
	done    chan struct{}
	exited  chan struct{}
	once    sync.Once
}

func Start(ctx context.Context, node, script string, env []string, stderr io.Writer) (*Worker, error) {
	cmd := exec.CommandContext(ctx, node, script)
	cmd.Env = env
	cmd.Stderr = stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("browser stdin: %w", err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("browser stdout: %w", err)
	}
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("browser launch: %w", err)
	}
	w := &Worker{cmd: cmd, input: input, pending: map[string]chan response{}, done: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 2<<20)
		for scanner.Scan() {
			var reply response
			if json.Unmarshal(scanner.Bytes(), &reply) != nil || reply.ID == "" {
				break
			}
			w.mu.Lock()
			target := w.pending[reply.ID]
			delete(w.pending, reply.ID)
			w.mu.Unlock()
			if target != nil {
				target <- reply
			}
		}
		w.fail()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		close(w.exited)
	}()
	return w, nil
}
func (w *Worker) fail() { w.once.Do(func() { close(w.done) }) }

func (w *Worker) Call(ctx context.Context, method, session string, step *model.Step, scales ...float64) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := strconv.FormatUint(w.serial.Add(1), 10)
	scale := 1.0
	if len(scales) > 0 {
		scale = scales[0]
	}
	wire, err := json.Marshal(struct {
		ID      string      `json:"id"`
		Method  string      `json:"method"`
		Session string      `json:"session"`
		Step    *model.Step `json:"step,omitempty"`
		Scale   float64     `json:"scale,omitempty"`
	}{id, method, session, step, scale})
	if err != nil {
		return nil, err
	}
	if len(wire) > 1<<20 {
		return nil, errors.New("browser request exceeds 1 MiB")
	}
	reply := make(chan response, 1)
	w.mu.Lock()
	select {
	case <-w.done:
		w.mu.Unlock()
		return nil, ErrUnavailable
	default:
	}
	w.pending[id] = reply
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.pending, id); w.mu.Unlock() }()
	// A single bounded frame is serialized; responses are independently routed.
	w.writeMu.Lock()
	_, err = w.input.Write(append(wire, '\n'))
	w.writeMu.Unlock()
	if err != nil {
		w.fail()
		return nil, fmt.Errorf("%w: write: %w", ErrUnavailable, err)
	}
	select {
	case out := <-reply:
		if out.Error != nil {
			return nil, out.Error
		}
		return out.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.done:
		return nil, ErrUnavailable
	}
}

func (w *Worker) Close() error {
	w.fail()
	_ = w.input.Close()
	select {
	case <-w.exited:
		return nil
	case <-time.After(10 * time.Second):
		_ = w.cmd.Process.Kill()
		<-w.exited
		return errors.New("browser worker shutdown exceeded deadline")
	}
}
