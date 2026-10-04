// Package localrpc is the bounded authenticated local channel for the native UI.
package localrpc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
)

const MaxFrameBytes = 256 * 1024

type CredentialVerifier interface {
	Verify(context.Context, string) (auth.Principal, error)
}
type Handler func(context.Context, string, json.RawMessage) (any, error)
type Options struct {
	SocketPath string
	Verifier   CredentialVerifier
	// VerifyPeer proves the enrolled console's audit/code identity. UID alone is
	// not sufficient. Tests may supply explicit isolated fixture verification.
	VerifyPeer func(*net.UnixConn) error
	Handle     Handler
}
type Server struct {
	options     Options
	listener    *net.UnixListener
	mu          sync.Mutex
	connections map[*net.UnixConn]bool
	closed      bool
	wg          sync.WaitGroup
}
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      string    `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func New(ctx context.Context, o Options) (*Server, error) {
	if len([]byte(o.SocketPath)) > 95 {
		return nil, errors.New("native consent socket path exceeds portable Unix limit")
	}
	if !filepath.IsAbs(o.SocketPath) || o.Verifier == nil || o.VerifyPeer == nil || o.Handle == nil {
		return nil, errors.New("fixed socket, Scy verifier, signed peer policy and handler required")
	}
	dir := filepath.Dir(o.SocketPath)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("native consent socket directory must be private")
	}
	if _, err = os.Lstat(o.SocketPath); !os.IsNotExist(err) {
		return nil, errors.New("consent endpoint already exists; supervisor reconciliation required")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: o.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(o.SocketPath, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	s := &Server{options: o, listener: listener, connections: map[*net.UnixConn]bool{}}
	s.wg.Add(1)
	go s.accept()
	go func() { <-ctx.Done(); _ = s.Close() }()
	return s, nil
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.connections[c] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(c)
	}
}
func (s *Server) serve(c *net.UnixConn) {
	defer s.wg.Done()
	defer func() { c.Close(); s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
	if err := s.options.VerifyPeer(c); err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	r, err := read(c)
	if err != nil || r.Method != "hello" {
		return
	}
	var hello struct {
		ProtocolVersion int    `json:"protocolVersion"`
		Credential      string `json:"credential"`
		ClientBundleID  string `json:"clientBundleID"`
	}
	if err = json.Unmarshal(r.Params, &hello); err != nil || hello.ProtocolVersion != 1 || hello.ClientBundleID != "com.viant.mechanize.consent" {
		return
	}
	credential := hello.Credential
	p, err := s.options.Verifier.Verify(context.Background(), credential)
	hello.Credential = ""
	if err != nil || !p.HasScope("consent:admin") {
		_ = write(c, response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32001, Message: "verified human console enrollment required"}})
		return
	}
	var random [24]byte
	if _, err = rand.Read(random[:]); err != nil {
		return
	}
	session := hex.EncodeToString(random[:])
	if err = write(c, response{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{"protocolVersion": 1, "sessionID": session, "brokerName": "Mechanize"}}); err != nil {
		return
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	seen := map[string]bool{r.ID: true}
	for count := 0; count < 4096; count++ {
		_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
		r, err = read(c)
		if err != nil {
			return
		}
		if seen[r.ID] {
			return
		}
		seen[r.ID] = true
		current, verifyErr := s.options.Verifier.Verify(context.Background(), credential)
		if verifyErr != nil || current.Namespace != p.Namespace || current.ClientID != p.ClientID || !current.HasScope("consent:admin") {
			return
		}
		var authority struct {
			SessionID string `json:"sessionID"`
		}
		if err = json.Unmarshal(r.Params, &authority); err != nil || authority.SessionID != session {
			return
		}
		switch r.Method {
		case "snapshot", "decide", "revoke", "inventory", "helperPermissionDoctor", "applicationAccess.get", "applicationAccess.set":
		default:
			_ = write(c, response{JSONRPC: "2.0", ID: r.ID, Error: &rpcError{Code: -32601, Message: "unsupported native consent method"}})
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		value, err := s.options.Handle(bounded, r.Method, r.Params)
		cancel()
		reply := response{JSONRPC: "2.0", ID: r.ID, Result: value}
		if err != nil {
			reply.Result = nil
			reply.Error = &rpcError{Code: -32000, Message: "consent operation rejected"}
		}
		if err = write(c, reply); err != nil {
			return
		}
	}
}
func read(r io.Reader) (request, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return request{}, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrameBytes {
		return request{}, errors.New("invalid frame")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return request{}, err
	}
	var out request
	if err := json.Unmarshal(raw, &out); err != nil {
		return request{}, err
	}
	if out.JSONRPC != "2.0" || out.ID == "" || len(out.ID) > 128 || out.Method == "" {
		return request{}, errors.New("invalid request")
	}
	return out, nil
}
func write(w io.Writer, r response) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > MaxFrameBytes {
		return errors.New("reply bound")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(raw)))
	for _, data := range [][]byte{h[:], raw} {
		for len(data) > 0 {
			n, err := w.Write(data)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
	}
	return nil
}
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	_ = s.listener.Close()
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}
