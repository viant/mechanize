package containerbrowser

import (
	"context"
	"errors"
	"net/http"

	"github.com/viant/mechanize/auth"
)

type sessionCaptureKey struct{}
type sessionCapture struct{ session *browserSession }

func ownerFromContext(ctx context.Context) (string, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return "", auth.ErrUnauthorized
	}
	return p.Namespace, nil
}

// HTTP indexes transport sessions and rejects unknown session references.
func (h *Host) HTTP(next http.Handler) http.Handler {
	if h.Verifier == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "OAuth verifier unavailable", http.StatusServiceUnavailable)
		})
	}
	return h.Verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := ownerFromContext(r.Context()); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "verified identity is required", http.StatusUnauthorized)
			return
		}
		if version := r.Header.Get("MCP-Protocol-Version"); version != "" && version != "2025-11-25" && version != "2025-06-18" && version != "2025-03-26" {
			http.Error(w, "stateful MCP protocol version required", http.StatusBadRequest)
			return
		}
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			h.mu.Lock()
			s := h.byTransport[id]
			h.mu.Unlock()
			if s == nil {
				http.Error(w, "session unavailable", http.StatusNotFound)
				return
			}
			if err := s.authorize(r.Context()); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					http.Error(w, "request canceled or timed out", http.StatusRequestTimeout)
					return
				}
				http.Error(w, "session owner mismatch", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		capture := &sessionCapture{}
		// Initialization is synchronous. Publish the returned ID before its headers
		// reach the caller, so the next request cannot race index registration.
		writer := &sessionResponse{ResponseWriter: w, host: h, capture: capture}
		next.ServeHTTP(writer, r.WithContext(context.WithValue(r.Context(), sessionCaptureKey{}, capture)))
	}))
}

type sessionResponse struct {
	http.ResponseWriter
	host      *Host
	capture   *sessionCapture
	published bool
}

func (w *sessionResponse) publish() {
	if w.published {
		return
	}
	w.published = true
	id := w.Header().Get("Mcp-Session-Id")
	s := w.capture.session
	if id != "" && s != nil {
		w.host.mu.Lock()
		s.transportID = id
		w.host.byTransport[id] = s
		w.host.mu.Unlock()
	}
}
func (w *sessionResponse) WriteHeader(status int)      { w.publish(); w.ResponseWriter.WriteHeader(status) }
func (w *sessionResponse) Write(b []byte) (int, error) { w.publish(); return w.ResponseWriter.Write(b) }
func (w *sessionResponse) Flush() {
	w.publish()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *sessionResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
