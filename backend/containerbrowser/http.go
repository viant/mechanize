package containerbrowser

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

type sessionCaptureKey struct{}
type sessionCapture struct{ session *browserSession }
type ownerKey struct{}

func ownerFromContext(ctx context.Context) string {
	owner, _ := ctx.Value(ownerKey{}).(string)
	return owner
}

// HTTP indexes transport sessions and rejects unknown session references.
func (h *Host) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(h.BearerToken) > 0 {
			provided := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
			expected := sha256.Sum256(h.BearerToken)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
				http.Error(w, "service authentication required", http.StatusUnauthorized)
				return
			}
			owner := r.Header.Get("X-Mechanize-Owner")
			if strings.TrimSpace(owner) == "" || len(owner) > 256 {
				http.Error(w, "opaque session owner required", http.StatusBadRequest)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ownerKey{}, owner))
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
	})
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
