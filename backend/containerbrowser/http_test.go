package containerbrowser

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceAuthenticationAndSessionOwnership(t *testing.T) {
	token := strings.Repeat("s", 32)
	h := &Host{BearerToken: []byte(token), byTransport: map[string]*browserSession{"session-a": {owner: "user-a/chat-a"}}}
	for _, check := range []struct {
		token, owner, session string
		status                int
	}{
		{"", "user-a/chat-a", "session-a", 401},
		{"wrong", "user-a/chat-a", "session-a", 401},
		{token, "", "", 400},
		{token, "user-b/chat-a", "session-a", 403},
		{token, "user-a/chat-b", "session-a", 403},
		{token, "user-a/chat-a", "missing", 404},
		{token, "user-a/chat-a", "session-a", 204},
		{token, "user-a/chat-a", "", 204},
	} {
		req := httptest.NewRequest("POST", "http://service.example/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+check.token)
		req.Header.Set("X-Mechanize-Owner", check.owner)
		req.Header.Set("Mcp-Session-Id", check.session)
		response := httptest.NewRecorder()
		h.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ownerFromContext(r.Context()) != check.owner {
				t.Error("trusted owner context lost")
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(response, req)
		if response.Code != check.status {
			t.Errorf("owner=%q session=%q: got %d want %d", check.owner, check.session, response.Code, check.status)
		}
		if strings.Contains(response.Body.String(), token) {
			t.Error("response exposed token")
		}
	}
}

func TestLegacyAnonymousLoopbackHandler(t *testing.T) {
	h := &Host{}
	response := httptest.NewRecorder()
	h.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(response, httptest.NewRequest("POST", "http://localhost/mcp", nil))
	if response.Code != 204 {
		t.Fatal(response.Code)
	}
}
