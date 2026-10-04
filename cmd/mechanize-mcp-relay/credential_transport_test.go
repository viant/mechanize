package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

type credentialRoundTrip func(*http.Request) (*http.Response, error)

func (f credentialRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func credentialResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}
}
func credentialFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	config, tokenPath := filepath.Join(dir, "config"), filepath.Join(dir, "token")
	token := strings.Repeat("fixture-private-token-", 3)
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"stdioCredential": map[string]any{"URL": tokenPath}})
	if err := os.WriteFile(config, body, 0600); err != nil {
		t.Fatal(err)
	}
	return config, tokenPath, token
}
func credentialRequest(t *testing.T, endpoint string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", endpoint, strings.NewReader(`{"method":"tools/call"}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSecureTransportRefreshesRotatedPrivateCredentialAndConfig(t *testing.T) {
	config, tokenPath, first := credentialFixture(t)
	target := "http://127.0.0.1:4987/mcp"
	var seen []string
	transport := &secureTransport{endpoint: target, loadCredential: func(ctx context.Context) (string, error) { return credential(ctx, config) }, base: credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Header.Get("Authorization"))
		return credentialResponse(200), nil
	})}
	request := credentialRequest(t, target)
	request.Header.Set("Authorization", "caller-supplied")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	second := strings.Repeat("fixture-renewed-token-", 3)
	replacement := tokenPath + ".next"
	if err := os.WriteFile(replacement, []byte(second), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, tokenPath); err != nil {
		t.Fatal(err)
	}
	response, err = transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	third := strings.Repeat("fixture-reference-rotation-", 2)
	nextPath := filepath.Join(filepath.Dir(config), "next-token")
	if err := os.WriteFile(nextPath, []byte(third), 0600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"stdioCredential": map[string]any{"URL": nextPath}})
	if err := os.WriteFile(config, body, 0600); err != nil {
		t.Fatal(err)
	}
	response, err = transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(seen) != 3 || seen[0] != "Bearer "+first || seen[1] != "Bearer "+second || seen[2] != "Bearer "+third {
		t.Fatal("credential refresh did not follow current private resources")
	}
	if request.Header.Get("Authorization") != "caller-supplied" {
		t.Fatal("transport mutated caller request")
	}
}
func TestSecureTransportRevalidatesResourcesBeforeEveryRequest(t *testing.T) {
	for _, kind := range []string{"token-mode", "config-mode", "token-symlink", "config-symlink", "missing-token", "missing-config", "bad-config", "bad-token"} {
		t.Run(kind, func(t *testing.T) {
			config, tokenPath, _ := credentialFixture(t)
			target := "http://127.0.0.1:4987/mcp"
			calls := 0
			transport := &secureTransport{endpoint: target, loadCredential: func(ctx context.Context) (string, error) { return credential(ctx, config) }, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return credentialResponse(200), nil })}
			response, err := transport.RoundTrip(credentialRequest(t, target))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			switch kind {
			case "token-mode":
				err = os.Chmod(tokenPath, 0644)
			case "config-mode":
				err = os.Chmod(config, 0644)
			case "token-symlink":
				err = os.Remove(tokenPath)
				if err == nil {
					err = os.Symlink(config, tokenPath)
				}
			case "config-symlink":
				err = os.Remove(config)
				if err == nil {
					err = os.Symlink(tokenPath, config)
				}
			case "missing-token":
				err = os.Remove(tokenPath)
			case "missing-config":
				err = os.Remove(config)
			case "bad-config":
				err = os.WriteFile(config, []byte("PRIVATE_CONFIG_CONTENT"), 0600)
			case "bad-token":
				err = os.WriteFile(tokenPath, []byte("PRIVATE_TOKEN_CONTENT\ninvalid"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.RoundTrip(credentialRequest(t, target))
			if err == nil || err.Error() != "MCP credential unavailable" || calls != 1 {
				t.Fatal("invalid refreshed resource dispatched or exposed private failure", kind, calls)
			}
			if strings.Contains(err.Error(), filepath.Dir(config)) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("credential diagnostics leaked private material")
			}
		})
	}
}

// Foreign ownership metadata is exercised without chown/admin privileges.
// privateRead obtains exactly this metadata from its already-open nofollow FD.
type credentialInfo struct {
	os.FileInfo
	owner uint32
}

func (f credentialInfo) Sys() any {
	stat := *f.FileInfo.Sys().(*syscall.Stat_t)
	stat.Uid = f.owner
	return &stat
}
func TestCredentialFileOwnershipIsRequiredIndependentlyOfPrivateMode(t *testing.T) {
	_, tokenPath, _ := credentialFixture(t)
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !privateFileInfo(credentialInfo{FileInfo: info, owner: uint32(os.Getuid())}) {
		t.Fatal("current owner private fixture rejected")
	}
	if privateFileInfo(credentialInfo{FileInfo: info, owner: uint32(os.Getuid() + 1)}) {
		t.Fatal("foreign-owned private resource accepted")
	}
}
func TestSecureTransportConcurrentRequestsRefreshWithoutSharingHeaders(t *testing.T) {
	config, tokenPath, _ := credentialFixture(t)
	next := strings.Repeat("fixture-concurrent-rotation-", 2)
	if err := os.WriteFile(tokenPath, []byte(next), 0600); err != nil {
		t.Fatal(err)
	}
	target := "http://127.0.0.1:4987/mcp"
	var calls atomic.Int32
	transport := &secureTransport{endpoint: target, loadCredential: func(ctx context.Context) (string, error) { return credential(ctx, config) }, base: credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+next {
			t.Error("concurrent request carried stale credential")
		}
		return credentialResponse(200), nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := credentialRequest(t, target)
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Error(err)
				return
			}
			response.Body.Close()
			if request.Header.Get("Authorization") != "" {
				t.Error("concurrent caller request mutated")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 32 {
		t.Fatal("request lost or retried", calls.Load())
	}
}

type credentialBody struct{ reads, closes int }

func (b *credentialBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("PRIVATE_AUTH_BODY")
}
func (b *credentialBody) Close() error { b.closes++; return nil }
func TestSecureTransportAuthenticationFailureNeverRetriesOrLeaksResponse(t *testing.T) {
	for _, status := range []int{401, 403} {
		target := "http://127.0.0.1:4987/mcp"
		calls, loads := 0, 0
		body := &credentialBody{}
		transport := &secureTransport{endpoint: target, loadCredential: func(context.Context) (string, error) { loads++; return strings.Repeat("fixture", 8), nil }, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Body: body}, nil
		})}
		_, err := transport.RoundTrip(credentialRequest(t, target))
		if err == nil || !errors.Is(err, errMCPAuthDenied) || loads != 1 || calls != 1 || body.reads != 0 || body.closes != 1 {
			t.Fatal("authentication failure replayed or exposed response", status)
		}
	}
}

func TestSecureTransportClassifiesNetworkAndExpiredSessionWithoutLeakingDetails(t *testing.T) {
	target := "http://127.0.0.1:4987/mcp"
	credential := func(context.Context) (string, error) { return strings.Repeat("fixture", 8), nil }
	privateNetworkError := "https://private.invalid/mcp?token=PRIVATE_TOKEN"
	network := &secureTransport{endpoint: target, loadCredential: credential, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) {
		return nil, errors.New(privateNetworkError)
	})}
	_, err := network.RoundTrip(credentialRequest(t, target))
	if !errors.Is(err, errMCPHTTPTransport) || strings.Contains(err.Error(), privateNetworkError) || strings.Contains(err.Error(), "PRIVATE_TOKEN") {
		t.Fatal("network detail was not safely classified")
	}

	body := &credentialBody{}
	expiredSession := &secureTransport{endpoint: target, loadCredential: credential, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{"Mcp-Session-Id": []string{"opaque-fixture-session"}}, Body: body}, nil
	})}
	request := credentialRequest(t, target)
	request.Header.Set("Mcp-Session-Id", "opaque-fixture-session")
	_, err = expiredSession.RoundTrip(request)
	if err == nil || !errors.Is(err, errMCPSessionExpired) || strings.Contains(err.Error(), "opaque-fixture-session") || body.reads != 0 || body.closes != 1 {
		t.Fatalf("expired session classification mismatch: err=%v reads=%d closes=%d", err, body.reads, body.closes)
	}
}

func TestSecureTransportRejectsUnpinnedDestinationsBeforeCredentialLoad(t *testing.T) {
	target := "http://127.0.0.1:4987/mcp"
	loads, calls := 0, 0
	transport := &secureTransport{endpoint: target, loadCredential: func(context.Context) (string, error) { loads++; return strings.Repeat("fixture", 8), nil }, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return credentialResponse(200), nil })}
	for _, destination := range []string{"http://127.0.0.1:4988/mcp", "https://127.0.0.1:4987/mcp", "http://example.com/mcp", "http://localhost:4987/mcp", "http://127.0.0.1:4987/mcp?secret=x", "http://user:secret@127.0.0.1:4987/mcp"} {
		if _, err := transport.RoundTrip(credentialRequest(t, destination)); err == nil || err.Error() != "MCP endpoint refused" {
			t.Fatal("unpinned destination admitted")
		}
	}
	if loads != 0 || calls != 0 {
		t.Fatal("untrusted destination received credential or transport")
	}
}
func TestSecureTransportCancelledOrUnavailableLoaderDoesNotSend(t *testing.T) {
	target := "http://127.0.0.1:4987/mcp"
	loads, calls := 0, 0
	transport := &secureTransport{endpoint: target, loadCredential: func(context.Context) (string, error) {
		loads++
		return "", errors.New("PRIVATE_CONFIG_PATH PRIVATE_TOKEN")
	}, base: credentialRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return credentialResponse(200), nil })}
	request := credentialRequest(t, target)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	if _, err := transport.RoundTrip(request.WithContext(ctx)); !errors.Is(err, context.Canceled) || loads != 0 {
		t.Fatal("cancelled request loaded credential")
	}
	if _, err := transport.RoundTrip(request); err == nil || err.Error() != "MCP credential unavailable" || loads != 1 || calls != 0 {
		t.Fatal("failed loader leaked or dispatched")
	}
	transport.loadCredential = func(context.Context) (string, error) { return "", nil }
	if _, err := transport.RoundTrip(request); err == nil || calls != 0 {
		t.Fatal("empty credential dispatched")
	}
}
func TestSecureTransportCannotForwardCredentialThroughRedirect(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL+"/mcp", 302) }))
	defer origin.Close()
	loads := 0
	target := origin.URL + "/mcp"
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	client := &http.Client{Transport: &secureTransport{endpoint: target, loadCredential: func(context.Context) (string, error) { loads++; return strings.Repeat("fixture", 8), nil }, base: base}}
	// Even a caller omitting run's CheckRedirect cannot bypass exact endpoint pinning.
	_, err := client.Do(credentialRequest(t, target))
	if err == nil || loads != 1 || redirected.Load() != 0 {
		t.Fatal("redirect received credentials or was dispatched")
	}
}
