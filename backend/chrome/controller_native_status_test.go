package chrome_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/host"
)

type controllerNativeVerifier struct{ p auth.Principal }

func (v controllerNativeVerifier) Verify(_ context.Context, raw string) (auth.Principal, error) {
	if raw != "synthetic-console-enrollment" {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return v.p, nil
}
func TestNativeControllerStatusProvidesOwnedSelectionIdentity(t *testing.T) {
	gateway, p := chrome.ReconnectMCPFixtureForTest(t)
	p.ClientID = "fixture-native-console"
	p.Scopes = append(p.Scopes, "consent:admin")
	ordinary, e := gateway.BrowserStatus(auth.WithPrincipal(context.Background(), p), p)
	if e != nil || len(ordinary.Channels) != 1 || ordinary.Channels[0].ProfileChannel != "" || ordinary.Channels[0].BrowserInstance != "" {
		t.Fatal("ordinary status exposed native selection identity", e)
	}
	broker, e := host.NewConsentBroker(host.ConsentBrokerOptions{
		Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
			t.Error("metadata used database mutation")
			return nil, errors.New("forbidden fixture operation")
		},
		Enrolled: func(context.Context, auth.Principal) (host.User, error) {
			return host.User{Subject: p.Subject, DesktopAccess: true}, nil
		},
		SessionOwned: func(context.Context, auth.Principal, string) error { return nil }, Policy: func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil },
	})
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("/private/tmp", "controller-native-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "console.sock")
	listener, e := host.OpenConsentListener(context.Background(), host.ConsentListenerOptions{SocketPath: socket, Verifier: controllerNativeVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, Broker: broker, Additional: func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		actor, e := auth.FromContext(ctx)
		if e != nil || !auth.NativeHuman(ctx) || actor.Namespace != p.Namespace || actor.ClientID != p.ClientID || method != "browserStatus" {
			return nil, auth.ErrUnauthorized
		}
		return gateway.BrowserStatus(ctx, actor)
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	conn, e := net.Dial("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := func(method string, params map[string]any) json.RawMessage {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "fixture-" + method, "method": method, "params": params})
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		if _, e = conn.Write(append(header[:], raw...)); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(conn, header[:]); e != nil {
			t.Fatal(e)
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > 256*1024 {
			t.Fatal("invalid frame")
		}
		body := make([]byte, size)
		if _, e = io.ReadFull(conn, body); e != nil {
			t.Fatal(e)
		}
		var response struct {
			Result json.RawMessage
			Error  json.RawMessage
		}
		if json.Unmarshal(body, &response) != nil || len(response.Error) > 0 {
			t.Fatal("native metadata request rejected")
		}
		return response.Result
	}
	var hello struct{ SessionID string }
	if json.Unmarshal(request("hello", map[string]any{"protocolVersion": 1, "credential": "synthetic-console-enrollment", "clientBundleID": "com.viant.mechanize.consent"}), &hello) != nil || hello.SessionID == "" {
		t.Fatal("native handshake unavailable")
	}
	var status chrome.BrowserStatus
	if json.Unmarshal(request("browserStatus", map[string]any{"sessionID": hello.SessionID}), &status) != nil || len(status.Channels) != 1 {
		t.Fatal("native channel metadata missing")
	}
	row := status.Channels[0]
	if row.ProfileChannel == "" || row.BrowserInstance == "" || !row.Connected || !row.ProcessQualified || !row.ScopeQualified {
		t.Fatal("qualified native identity was not projected")
	}
}
