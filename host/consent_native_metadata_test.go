package host

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
)

type metadataConsoleVerifier struct{ p auth.Principal }

func (v metadataConsoleVerifier) Verify(_ context.Context, credential string) (auth.Principal, error) {
	if credential != "fixture-enrollment" {
		return auth.Principal{}, errors.New("invalid fixture")
	}
	return v.p, nil
}

func nativeMetadataExchange(t *testing.T, c net.Conn, value any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if _, err = c.Write(append(header[:], raw...)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, header[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > 256*1024 {
		t.Fatal("invalid native reply")
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(body, &result) != nil {
		t.Fatal("invalid native metadata reply")
	}
	return result
}

func TestNativeBrowserSetupMetadataUsesAdditionalVerifiedHumanProvider(t *testing.T) {
	for _, available := range []bool{true, false} {
		t.Run(map[bool]string{true: "available", false: "unavailable"}[available], func(t *testing.T) {
			dir, err := os.MkdirTemp("/private/tmp", "mc-setup-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			p, err := auth.NewPrincipal("fixture", "", "console-user", []string{"consent:admin"})
			if err != nil {
				t.Fatal(err)
			}
			p.ClientID = "native-console"
			broker, err := NewConsentBroker(ConsentBrokerOptions{
				Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
					t.Error("browser metadata incorrectly routed to consent components")
					return nil, errors.New("wrong route")
				},
				Enrolled:     func(context.Context, auth.Principal) (User, error) { return User{}, nil },
				SessionOwned: func(context.Context, auth.Principal, string) error { return nil },
				Policy:       func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			var called atomic.Bool
			o := ConsentListenerOptions{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: metadataConsoleVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, Broker: broker}
			if available {
				o.Additional = func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
					actor, e := auth.FromContext(ctx)
					if e != nil || actor.Namespace != p.Namespace || actor.ClientID != p.ClientID || !auth.NativeHuman(ctx) || method != "browserSetupMetadata" {
						return nil, auth.ErrUnauthorized
					}
					called.Store(true)
					return map[string]bool{"metadataAvailable": true}, nil
				}
			}
			server, err := OpenConsentListener(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			c, err := net.Dial("unix", o.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			hello := nativeMetadataExchange(t, c, map[string]any{"jsonrpc": "2.0", "id": "hello", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
			var handshake struct {
				SessionID string `json:"sessionID"`
			}
			if json.Unmarshal(hello["result"], &handshake) != nil || handshake.SessionID == "" {
				t.Fatal("fixture console did not authenticate")
			}
			reply := nativeMetadataExchange(t, c, map[string]any{"jsonrpc": "2.0", "id": "metadata", "method": "browserSetupMetadata", "params": map[string]any{"sessionID": handshake.SessionID}})
			if available {
				if !called.Load() || reply["error"] != nil {
					t.Fatal("verified browser metadata provider not reached")
				}
			} else if called.Load() || reply["error"] == nil {
				t.Fatal("missing provider reported success")
			}
		})
	}
}

func TestNativeControllersUsesAdditionalVerifiedHumanProvider(t *testing.T) {
	for _, available := range []bool{true, false} {
		t.Run(map[bool]string{true: "available", false: "unavailable"}[available], func(t *testing.T) {
			dir, err := os.MkdirTemp("/private/tmp", "mc-setup-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			p, err := auth.NewPrincipal("fixture", "", "console-user", []string{"consent:admin"})
			if err != nil {
				t.Fatal(err)
			}
			p.ClientID = "native-console"
			broker, err := NewConsentBroker(ConsentBrokerOptions{
				Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
					t.Error("browser metadata incorrectly routed to consent components")
					return nil, errors.New("wrong route")
				},
				Enrolled:     func(context.Context, auth.Principal) (User, error) { return User{}, nil },
				SessionOwned: func(context.Context, auth.Principal, string) error { return nil },
				Policy:       func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			var called atomic.Bool
			o := ConsentListenerOptions{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: metadataConsoleVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, Broker: broker}
			if available {
				o.Additional = func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
					actor, e := auth.FromContext(ctx)
					if e != nil || actor.Namespace != p.Namespace || actor.ClientID != p.ClientID || !auth.NativeHuman(ctx) || method != "browserControllers" {
						return nil, auth.ErrUnauthorized
					}
					called.Store(true)
					return map[string]bool{"metadataAvailable": true}, nil
				}
			}
			server, err := OpenConsentListener(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			c, err := net.Dial("unix", o.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			hello := nativeMetadataExchange(t, c, map[string]any{"jsonrpc": "2.0", "id": "hello", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
			var handshake struct {
				SessionID string `json:"sessionID"`
			}
			if json.Unmarshal(hello["result"], &handshake) != nil || handshake.SessionID == "" {
				t.Fatal("fixture console did not authenticate")
			}
			reply := nativeMetadataExchange(t, c, map[string]any{"jsonrpc": "2.0", "id": "metadata", "method": "browserControllers", "params": map[string]any{"sessionID": handshake.SessionID}})
			if available {
				if !called.Load() || reply["error"] != nil {
					t.Fatal("verified browser metadata provider not reached")
				}
			} else if called.Load() || reply["error"] == nil {
				t.Fatal("missing provider reported success")
			}
		})
	}
}
