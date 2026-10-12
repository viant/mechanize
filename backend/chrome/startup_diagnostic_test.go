package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestBrokerStartupRefusalsCarryOnlyClosedCode(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"credential", "brokerEnrollmentRefused"}, {"origin", "brokerEnrollmentRefused"}, {"channel", "brokerEnrollmentRefused"},
		{"version", "brokerHelloRejected"}, {"scope", "brokerScopeUnqualified"}, {"busy", "brokerChannelBusy"},
		{"peer", "brokerPeerUnavailable"}, {"audit", "brokerPeerAuditUnavailable"}, {"process", "brokerProcessUnqualified"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			grant := enrollment(principal(t, "startup"), "p")
			if tc.mode == "scope" {
				grant.TrustScope = "desktop"
			}
			var check chromePeerCheck
			if tc.mode == "peer" || tc.mode == "audit" || tc.mode == "process" {
				check = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
					err := errors.New("PRIVATE-CANARY")
					if tc.mode == "peer" {
						err = errors.Join(nativepeer.ErrNativePeerAuthentication, err)
					}
					if tc.mode == "audit" {
						err = errors.Join(nativepeer.ErrNativePeerAudit, err)
					}
					return nativepeer.ChromeProcessEvidence{}, err
				}
			}
			dir, err := os.MkdirTemp("/tmp", "broker-startup-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "b.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("secret", 8)}, check)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { b.Close() })
			if tc.mode == "busy" {
				connectHost(t, b, grant)
			}
			conn, err := net.Dial("unix", b.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			hello := map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "fixtureEnrollment": true, "credential": strings.Repeat("secret", 8)}
			switch tc.mode {
			case "credential":
				hello["credential"] = "PRIVATE-CANARY"
			case "origin":
				hello["extensionOrigin"] = "PRIVATE-CANARY"
			case "channel":
				hello["profileChannel"] = "PRIVATE-CANARY"
			case "version":
				hello["protocolVersion"] = 9
			case "scope":
				hello["trustScope"] = "desktop"
				hello["profileDirectory"] = "PRIVATE-CANARY"
			}
			_ = WriteFrame(conn, hello)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			raw, err := ReadFrame(conn)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := json.Marshal(struct {
				Type string `json:"type"`
				Code string `json:"code"`
			}{"nativeHostError", tc.want})
			if string(raw) != string(want) {
				t.Fatalf("wrong closed diagnostic %s", raw)
			}
			if _, err = ReadFrame(conn); err == nil {
				t.Fatal("rejected connection remained usable")
			}
		})
	}
}

func TestRejectedNativeStartupWriteIsBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	started := time.Now()
	rejectNativeStartup(a, "brokerHelloRejected")
	if time.Since(started) > time.Second {
		t.Fatal("rejection writer blocked")
	}
}
