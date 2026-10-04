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

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

func TestProductionProcessChannelCannotAdoptClientProfileClaims(t *testing.T) {
	principal, _ := auth.NewPrincipal("fixture:issuer", "", "owner", []string{"desktop:control"})
	dir, err := os.MkdirTemp("/tmp", "mchrome-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0700)
	config := Config{SocketPath: filepath.Join(dir, "channel.sock"), Grants: []Enrollment{{Principal: principal, ProfileDirectory: dir, ProfileChannel: "profile1", BrowserInstance: "browser1", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}}}}
	checks := 0
	check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		checks++
		parent := session.ProcessIdentity{PID: 10}
		return nativepeer.ChromeProcessEvidence{KernelPeerQualified: true, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, ProfileQualified: true, ExecutorQualified: true}, nil
	}
	// Package-private injection exercises gating, not production signature proof.
	broker, err := newBrokerWithPeer(config, map[string]string{channelKey("profile1", "browser1"): strings.Repeat("fixture", 8)}, check)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	conn, err := net.Dial("unix", config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": "profile1", "browserInstance": "browser1", "extensionOrigin": config.Grants[0].ExtensionOrigin, "credential": strings.Repeat("fixture", 8), "fixtureEnrollment": false, "profileDirectory": dir, "profileLaunchQualified": true, "profileQualified": true, "executorQualified": true}); err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	if ack["type"] != "processQualified" || ack["profileQualified"] != true || ack["executorQualified"] != false {
		t.Fatalf("process claim promoted to profile authority: %+v", ack)
	}
	gateway, _ := NewGateway(broker, GatewayOptions{})
	for _, capability := range gateway.Capabilities() {
		if capability.Supported {
			t.Fatalf("unqualified profile exposed DOM capability: %+v", capability)
		}
	}
	status, err := gateway.ChannelTrust(auth.WithPrincipal(context.Background(), principal), principal)
	if err != nil || len(status) != 1 || !status[0].ProcessQualified || !status[0].ProfileQualified || status[0].ExecutorQualified || status[0].Evidence.ProfileQualified || status[0].Evidence.ExecutorQualified {
		t.Fatalf("independent qualification layers: %+v %v", status, err)
	}
	if err = WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{{Identity: Identity{ProfileChannel: "profile1", BrowserInstance: "browser1", TabID: 1, DocumentID: "claimed-document", Generation: 1}, Origin: "https://fixture.test"}}, "profileQualified": true}); err != nil {
		t.Fatal(err)
	}
	inventory, err := gateway.ListTabs(auth.WithPrincipal(context.Background(), principal), principal)
	if err != nil || len(inventory.Documents) != 0 || inventory.Complete {
		t.Fatalf("client inventory promoted unqualified profile: %+v %v", inventory, err)
	}
	broker.mu.Lock()
	selected := broker.channels[channelKey("profile1", "browser1")]
	broker.mu.Unlock()
	_, err = broker.call(auth.WithPrincipal(context.Background(), principal), selected, Command{Action: "record.start"}, true)
	var detail *model.MechanizeError
	if !errors.As(err, &detail) || detail.Code != "profileUnqualified" {
		t.Fatalf("recording accepted process-only channel: %v", err)
	}
	if checks < 2 {
		t.Fatal("contextual process trust was not freshly reverified")
	}
}
