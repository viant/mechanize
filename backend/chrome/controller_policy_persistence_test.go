package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

type controllerPolicyFixtureStore struct {
	policies map[ControllerPolicyKey]ControllerPolicy
	saves    int
	fail     bool
}

func (s *controllerPolicyFixtureStore) Load(k ControllerPolicyKey) (ControllerPolicy, error) {
	if s.fail {
		return ControllerPolicy{}, errors.New("fixture corruption")
	}
	return s.policies[k], nil
}
func (s *controllerPolicyFixtureStore) Save(ctx context.Context, p auth.Principal, k ControllerPolicyKey, v ControllerPolicy) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	if s.fail {
		return errors.New("fixture save unavailable")
	}
	s.saves++
	s.policies[k] = v
	return nil
}
func TestControllerPolicyRestoresBeforeConnectionWithoutSessionAuthority(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "controller-persistent", []string{"desktop:observe", "consent:admin"})
	ctx := auth.WithPrincipal(context.Background(), p)
	human, _ := auth.WithNativeHuman(ctx)
	grant := enrollment(p, "persistent")
	store := &controllerPolicyFixtureStore{policies: map[ControllerPolicyKey]ControllerPolicy{}}
	b := fixtureBroker(t, grant)
	g, e := NewGateway(b, GatewayOptions{ControllerPolicies: store})
	if e != nil {
		t.Fatal(e)
	}
	input := ControllerManagement{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, Action: "configure", Policy: &ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}}
	if _, e = g.ManageControllers(ctx, p, input); e == nil || store.saves != 0 {
		t.Fatal("remote configuration persisted")
	}
	if _, e = g.ManageControllers(human, p, input); e != nil || store.saves != 1 {
		t.Fatal("native configuration not saved", e)
	}
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerSessions = map[string]*ControllerSession{"old": {ID: "old", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}}
	b.mu.Unlock()
	restarted, err := persistentControllerBroker(t, grant, store)
	if err != nil {
		t.Fatal(err)
	}
	next, e := NewGateway(restarted, GatewayOptions{ControllerPolicies: store})
	if e != nil {
		t.Fatal(e)
	}
	input.Action = "status"
	input.Policy = nil
	state, e := next.ManageControllers(human, p, input)
	if e != nil || !state.Policy.Enabled || len(state.Policy.Origins) != 1 || len(state.Sessions) != 0 || state.Connected {
		t.Fatal("restart omitted policy or restored approval", state, e)
	}
	// First immediate connection must receive restored policy without opening
	// the native panel or constructing a new controller session approval.
	conn := connectHost(t, restarted, grant)
	restarted.mu.Lock()
	channel := restarted.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	epoch, channelEpoch, scope := restarted.epoch, channel.epoch, channel.scopeHash
	restarted.mu.Unlock()
	if e = WriteFrame(conn, map[string]any{"type": "controllerSync", "sessionId": "sync", "brokerEpoch": epoch, "channelEpoch": channelEpoch, "scopeHash": scope}); e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	var restored struct {
		Type    string   `json:"type"`
		Enabled bool     `json:"enabled"`
		Origins []string `json:"origins"`
	}
	if json.Unmarshal(raw, &restored) != nil || restored.Type != "controllerPolicy" || !restored.Enabled || len(restored.Origins) != 1 {
		t.Fatal("first sync lost restored policy")
	}
	conn.Close()
	store.fail = true
	if _, e = persistentControllerBroker(t, grant, store); e == nil {
		t.Fatal("corrupt settings started controller gateway")
	}
	input.Action = "configure"
	input.Policy = &ControllerPolicy{Enabled: false, Origins: []string{}}
	if _, e = next.ManageControllers(human, p, input); e == nil {
		t.Fatal("failed save reported accepted")
	}
	input.Action = "status"
	input.Policy = nil
	state, e = next.ManageControllers(human, p, input)
	if e != nil || !state.Policy.Enabled {
		t.Fatal("failed save changed policy")
	}
}

func persistentControllerBroker(t *testing.T, grant Enrollment, store ControllerPolicyStore) (*Broker, error) {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "mch-policy-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0700)
	b, e := newBroker(Config{SocketPath: filepath.Join(dir, "broker.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}, ControllerPolicies: store}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("secret", 8)})
	if e == nil {
		t.Cleanup(func() { b.Close() })
	}
	return b, e
}
