package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/scy"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type catalogOriginPolicy struct{ origins []string }

func (p catalogOriginPolicy) Load(chrome.ControllerPolicyKey) (chrome.ControllerPolicy, error) {
	origins := p.origins
	if origins == nil {
		origins = []string{"https://shell.fixture.test"}
	}
	return chrome.ControllerPolicy{Enabled: true, Origins: origins}, nil
}
func (catalogOriginPolicy) Save(context.Context, auth.Principal, chrome.ControllerPolicyKey, chrome.ControllerPolicy) error {
	return nil
}

// Canonical optional-tool catalog crosses the real broker socket and the shipped
// extension projection. No fixture tool handler may execute during discovery.
func TestControllerCanonicalCatalogActualExtensionProjection(t *testing.T) {
	controllerCanonicalRoundtrip(t, "catalog")
}
func TestControllerCanonicalToolCallActualExtensionProjection(t *testing.T) {
	controllerCanonicalRoundtrip(t, "call")
}

func TestControllerLocalhostPatternActualExtensionProjection(t *testing.T) {
	controllerCanonicalRoundtrip(t, "localhost")
}
func controllerCanonicalRoundtrip(t *testing.T, mode string) {
	origin, policyOrigin := "https://shell.fixture.test", "https://shell.fixture.test"
	if mode == "localhost" {
		origin = "http://localhost:49173"
		policyOrigin = "localhost:*"
		mode = "catalog"
	}

	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		v := reflect.ValueOf(deps).Elem()
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Kind() == reflect.Func && f.IsNil() {
				f.Set(reflect.MakeFunc(f.Type(), func([]reflect.Value) []reflect.Value { panic("catalog invoked tool") }))
			}
		}
	})
	listed, e := d.ListTools(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("/tmp", "mcp-catalog-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	const key = "MECHANIZE_TEST_CATALOG_SCY_KEY"
	t.Setenv(key, "fixture-catalog-encryption-key-32")
	credential := strings.Repeat("catalog-fixture-only-", 3)
	credentialDir := filepath.Join(dir, "credentials")
	if e = os.Mkdir(credentialDir, 0700); e != nil {
		t.Fatal(e)
	}
	resource := scy.Resource{URL: filepath.Join(credentialDir, "enrollment.sec"), Key: "blowfish://env/" + key}
	if scy.New().Store(ctx, scy.NewSecret(credential, &resource)) != nil {
		t.Fatal("fixture enrollment unavailable")
	}
	os.Chmod(resource.URL, 0600)
	os.Chmod(dir, 0700)
	grant := chrome.Enrollment{Principal: id.Principal, ProfileChannel: "catalog", BrowserInstance: "catalog-browser", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, CredentialResource: resource}
	socket := filepath.Join(dir, "broker.sock")
	broker, e := chrome.NewBroker(ctx, chrome.Config{FixtureEnrollment: true, SocketPath: socket, Grants: []chrome.Enrollment{grant}, ControllerPolicies: catalogOriginPolicy{origins: []string{policyOrigin}}})
	if e != nil {
		t.Fatal("broker unavailable", e)
	}
	defer broker.Close()
	gateway, e := chrome.NewGateway(broker, chrome.GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if e = gateway.SetControllerDispatcher(d); e != nil {
		t.Fatal(e)
	}
	conn, e := net.Dial("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if e = chrome.WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "fixtureEnrollment": true, "credential": credential}); e != nil {
		t.Fatal(e)
	}
	raw, e := chrome.ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	var hello map[string]json.RawMessage
	json.Unmarshal(raw, &hello)
	binding := map[string]json.RawMessage{}
	for _, k := range []string{"brokerEpoch", "channelEpoch", "scopeHash"} {
		binding[k] = hello[k]
	}
	deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node unavailable")
	}
	child := exec.CommandContext(deadline, node, "../extension/chrome/test/controller-roundtrip.cjs", mode, origin, policyOrigin)
	input, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		input.Close()
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	encoder, scanner := json.NewEncoder(input), bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 65536), 256*1024)
	if encoder.Encode(binding) != nil {
		t.Fatal("binding send failed")
	}
	phases := []string{"controllerOpen", "controllerRequest"}
	if mode == "call" {
		phases = append(phases, "controllerRequest")
	}
	var callKeys []string
	for index, phase := range phases {
		if !scanner.Scan() {
			t.Fatal("extension request missing", phase)
		}
		var probe struct{ Type string }
		json.Unmarshal(scanner.Bytes(), &probe)
		if probe.Type != phase {
			t.Fatal("unexpected extension phase", probe.Type)
		}
		if e = chrome.WriteFrame(conn, json.RawMessage(scanner.Bytes())); e != nil {
			t.Fatal(e)
		}
		raw, e = chrome.ReadFrame(conn)
		if e != nil {
			t.Fatal("broker reply missing", phase, e)
		}
		if index == 1 {
			var result struct{ Result map[string]json.RawMessage }
			if json.Unmarshal(raw, &result) != nil || len(result.Result) != 1 || result.Result["tools"] == nil {
				t.Fatal("broker catalog is not exact negotiated tools object")
			}
		}
		if index == 2 {
			var message struct{ Result map[string]json.RawMessage }
			json.Unmarshal(raw, &message)
			for key := range message.Result {
				callKeys = append(callKeys, key)
			}
		}
		if encoder.Encode(json.RawMessage(raw)) != nil {
			t.Fatal("native reply send failed")
		}
	}
	if !scanner.Scan() {
		t.Fatal("browser catalog result missing", scanner.Err())
	}
	var result struct {
		Type  string
		Value struct {
			Error     string
			RequestID string
			Result    struct {
				Tools             []json.RawMessage
				Content           []json.RawMessage
				StructuredContent map[string]any
			}
		}
	}
	expectedID := "browser-catalog"
	if mode == "call" {
		expectedID = "browser-call"
	}
	if json.Unmarshal(scanner.Bytes(), &result) != nil || result.Type != "fixtureBrowserResult" || result.Value.RequestID != expectedID || result.Value.Error != "" {
		t.Fatalf("canonical response rejected at browser boundary: mode=%s keys=%v", mode, callKeys)
	}
	if mode == "catalog" && len(result.Value.Result.Tools) != len(listed.Tools) {
		t.Fatal("catalog changed")
	}
	if mode == "call" && (len(result.Value.Result.Content) != 1 || result.Value.Result.StructuredContent["schemaVersion"] != float64(1)) {
		t.Fatal("complete tool result changed")
	}

	if child.Wait() != nil {
		t.Fatal("extension fixture failed")
	}
	t.Logf("actual broker/extension catalog accepted: %d tools", len(listed.Tools))
}
