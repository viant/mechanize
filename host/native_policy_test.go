package host

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

func TestNativePolicyDoctorHelperProcess(t *testing.T) {
	if os.Getenv("MECHANIZE_POLICY_HELPER_FIXTURE") != "1" {
		return
	}
	_, _ = os.Stderr.Write([]byte("ready\n"))
	for {
		var header [4]byte
		if _, err := io.ReadFull(os.Stdin, header[:]); err != nil {
			os.Exit(0)
		}
		length := binary.BigEndian.Uint32(header[:])
		body := make([]byte, length)
		if _, err := io.ReadFull(os.Stdin, body); err != nil {
			os.Exit(0)
		}
		var request native.Request
		if json.Unmarshal(body, &request) != nil {
			os.Exit(2)
		}
		log, err := os.OpenFile(os.Getenv("MECHANIZE_POLICY_HELPER_METHODS"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(3)
		}
		_, _ = io.WriteString(log, request.Method+"\n")
		_ = log.Close()
		var state struct {
			AXTrusted           bool     `json:"axTrusted"`
			NativeRootScopes    []string `json:"nativeRootScopes"`
			NativeWindowScopes  []string `json:"nativeWindowScopes"`
			NativeWindowActions []string `json:"nativeWindowActions"`
			NativeTextActions   []string `json:"nativeTextActions"`
			NativeTextReads     []string `json:"nativeTextReads"`
			Fail                bool     `json:"fail"`
		}
		stateBytes, err := os.ReadFile(os.Getenv("MECHANIZE_POLICY_HELPER_STATE"))
		if err != nil || json.Unmarshal(stateBytes, &state) != nil {
			os.Exit(4)
		}
		reply := native.Reply{ProtocolVersion: native.ProtocolVersion, RequestID: request.RequestID, HelperEpoch: "policy-fixture"}
		if request.Method != "doctor" {
			reply.Error = &native.NativeError{Code: "unexpectedMethod", Message: "doctor required", Stage: "policy", DispatchState: "notDispatched"}
		} else if state.Fail {
			reply.Error = &native.NativeError{Code: "doctorFailed", Message: "fixture doctor failure", Stage: "doctor", DispatchState: "notDispatched"}
		} else {
			reply.Result, _ = json.Marshal(map[string]any{"axTrusted": state.AXTrusted, "nativeRootScopes": state.NativeRootScopes, "nativeWindowScopes": state.NativeWindowScopes, "nativeWindowActions": state.NativeWindowActions, "nativeTextActions": state.NativeTextActions, "nativeTextReads": state.NativeTextReads})
		}
		encoded, _ := json.Marshal(reply)
		binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
		if _, err = os.Stdout.Write(header[:]); err != nil {
			os.Exit(5)
		}
		if _, err = os.Stdout.Write(encoded); err != nil {
			os.Exit(6)
		}
	}
}

func policyShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func policyDoctorClient(t *testing.T, statePath, methodsPath string) *native.Client {
	t.Helper()
	if err := os.WriteFile(methodsPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	wrapper, err := os.CreateTemp(t.TempDir(), "policy-helper-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n" +
		"export MECHANIZE_POLICY_HELPER_FIXTURE=1\n" +
		"export MECHANIZE_POLICY_HELPER_STATE=" + policyShellQuote(statePath) + "\n" +
		"export MECHANIZE_POLICY_HELPER_METHODS=" + policyShellQuote(methodsPath) + "\n" +
		"exec " + policyShellQuote(executable) + " -test.run='^TestNativePolicyDoctorHelperProcess$'\n"
	if _, err := io.WriteString(wrapper, body); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wrapper.Name(), 0700); err != nil {
		t.Fatal(err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	client, err := native.NewClient(context.Background(), native.Options{HelperPath: wrapper.Name(), Stderr: readyWrite})
	_ = readyWrite.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := readyRead.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [6]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || string(ready[:]) != "ready\n" {
		t.Fatalf("native doctor fixture startup: %q %v", ready, err)
	}
	return client
}

func TestHostPolicyReadsColdDoctorAndRefreshesRevocation(t *testing.T) {
	principal, err := auth.NewPrincipal("fixture:issuer", "", "policy-reader", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), principal)
	root := t.TempDir()
	statePath := filepath.Join(root, "doctor.json")
	methodsPath := filepath.Join(root, "methods.log")
	writeDoctorState := func(axTrusted, fail bool) {
		t.Helper()
		body, err := json.Marshal(map[string]bool{"axTrusted": axTrusted, "fail": fail})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeDoctorState(true, false)
	client := policyDoctorClient(t, statePath, methodsPath)
	gateway, err := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		nativeClient: client,
		nativeByUser: map[string]*native.Gateway{principal.Namespace: gateway},
		users:        map[string]User{principal.Namespace: {NativeBundles: []string{"com.fixture.app"}}},
	}
	for _, cap := range gateway.Capabilities() {
		if cap.Name == "element.read" && cap.Supported {
			t.Fatal("cold gateway unexpectedly had cached read readiness")
		}
	}
	policy, err := h.Policy(ctx, principal)
	if err != nil || !policy.Capabilities["native:attributeRead"] {
		t.Fatalf("cold doctor did not enable read capability: caps=%v err=%v", policy.Capabilities, err)
	}
	writeDoctorState(false, false)
	policy, err = h.Policy(ctx, principal)
	if err != nil || policy.Capabilities["native:attributeRead"] || policy.Capabilities["native:boundedObservation"] {
		t.Fatalf("revoked AX readiness remained advertised: caps=%v err=%v", policy.Capabilities, err)
	}
	writeDoctorState(true, true)
	policy, err = h.Policy(ctx, principal)
	if err != nil || policy.Capabilities["native:attributeRead"] {
		t.Fatalf("failed doctor advertised read capability: caps=%v err=%v", policy.Capabilities, err)
	}
	methods, err := os.ReadFile(methodsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(methods)); !reflect.DeepEqual(got, []string{"doctor", "doctor", "doctor"}) {
		t.Fatalf("policy discovery read content or sent input: methods=%v", got)
	}
}

func TestHostPolicyHonorsCanceledDoctorContext(t *testing.T) {
	principal, err := auth.NewPrincipal("fixture:issuer", "", "policy-cancel", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "doctor.json")
	methodsPath := filepath.Join(t.TempDir(), "methods.log")
	if err := os.WriteFile(statePath, []byte(`{"axTrusted":true,"fail":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	client := policyDoctorClient(t, statePath, methodsPath)
	gateway, err := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{nativeClient: client, nativeByUser: map[string]*native.Gateway{principal.Namespace: gateway}, users: map[string]User{principal.Namespace: {NativeBundles: []string{"com.fixture.app"}}}}
	ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), principal))
	cancel()
	policy, err := h.Policy(ctx, principal)
	if !errors.Is(err, context.Canceled) || policy.Capabilities["native:attributeRead"] {
		t.Fatalf("canceled doctor context was ignored: caps=%v err=%v", policy.Capabilities, err)
	}
}

func TestHostPolicyRequiresFreshNativeRootAdvertisements(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "root-policy", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	dir := t.TempDir()
	statePath, methodsPath := filepath.Join(dir, "doctor.json"), filepath.Join(dir, "methods.log")
	write := func(ax bool, scopes []string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"axTrusted": ax, "nativeRootScopes": scopes})
		if err := os.WriteFile(statePath, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(true, nil)
	client := policyDoctorClient(t, statePath, methodsPath)
	g, err := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{nativeClient: client, nativeByUser: map[string]*native.Gateway{p.Namespace: g}, users: map[string]User{p.Namespace: {NativeBundles: []string{"com.fixture.app"}}}}
	for _, tc := range []struct {
		ax          bool
		scopes      []string
		menu, focus bool
	}{{true, nil, false, false}, {true, []string{"unknownRoot"}, false, false}, {true, []string{"menuBar"}, true, false}, {true, []string{"focusedElement"}, false, true}, {true, []string{"menuBar", "focusedElement"}, true, true}, {false, []string{"menuBar", "focusedElement"}, false, false}, {true, nil, false, false}} {
		write(tc.ax, tc.scopes)
		policy, err := h.Policy(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Capabilities["native:menuBarScope"] != tc.menu || policy.Capabilities["native:focusedElementScope"] != tc.focus {
			t.Fatalf("root scope policy did not follow fresh doctor: %+v caps=%v", tc, policy.Capabilities)
		}
	}
}

func TestHostPolicyWindowPositionRequiresFreshAdvertisementAndControl(t *testing.T) {
	for _, mode := range []string{"qualified", "noAdvert", "unknownAdvert", "noAX", "noControl", "unqualifiedControl", "launchOnly", "revokedAdvertisement"} {
		t.Run(mode, func(t *testing.T) {
			h, f := hostControlFixture(t)
			dir := t.TempDir()
			statePath, methodsPath := filepath.Join(dir, "doctor.json"), filepath.Join(dir, "methods.log")
			actions := []string{"setPosition"}
			if mode == "noAdvert" {
				actions = nil
			}
			if mode == "unknownAdvert" {
				actions = []string{"drag"}
			}
			write := func(actions []string) {
				raw, _ := json.Marshal(map[string]any{"axTrusted": mode != "noAX", "nativeWindowActions": actions})
				if err := os.WriteFile(statePath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(actions)
			client := policyDoctorClient(t, statePath, methodsPath)
			gateway, err := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
			if err != nil {
				t.Fatal(err)
			}
			h.nativeClient = client
			h.nativeByUser = map[string]*native.Gateway{f.principal.Namespace: gateway}
			if mode == "noControl" {
				h.nativeControl = nil
			}
			if mode == "unqualifiedControl" {
				f.ready.Accessibility = false
			}
			if mode == "launchOnly" {
				f.manager.options.LaunchOnly = true
				f.ready.MutationQualified = false
				f.ready.LaunchQualified = true
			}
			policy, err := h.Policy(f.ctx, f.principal)
			if err != nil {
				t.Fatal(err)
			}
			want := mode == "qualified" || mode == "revokedAdvertisement"
			if policy.Capabilities["native:windowPosition"] != want {
				t.Fatalf("wrong capability for %s: %+v", mode, policy)
			}
			if mode == "revokedAdvertisement" {
				write(nil)
				policy, err = h.Policy(f.ctx, f.principal)
				if err != nil || policy.Capabilities["native:windowPosition"] {
					t.Fatal("revoked window capability cached", err)
				}
			}
		})
	}
}

func TestHostPolicyNativeTextActionsRequireFreshAdvertisement(t *testing.T) {
	for _, mode := range []string{"qualified", "noAdvert", "unknownAdvert", "noAX", "noControl", "launchOnly", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			h, f := hostControlFixture(t)
			dir := t.TempDir()
			statePath, methodsPath := filepath.Join(dir, "doctor.json"), filepath.Join(dir, "methods.log")
			actions, reads := []string{"replaceText"}, []string{"valueMatches"}
			if mode == "noAdvert" {
				actions = nil
				reads = nil
			}
			if mode == "unknownAdvert" {
				actions = []string{"rawPaste"}
				reads = []string{"readAllValues"}
			}
			write := func(actions, reads []string) {
				body, _ := json.Marshal(map[string]any{"axTrusted": mode != "noAX", "nativeTextActions": actions, "nativeTextReads": reads})
				if e := os.WriteFile(statePath, body, 0600); e != nil {
					t.Fatal(e)
				}
			}
			write(actions, reads)
			client := policyDoctorClient(t, statePath, methodsPath)
			g, e := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
			if e != nil {
				t.Fatal(e)
			}
			h.nativeClient = client
			h.nativeByUser = map[string]*native.Gateway{f.principal.Namespace: g}
			if mode == "noControl" {
				h.nativeControl = nil
			}
			if mode == "launchOnly" {
				f.manager.options.LaunchOnly = true
				f.ready.MutationQualified = false
				f.ready.LaunchQualified = true
			}
			policy, e := h.Policy(f.ctx, f.principal)
			if e != nil {
				t.Fatal(e)
			}
			replace := mode == "qualified" || mode == "revoked"
			read := mode == "qualified" || mode == "revoked" || mode == "noControl" || mode == "launchOnly"
			if policy.Capabilities["native:replaceText"] != replace || policy.Capabilities["native:valueMatches"] != read {
				t.Fatalf("unsupported native text capabilities for%s: %+v", mode, policy)
			}
			if mode == "revoked" {
				write(nil, nil)
				policy, e = h.Policy(f.ctx, f.principal)
				if e != nil || policy.Capabilities["native:replaceText"] || policy.Capabilities["native:valueMatches"] {
					t.Fatal("revoked text capabilities cached", e)
				}
			}
		})
	}
}

func TestHostPolicyWindowKeyboardRequiresSessionOptinAndFreshMethod(t *testing.T) {
	for _, mode := range []string{"qualified", "noAdvert", "unknownAdvert", "noOptin", "noAX", "launchOnly", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			h, f := hostControlFixture(t)
			f.manager.options.SemanticOnly = true
			f.manager.options.SessionKeyboard = true
			f.ready.SemanticQualified = true
			f.ready.SessionKeyboardQualified = true
			if mode == "noOptin" {
				f.manager.options.SessionKeyboard = false
			}
			if mode == "launchOnly" {
				f.manager.options.LaunchOnly = true
				f.manager.options.SemanticOnly = false
				f.manager.options.SessionKeyboard = false
				f.ready.LaunchQualified = true
			}
			dir := t.TempDir()
			statePath, methodsPath := filepath.Join(dir, "doctor.json"), filepath.Join(dir, "methods.log")
			actions := []string{"pressSessionKey"}
			if mode == "noAdvert" {
				actions = nil
			}
			if mode == "unknownAdvert" {
				actions = []string{"rawText"}
			}
			write := func(actions []string) {
				body, _ := json.Marshal(map[string]any{"axTrusted": mode != "noAX", "nativeWindowActions": actions})
				if e := os.WriteFile(statePath, body, 0600); e != nil {
					t.Fatal(e)
				}
			}
			write(actions)
			client := policyDoctorClient(t, statePath, methodsPath)
			g, e := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
			if e != nil {
				t.Fatal(e)
			}
			h.nativeClient = client
			h.nativeByUser = map[string]*native.Gateway{f.principal.Namespace: g}
			policy, e := h.Policy(f.ctx, f.principal)
			if e != nil {
				t.Fatal(e)
			}
			if policy.Capabilities["native:windowSessionKeyboard"] != (mode == "qualified" || mode == "revoked") {
				t.Fatal("unqualified windowkeyboard advertised", mode, policy)
			}
			if mode == "revoked" {
				write(nil)
				policy, e = h.Policy(f.ctx, f.principal)
				if e != nil || policy.Capabilities["native:windowSessionKeyboard"] {
					t.Fatal("revoked windowkeyboard retained", e)
				}
			}
		})
	}
}

func TestHostPolicyRequiresFreshWindowScopeAdvertisement(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "root-policy", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	dir := t.TempDir()
	statePath, methodsPath := filepath.Join(dir, "doctor.json"), filepath.Join(dir, "methods.log")
	write := func(ax bool, scopes []string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"axTrusted": ax, "nativeWindowScopes": scopes})
		if err := os.WriteFile(statePath, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(true, nil)
	client := policyDoctorClient(t, statePath, methodsPath)
	g, err := native.NewGateway(client, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{nativeClient: client, nativeByUser: map[string]*native.Gateway{p.Namespace: g}, users: map[string]User{p.Namespace: {NativeBundles: []string{"com.fixture.app"}}}}
	for _, tc := range []struct {
		ax          bool
		scopes      []string
		menu, focus bool
	}{{true, nil, false, false}, {true, []string{"unknownRoot"}, false, false}, {true, []string{"exactTitle"}, true, false}, {true, []string{"unsupportedWindow"}, false, true}, {true, []string{"exactTitle", "unsupportedWindow"}, true, true}, {false, []string{"exactTitle", "unsupportedWindow"}, false, false}, {true, nil, false, false}} {
		write(tc.ax, tc.scopes)
		policy, err := h.Policy(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Capabilities["native:windowScope"] != tc.menu {
			t.Fatalf("root scope policy did not follow fresh doctor: %+v caps=%v", tc, policy.Capabilities)
		}
	}
}
