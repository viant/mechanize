package host

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mcp-protocol/schema"
	mcpserver "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data/consentgrants"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"github.com/viant/scy"
)

type observationPolicyReadCaller struct {
	doctors, snapshots atomic.Int32
	delay              time.Duration
}

func (c *observationPolicyReadCaller) Close() error { return nil }
func (c *observationPolicyReadCaller) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	if err := ctx.Err(); err != nil {
		return native.Reply{}, err
	}
	var result any
	switch r.Method {
	case "doctor":
		c.doctors.Add(1)
		if c.delay > 0 {
			timer := time.NewTimer(c.delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return native.Reply{}, ctx.Err()
			}
		}
		result = map[string]any{"axTrusted": true}
	case "apps.list":
		result = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "com.fixture.app", "launchTime": "fixture-launch", "startToken": "fixture-start"}}}
	case "elements.snapshot":
		c.snapshots.Add(1)
		result = map[string]any{"observationId": "obs", "generation": 1, "complete": true, "nodes": []map[string]any{{"ref": "public", "nativeRole": "AXButton", "identifier": "public"}}}
	default:
		return native.Reply{}, errors.New("fixture unexpected read method")
	}
	raw, _ := json.Marshal(result)
	return native.Reply{HelperEpoch: "fixture", Result: raw}, nil
}

type observationPolicyFixture struct {
	h             *Host
	f             *controlFixture
	read          *observationPolicyReadCaller
	webReads      atomic.Int32
	grantState    string
	session       string
	beforeConsent func()
	backendTime   atomic.Int64
}

func newObservationPolicyFixture(t *testing.T, delay bool) *observationPolicyFixture {
	t.Helper()
	h, f := hostControlFixture(t)
	f.principal.Scopes = append(f.principal.Scopes, "desktop:observe")
	f.principal.ClientID = "fixture-agent"
	f.principal.ClientName = "Fixture agent"
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	q := &observationPolicyFixture{h: h, f: f, read: &observationPolicyReadCaller{}, grantState: "active", session: "session"}
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{}, errors.New("input forbidden")
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	opened, err := runtime.Open(f.ctx, "Generic observation fixture")
	if err != nil {
		t.Fatal(err)
	}
	q.session = opened.SessionID
	t.Cleanup(func() { runtime.Close(f.ctx, q.session); runtime.Shutdown(context.Background()) })

	if delay {
		q.read.delay = 80 * time.Millisecond
		old := f.manager.options.Qualify
		f.manager.options.Qualify = func(ctx context.Context, p auth.Principal, i session.ProcessIdentity, b []string) (NativeControlReadiness, error) {
			timer := time.NewTimer(120 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return NativeControlReadiness{}, ctx.Err()
			}
			return old(ctx, p, i, b)
		}
	}
	readGateway, err := native.NewGateway(q.read, native.GatewayOptions{AllowedBundles: []string{"com.fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	h.nativeClient = q.read
	h.nativeByUser = map[string]*native.Gateway{f.principal.Namespace: readGateway}
	h.users[f.principal.Namespace] = User{NativeBundles: []string{"com.fixture.app"}, WebOrigins: []string{"https://fixture.test"}}
	// The existing encrypted fixture-enrollment path is entirely local/inert.
	const keyName = "MECHANIZE_OBSERVATION_POLICY_FIXTURE_KEY"
	t.Setenv(keyName, "fixture-encryption-key-32-bytes-xx")
	dir, err := os.MkdirTemp("/private/tmp", "mop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, "credentials"), 0700); err != nil {
		t.Fatal(err)
	}
	resource := scy.Resource{URL: filepath.Join(dir, "credentials", "fixture.sec"), Key: "blowfish://env/" + keyName}
	token := strings.Repeat("fixture-only-enrollment-", 3)
	if err = scy.New().Store(f.ctx, scy.NewSecret(token, &resource)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(resource.URL, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	grant := chrome.Enrollment{Principal: f.principal, ProfileChannel: "fixture-profile", BrowserInstance: "fixture-browser", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, CredentialResource: resource}
	broker, err := chrome.NewBroker(f.ctx, chrome.Config{FixtureEnrollment: true, SocketPath: filepath.Join(dir, "chrome.sock"), Grants: []chrome.Enrollment{grant}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { broker.Close() })
	conn, err := net.Dial("unix", filepath.Join(dir, "chrome.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err = chrome.WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "fixtureEnrollment": true, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": token}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = chrome.ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Time{})
	doc := chrome.Document{Identity: chrome.Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "fixture-document", Generation: 1}, Origin: "https://fixture.test", Title: "Generic fixture"}
	if err = chrome.WriteFrame(conn, map[string]any{"type": "documents", "documents": []chrome.Document{doc}}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		status, e := broker.BrowserStatus(f.ctx, f.principal)
		if e == nil && len(status.Channels) == 1 && status.Channels[0].DocumentCount == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("fixture inventory unavailable")
		}
		time.Sleep(time.Millisecond)
	}
	h.chrome, err = chrome.NewGateway(broker, chrome.GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, e := chrome.ReadFrame(conn)
			if e != nil {
				return
			}
			var command chrome.Command
			if json.Unmarshal(raw, &command) != nil || command.Action != "observe" {
				return
			}
			start := time.Now()
			q.webReads.Add(1)
			time.Sleep(10 * time.Millisecond)
			enabled := true
			if chrome.WriteFrame(conn, chrome.Reply{RequestID: command.RequestID, Identity: command.Identity, Nodes: []chrome.Node{{ID: "public", Role: "button", Name: "Generic button", Enabled: &enabled}}, Coverage: []string{"fixture"}}) != nil {
				return
			}
			q.backendTime.Store(time.Since(start).Microseconds())
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture peer did not drain")
		}
	})
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Enrolled: h.enrolled, SessionOwned: func(ctx context.Context, p auth.Principal, id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return h.Runtime.CheckSession(ctx, p, id)
	}, Policy: h.ConsentPolicy, Invoke: func(ctx context.Context, p auth.Principal, r exec.ComponentRequest) (any, error) {
		if q.beforeConsent != nil {
			q.beforeConsent()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scope := `{"kind":"origin","origin":"https://fixture.test"}`
		if strings.HasPrefix(r.Target.Route.Path, "unused") {
			return nil, errors.New("unused")
		}
		if b, ok := auth.ConsentBindingFromContext(ctx); ok && b.Purpose == "native inspect" {
			scope = `{"kind":"application","bundleID":"com.fixture.app"}`
		}
		raw, _ := json.Marshal(map[string]any{"namespace": f.principal.Namespace, "id": "request", "clientId": f.principal.ClientID, "sessionId": q.session, "scopeJson": scope, "modesJson": `["observe"]`, "purpose": func() string {
			if scope[9] == 'a' {
				return "native inspect"
			}
			return "web inspect"
		}(), "durationSeconds": 60, "decision": string(consent.AllowSession), "grantId": "grant", "grantState": q.grantState, "grantExpiresAt": time.Now().Add(time.Minute).UnixMilli()})
		var row consentgrants.Record
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		return &consentgrants.ListGrantsOutput{Data: []*consentgrants.Record{&row}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func (q *observationPolicyFixture) server(t *testing.T) *mcpserver.Server {
	t.Helper()
	server, err := gateway.New(gateway.Dependencies{Runtime: q.h.Runtime, Policy: q.h.Policy, ObservationPolicy: q.h.ObservationPolicy, Observe: q.h.Observe, ObserveNativeRoot: q.h.ObserveNativeRoot, ObserveNativeWindow: q.h.ObserveNativeWindow})
	if err != nil {
		t.Fatal(err)
	}
	return server
}
func (q *observationPolicyFixture) arguments(kind string) map[string]any {
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test"}
	purpose := "web inspect"
	if kind == "native" {
		surface = model.Surface{Kind: "native", BundleID: "com.fixture.app"}
		purpose = "native inspect"
	}
	return map[string]any{"surface": surface, "sessionId": q.session, "grantId": "grant", "purpose": purpose}
}
func TestObservationPolicyMCPWebAvoidsNativeDiscoveryAndAdmission(t *testing.T) {
	q := newObservationPolicyFixture(t, true)
	ctx := q.f.ctx
	client := q.server(t).AsClient(ctx)
	if _, err := client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	samples := []int64{}
	for i := 0; i < 20; i++ {
		start := time.Now()
		out, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: q.arguments("web")})
		if err != nil || out == nil || out.IsError != nil && *out.IsError {
			t.Fatalf("web fixture rejected: %v %+v", err, out)
		}
		samples = append(samples, time.Since(start).Microseconds())
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("OBSERVE_P2 calls=20 medianUs=%d p95Us=%d lastAdapterUs=%d nativeDoctors=%d nativeExecutable=%d nativeReadiness=%d nativeStarts=%d webReads=%d", samples[9], samples[18], q.backendTime.Load(), q.read.doctors.Load(), q.f.executableChecks, q.f.qualifications, q.f.starts, q.webReads.Load())
	if q.read.doctors.Load() != 0 || q.f.executableChecks != 0 || q.f.qualifications != 0 || q.f.starts != 0 || q.webReads.Load() != 20 {
		t.Fatal("web observe coupled to native discovery/admission")
	}
}
func TestObservationPolicyMCPKeepsHostConsentScopeAndAdapterChecks(t *testing.T) {
	for _, kind := range []string{"web", "native"} {
		for _, mode := range []string{"allowed", "revokedGrant", "removedEnrollment", "wrongSession", "unauthorized", "cancelBefore", "cancelDuringConsent"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				q := newObservationPolicyFixture(t, false)
				ctx := q.f.ctx
				args := q.arguments(kind)
				switch mode {
				case "revokedGrant":
					q.grantState = "revoked"
				case "removedEnrollment":
					q.h.users[q.f.principal.Namespace] = User{}
				case "wrongSession":
					args["sessionId"] = "foreign"
				case "unauthorized":
					p := q.f.principal
					p.Scopes = nil
					ctx = auth.WithPrincipal(ctx, p)
				case "cancelBefore":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "cancelDuringConsent":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					defer cancel()
					q.beforeConsent = cancel
				}
				client := q.server(t).AsClient(ctx)
				_, initErr := client.Initialize(ctx)
				var out *schema.CallToolResult
				var err error
				if initErr == nil {
					out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: args})
				}
				accepted := initErr == nil && err == nil && out != nil && (out.IsError == nil || !*out.IsError)
				reads := q.webReads.Load() + q.read.snapshots.Load()
				if mode == "allowed" {
					if !accepted || reads != 1 {
						t.Fatalf("authorized observation denied %v %v %+v", initErr, err, out)
					}
					if kind == "native" && q.read.doctors.Load() == 0 {
						t.Fatal("native adapter AX doctor bypassed")
					}
				} else if accepted || reads != 0 {
					t.Fatalf("denied observation reached adapter mode=%s reads=%d", mode, reads)
				}
				if q.f.executableChecks != 0 || q.f.qualifications != 0 || q.f.starts != 0 {
					t.Fatal("observation admitted mutation helper")
				}
			})
		}
	}
}
func TestObservationPolicyChecksAuthenticatedIdentityAndCurrentEnrollment(t *testing.T) {
	h, f := hostControlFixture(t)
	f.principal.Scopes = append(f.principal.Scopes, "desktop:observe")
	f.principal.ClientID = "owner"
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	h.users[f.principal.Namespace] = User{NativeBundles: []string{"com.fixture.app"}, WebOrigins: []string{"https://fixture.test"}}
	p, err := h.ObservationPolicy(f.ctx, f.principal)
	if err != nil || !p.AllowedSurfaces["com.fixture.app"] || !p.AllowedSurfaces["https://fixture.test"] || p.AllowMutation || len(p.Capabilities) != 0 {
		t.Fatal("incorrect enrolled observation projection")
	}
	p.AllowedSurfaces["foreign"] = true
	p2, err := h.ObservationPolicy(f.ctx, f.principal)
	if err != nil || p2.AllowedSurfaces["foreign"] {
		t.Fatal("policy map reused")
	}
	bad := f.principal
	bad.ClientID = "foreign"
	if _, err = h.ObservationPolicy(f.ctx, bad); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign principal accepted")
	}
	delete(h.users, f.principal.Namespace)
	if _, err = h.ObservationPolicy(f.ctx, f.principal); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("withdrawn enrollment accepted")
	}
	if f.executableChecks != 0 {
		t.Fatal("enrollment check admitted native helper")
	}
}
