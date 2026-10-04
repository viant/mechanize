// fixture is a loopback-only acceptance bridge. Every scenario drives the real
// MCP HTTP client/server, Scy verifier, Endly runtime and generated Datly data.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	stream "github.com/viant/jsonrpc/transport/client/http/streamable"
	"github.com/viant/mcp-protocol/schema"
	client "github.com/viant/mcp/client"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

const address = "127.0.0.1:18767"

func main() {
	if len(os.Args) < 2 {
		panic("start|serve|stop required")
	}
	root, _ := filepath.Abs("..")
	pid := filepath.Join(root, "e2e", ".fixture.pid")
	switch os.Args[1] {
	case "start":
		if _, err := os.Stat(pid); err == nil {
			response, e := http.Get("http://" + address + "/health")
			if e == nil {
				response.Body.Close()
				return
			}
			panic("stale fixture PID; stop it first")
		}
		binary, _ := os.Executable()
		cmd := exec.Command(binary, "serve")
		cmd.Dir = filepath.Join(root, "e2e")
		log, err := os.OpenFile(filepath.Join(root, "e2e", ".fixture.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		must(err)
		cmd.Stdout = log
		cmd.Stderr = log
		must(cmd.Start())
		must(os.WriteFile(pid, []byte(strconv.Itoa(cmd.Process.Pid)), 0600))
		_ = cmd.Process.Release()
		_ = log.Close()
		for i := 0; i < 100; i++ {
			r, err := http.Get("http://" + address + "/health")
			if err == nil {
				r.Body.Close()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		panic("fixture startup timed out; inspect .fixture.log")
	case "stop":
		raw, err := os.ReadFile(pid)
		if os.IsNotExist(err) {
			return
		}
		must(err)
		n, err := strconv.Atoi(string(raw))
		must(err)
		p, err := os.FindProcess(n)
		must(err)
		_ = p.Signal(os.Interrupt)
		must(os.Remove(pid))
	case "serve":
		serve(root)
	default:
		panic("unknown command")
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}

type request struct {
	Scenario string `json:"scenario"`
	Source   string `json:"source"`
}

func serve(root string) {
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ready":true}`)) })
	mux.HandleFunc("/case", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var input request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result, err := scenario(r.Context(), root, input)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	must(http.ListenAndServe(address, mux))
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(copy)
}
func scenario(parent context.Context, root string, input request) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "mechanize-e2e-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key")
	if err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		return nil, err
	}
	verify, err := auth.NewVerifier(ctx, &verifier.Config{HMAC: &scy.Resource{URL: keyPath}}, auth.Policy{Issuer: "fixture:issuer", Audience: "mechanize-e2e", Algorithms: []string{"HS256"}, RequiredScopes: []string{"desktop:control"}})
	if err != nil {
		return nil, err
	}
	token := func(subject, scope string, expiry time.Time) string {
		v, e := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "fixture:issuer", "aud": "mechanize-e2e", "sub": subject, "scope": scope, "exp": expiry.Unix()}).SignedString(key)
		must(e)
		return v
	}
	var dispatches atomic.Int32
	builder, err := durable.New(durable.Options{SourceRoot: root, StorageRoot: dir, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		dispatches.Add(1)
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		return nil, err
	}
	defer builder.Close(context.Background())
	runtime, err := automation.NewWithOptions(builder.Execute, automation.Options{PreparePlan: builder.PreparePlan})
	if err != nil {
		return nil, err
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}
	server, err := gateway.New(gateway.Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }, StateGet: func(c context.Context, p auth.Principal, id string) (durable.State, error) {
		return builder.StateGet(c, p, id)
	}, StatePatch: func(c context.Context, p auth.Principal, id string, rev int, values map[string]model.Value) (durable.State, error) {
		return builder.StatePatch(c, p, id, rev, values)
	}})
	if err != nil {
		return nil, err
	}
	server.UseStreamableHTTP(true)
	httpServer := httptest.NewServer(verify.Middleware(server.HTTP(ctx, "").Handler))
	defer httpServer.Close()
	newClient := func(raw string) (*client.Client, error) {
		tr, e := stream.New(ctx, httpServer.URL+"/mcp", stream.WithHTTPClient(&http.Client{Transport: bearer{raw}}), stream.WithStateless())
		if e != nil {
			return nil, e
		}
		return client.New("MechanizeEndlyAcceptance", "1", tr), nil
	}
	aliceToken := token("alice", "desktop:control", time.Now().Add(time.Hour))
	principal, err := verify.Verify(ctx, aliceToken)
	if err != nil {
		return nil, err
	}
	ctx = auth.WithPrincipal(ctx, principal)
	alice, err := newClient(aliceToken)
	if err != nil {
		return nil, err
	}
	defer alice.Close()
	if _, err = alice.Initialize(ctx); err != nil {
		return nil, err
	}
	call := func(c *client.Client, name string, args map[string]any) (*schema.CallToolResult, error) {
		return c.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
	}
	rejected := func(result *schema.CallToolResult, err error) bool {
		return err != nil || result != nil && result.IsError != nil && *result.IsError
	}
	result := map[string]any{"scenario": input.Scenario, "transport": "MCP HTTP"}
	switch input.Scenario {
	case "discovery":
		tools, e := alice.ListTools(ctx, nil)
		if e != nil {
			return nil, e
		}
		result["toolCount"] = len(tools.Tools)
		caps, e := call(alice, "mechanize_capabilities", map[string]any{})
		if rejected(caps, e) {
			return nil, errors.New("capability discovery failed")
		}
		result["schemaVersion"] = caps.StructuredContent.(map[string]any)["schemaVersion"]
		skills, e := call(alice, "skill_list", map[string]any{})
		if rejected(skills, e) {
			return nil, errors.New("skill discovery failed")
		}
		raw, _ := json.Marshal(skills.StructuredContent)
		var catalog gateway.SkillCatalog
		must(json.Unmarshal(raw, &catalog))
		result["skillCount"] = len(catalog.Skills)
		read := 0
		for _, entry := range catalog.Skills {
			raw, _ := json.Marshal(entry)
			var m map[string]any
			must(json.Unmarshal(raw, &m))
			uri, _ := m["uri"].(string)
			if uri == "" {
				uri, _ = m["entrypoint"].(string)
			}
			if uri == "" {
				return nil, fmt.Errorf("missing skill uri: %s", raw)
			}
			v, e := call(alice, "skill_get", map[string]any{"uri": uri})
			if rejected(v, e) {
				return nil, errors.New("skill read failed")
			}
			content, _ := v.StructuredContent.(map[string]any)["entrypointText"].(string)
			if content == "" {
				return nil, errors.New("empty skill entrypoint")
			}
			read++
		}
		result["skillsRead"] = read
	case "validation":
		v, e := call(alice, "mechanize_script_validate", map[string]any{"source": input.Source})
		result["valid"] = !rejected(v, e)
		v, e = call(alice, "mechanize_script_validate", map[string]any{"source": "app(\"com.example.Fixture\").system(\"rm\")"})
		result["invalidRejected"] = rejected(v, e)
		result["dispatches"] = dispatches.Load()
	case "auth":
		denied := 0
		for _, raw := range []string{"invalid", token("alice", "desktop:control", time.Now().Add(-time.Hour)), token("alice", "", time.Now().Add(time.Hour))} {
			c, e := newClient(raw)
			if e != nil {
				denied++
				continue
			}
			_, e = c.Initialize(ctx)
			c.Close()
			if e != nil {
				denied++
			}
		}
		result["deniedCredentials"] = denied
		result["dispatches"] = dispatches.Load()
	case "durability", "isolation":
		v, e := call(alice, "mechanize_session_open", map[string]any{"name": "fixture"})
		if rejected(v, e) {
			return nil, errors.New("session open failed")
		}
		session := v.StructuredContent.(map[string]any)["sessionId"].(string)
		defer runtime.Close(context.Background(), session)
		// This fixture's independent entity identity is explicit. A production
		// caller must declare its own business key in the workflow envelope;
		// a run/step hash is not a substitute for the external entity identity.
		plan, compileErr := script.Compile(input.Source)
		if compileErr != nil {
			return nil, compileErr
		}
		for i := range plan.Steps {
			if plan.Steps[i].Effect.Class == model.ExternalNonIdempotent {
				plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"fixtureEntity": {Kind: model.StringValue, String: "disposable-save-button"}}
			}
		}
		encodedPlan, encodeErr := json.Marshal(plan)
		if encodeErr != nil {
			return nil, encodeErr
		}
		args := map[string]any{"sessionId": session, "clientRequestId": "fixture-request", "source": string(encodedPlan), "format": "json"}
		v, e = call(alice, "mechanize_step_run", args)
		if rejected(v, e) {
			return nil, fmt.Errorf("run failed: %+v %v", v, e)
		}
		raw, _ := json.Marshal(v.StructuredContent)
		var op gateway.Operation
		must(json.Unmarshal(raw, &op))
		if _, e = runtime.Wait(ctx, session, op.ID); e != nil {
			return nil, e
		}
		v, e = call(alice, "mechanize_state_get", map[string]any{"runId": op.RunID})
		if rejected(v, e) {
			return nil, fmt.Errorf("state get failed: %+v %v", v, e)
		}
		result["persistedRun"] = v.StructuredContent.(map[string]any)["runId"] == op.RunID
		result["dispatches"] = dispatches.Load()
		if input.Scenario == "durability" {
			must(builder.Close(ctx))
			builder, e = durable.New(durable.Options{SourceRoot: root, StorageRoot: dir, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				dispatches.Add(1)
				return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
			})
			if e != nil {
				return nil, e
			}
			defer builder.Close(context.Background())
			state, e := call(alice, "mechanize_state_get", map[string]any{"runId": op.RunID})
			result["restartStateRead"] = !rejected(state, e)
			v, e = call(alice, "mechanize_step_run", args)
			if rejected(v, e) {
				return nil, errors.New("idempotent replay failed")
			}
			result["sameOperation"] = v.StructuredContent.(map[string]any)["operationId"] == op.ID
			result["dispatches"] = dispatches.Load()
			result["businessStatus"] = v.StructuredContent.(map[string]any)["businessStatus"]
		} else {
			bob, e := newClient(token("bob", "desktop:control", time.Now().Add(time.Hour)))
			if e != nil {
				return nil, e
			}
			defer bob.Close()
			if _, e = bob.Initialize(ctx); e != nil {
				return nil, e
			}
			v, e = call(bob, "mechanize_state_get", map[string]any{"runId": op.RunID})
			result["foreignStateDenied"] = rejected(v, e)
			v, e = call(bob, "mechanize_operation_status", map[string]any{"sessionId": session, "operationId": op.ID})
			result["foreignOperationDenied"] = rejected(v, e)
			v, e = call(alice, "mechanize_state_patch", map[string]any{"runId": op.RunID, "expectedRevision": 1, "variables": map[string]any{"unsafe": map[string]any{"type": "string", "string": "changed"}}})
			result["unguardedPatchDenied"] = rejected(v, e)
		}
	default:
		return nil, errors.New("unknown scenario")
	}
	return result, nil
}
