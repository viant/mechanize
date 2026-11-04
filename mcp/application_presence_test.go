package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestApplicationPresenceOwnedSessionAndClosedMetadata(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:observe"})
	p.ClientID = "client-a"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("presence dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := rt.Open(ctx, "presence")
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx, session.SessionID)
	calls := 0
	fail := false
	s, err := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, ApplicationPresence: func(c context.Context, actor auth.Principal, surface model.Surface) (native.ApplicationPresence, error) {
		calls++
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.SessionID != session.SessionID || binding.Purpose != "Inspect app presence" || actor.ClientID != p.ClientID || surface.BundleID != "com.example.Editor" {
			t.Fatal("scope or consent changed")
		}
		if fail {
			return native.ApplicationPresence{}, errors.New("private internal detail")
		}
		return native.ApplicationPresence{BundleID: surface.BundleID, State: "notObserved", ObservedAt: time.Now()}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := s.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"sessionId": session.SessionID, "purpose": "Inspect app presence", "bundleId": "com.example.Editor"}
	call := func(c context.Context, a map[string]any) *schema.CallToolResult {
		out, e := client.CallTool(c, &schema.CallToolRequestParams{Name: "mechanize_application_presence", Arguments: a})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	out := call(ctx, args)
	if out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatal("owned read rejected")
	}
	foreign := p
	foreign.ClientID = "client-b"
	out = call(auth.WithPrincipal(context.Background(), foreign), args)
	if out.IsError == nil || !*out.IsError || calls != 1 {
		t.Fatal("foreign session reached callback")
	}
	extra := map[string]any{}
	for k, v := range args {
		extra[k] = v
	}
	extra["processId"] = 42
	out = call(ctx, extra)
	if out.IsError == nil || !*out.IsError || calls != 1 {
		t.Fatal("unknown input accepted")
	}
	fail = true
	out = call(ctx, args)
	raw, _ := json.Marshal(out)
	if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "private internal detail") {
		t.Fatal("private error escaped")
	}
}

func TestControllerApplicationPresenceKeepsAuthorityBoundary(t *testing.T) {
	for _, bundle := range []string{"com.example.Editor", "com.viant.mechanize.consent"} {
		raw, _ := json.Marshal(map[string]any{"sessionId": "session", "purpose": "Inspect app presence", "bundleId": bundle})
		_, _, err := controllerArgs("mechanize_application_presence", raw)
		if (err == nil) != (bundle == "com.example.Editor") {
			t.Fatal("controller authority boundary changed", bundle, err)
		}
	}
}
