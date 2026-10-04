package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func nativeWindowToolObservation(surface model.Surface, title, role string) model.Observation {
	uid := uint32(501)
	owned := true
	now := time.Now().UTC()
	scope := map[string]string{"title": title}
	if role != "" {
		scope["role"] = role
	}
	node := model.Node{Ref: model.ElementRef{ID: "window", Epoch: "fixture", AppLaunchID: "1:kernel:123:4", Generation: 1}, Role: "window", NativeRole: "AXWindow", Name: title, NativeOwnerProcessID: surface.ProcessID, NativeOwnerStartToken: surface.ProcessStartToken, NativeOwnerBundleID: surface.BundleID, NativeOwnerUID: &uid, NativeOwnerMatchesRoot: &owned}
	child := node
	child.Ref.ID = "child"
	child.ParentID = "window"
	child.Role = "textbox"
	child.NativeRole = "AXTextField"
	child.Name = "Name"
	return model.Observation{Surface: surface, WindowScope: scope, ID: "observation", Epoch: "fixture", Sequence: 1, Started: now, Ended: now, Nodes: []model.Node{node, child}}
}
func TestObserveNativeWindowToolRoutingConsentAndClosedScope(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "window-observer", []string{"desktop:observe"})
	for _, mode := range []string{"allowed", "AXWindow", "missingCallback", "unsupported", "noPID", "noBirth", "unknownRole", "emptyTitle", "extraScopeField", "mixedNativeRoot", "web", "denied", "unauthenticated", "wrongScope", "wrongSurface", "partial", "wrongOwner", "orphan", "rawValues", "windowRootsOnly"} {
		t.Run(mode, func(t *testing.T) {
			ctx := auth.WithPrincipal(context.Background(), p)
			if mode == "unauthenticated" {
				ctx = context.Background()
			}
			ordinary, rootCalls, windowCalls := 0, 0, 0
			d := Dependencies{Policy: func(context.Context, auth.Principal) (script.Policy, error) {
				return script.Policy{AllowAllNative: mode != "denied", AllowAllWeb: true}, nil
			}, Observe: func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
				ordinary++
				return model.Observation{}, nil
			}, ObserveNativeRoot: func(context.Context, auth.Principal, model.Surface, string) (model.Observation, error) {
				rootCalls++
				return model.Observation{}, nil
			}, ObserveNativeWindow: func(c context.Context, actor auth.Principal, surface model.Surface, title, role string) (model.Observation, error) {
				windowCalls++
				binding, ok := auth.ConsentBindingFromContext(c)
				if !ok || binding != (auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "inspect dialog"}) || actor.Namespace != p.Namespace || title != "Insert Sheet" {
					t.Fatal("trusted consent/identity/scope arguments changed")
				}
				if mode == "unsupported" {
					return model.Observation{}, errors.New("unsupported fixture")
				}
				observed := nativeWindowToolObservation(surface, title, role)
				switch mode {
				case "wrongScope":
					observed.WindowScope["title"] = "Other"
				case "wrongSurface":
					observed.Surface.ProcessID = 2
				case "partial":
					observed.Truncated = true
				case "wrongOwner":
					observed.Nodes[1].NativeOwnerStartToken = "124:4"
				case "orphan":
					observed.Nodes[1].ParentID = "missing"
				case "rawValues":
					observed.Nodes[1].Values = map[string]model.Value{"value": {Kind: model.StringValue, String: "PRIVATE_VALUE"}}
				case "windowRootsOnly":
					observed.WindowRootsOnly = true
				}
				return observed, nil
			}}
			if mode == "missingCallback" {
				d.ObserveNativeWindow = nil
			}
			handler := protocol.WithDefaultHandler(ctx, func(base *protocol.DefaultHandler) error { return registerObserve(base, d) })
			gateway, err := server.New(server.WithNewHandler(handler))
			if err != nil {
				t.Fatal(err)
			}
			client := gateway.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			surface := map[string]any{"kind": "native", "bundleId": "fixture.app", "processId": 1, "processStartToken": "123:4"}
			scope := map[string]any{"title": "Insert Sheet", "role": "window"}
			args := map[string]any{"surface": surface, "windowScope": scope, "sessionId": "session", "grantId": "grant", "purpose": "inspect dialog"}
			switch mode {
			case "AXWindow":
				scope["role"] = "AXWindow"
			case "noPID":
				delete(surface, "processId")
			case "noBirth":
				delete(surface, "processStartToken")
			case "unknownRole":
				scope["role"] = "dialog"
			case "emptyTitle":
				scope["title"] = ""
			case "extraScopeField":
				scope["documentKey"] = "unexpected"
			case "mixedNativeRoot":
				args["nativeRoot"] = "focusedElement"
			case "web":
				surface = map[string]any{"kind": "web", "origin": "https://fixture.example"}
				args["surface"] = surface
			}
			result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: args})
			success := mode == "allowed" || mode == "AXWindow"
			accepted := err == nil && result != nil && (result.IsError == nil || !*result.IsError)
			if accepted != success {
				t.Fatalf("unexpected exact-window tool acceptance: mode=%s err=%v", mode, err)
			}
			if ordinary != 0 || rootCalls != 0 {
				t.Fatal("exact scope fell back/broadened")
			}
			reached := success || mode == "unsupported" || mode == "wrongScope" || mode == "wrongSurface" || mode == "partial" || mode == "wrongOwner" || mode == "orphan" || mode == "rawValues" || mode == "windowRootsOnly"
			if reached != (windowCalls == 1) {
				t.Fatal("invalid request/callback gate changed")
			}
			if success {
				raw, _ := json.Marshal(result.StructuredContent)
				if strings.Contains(string(raw), "PRIVATE_VALUE") {
					t.Fatal("window tool exported plaintext values")
				}
			}
		})
	}
}
