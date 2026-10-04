package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/model"
)

type nativeWindowObserveCaller struct {
	mode   string
	calls  []string
	scopes []map[string]string
}

func (*nativeWindowObserveCaller) Close() error { return nil }
func (f *nativeWindowObserveCaller) Call(ctx context.Context, r Request) (Reply, error) {
	f.calls = append(f.calls, r.Method)
	var out any
	switch r.Method {
	case "doctor":
		scopes := []string{"exactTitle"}
		if f.mode == "unsupported" {
			scopes = nil
		}
		out = map[string]any{"axTrusted": true, "nativeWindowScopes": scopes}
	case "apps.list":
		birth := "123:4"
		if f.mode == "staleProcess" {
			birth = "124:4"
		}
		out = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "kernel:" + birth, "startToken": birth}}}
	case "elements.snapshot":
		var params struct {
			WindowScope map[string]string `json:"windowScope"`
			PID         int               `json:"pid"`
			Birth       string            `json:"processStartToken"`
		}
		if json.Unmarshal(r.Params, &params) != nil || params.PID != 1 || params.Birth != "123:4" {
			return Reply{}, errors.New("fixture request identity lost")
		}
		f.scopes = append(f.scopes, params.WindowScope)
		if len(params.WindowScope) == 0 {
			return Reply{}, errors.New("whole-application fixture is truncated above1000nodes")
		}
		root := map[string]any{"ref": "window", "nativeRole": "AXWindow", "name": "Insert Sheet", "nativeOwnerProcessId": 1, "nativeOwnerStartToken": "123:4", "nativeOwnerBundleId": "fixture.app", "nativeOwnerUid": 501, "nativeOwnerMatchesRoot": true}
		child := map[string]any{"ref": "name", "parentRef": "window", "nativeRole": "AXTextField", "name": "Name", "identifier": "sheet-name", "value": "PRIVATE_VALUE", "nativeOwnerProcessId": 1, "nativeOwnerStartToken": "123:4", "nativeOwnerBundleId": "fixture.app", "nativeOwnerUid": 501, "nativeOwnerMatchesRoot": true}
		nodes := []map[string]any{root, child}
		echo := params.WindowScope
		complete := true
		switch f.mode {
		case "badEcho":
			echo = map[string]string{"title": "Other"}
		case "missingEcho":
			echo = nil
		case "partial":
			complete = false
		case "wrongOwner":
			child["nativeOwnerProcessId"] = 2
		case "missingOwner":
			delete(child, "nativeOwnerMatchesRoot")
		case "orphan":
			child["parentRef"] = "missing"
		case "cycle":
			root["parentRef"] = "name"
		case "duplicate":
			child["ref"] = "window"
		case "foreignUID":
			child["nativeOwnerUid"] = 502
		case "extraRoot":
			nodes = append(nodes, map[string]any{"ref": "other", "nativeRole": "AXWindow", "name": "Other", "nativeOwnerProcessId": 1, "nativeOwnerStartToken": "123:4", "nativeOwnerBundleId": "fixture.app", "nativeOwnerUid": 501, "nativeOwnerMatchesRoot": true})
		}
		now := time.Now().UTC()
		out = map[string]any{"observationId": "scope-observation", "generation": 1, "complete": complete, "windowScope": echo, "nodes": nodes, "startedAt": now, "returnedAt": now}
	default:
		return Reply{}, errors.New("unexpected fixture native operation")
	}
	raw, _ := json.Marshal(out)
	return Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "fixture", Result: raw}, nil
}
func TestObserveNativeWindowExactMetadataWithoutBroadFallback(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, wantedRole := range []string{"", "window", "AXWindow"} {
		f := &nativeWindowObserveCaller{}
		g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		if err != nil {
			t.Fatal(err)
		}
		surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "123:4"}
		observed, err := g.ObserveNativeWindow(ctx, p, surface, "Insert Sheet", wantedRole)
		if err != nil || observed.Surface != surface || observed.WindowScope["title"] != "Insert Sheet" || len(observed.Nodes) != 2 || len(f.scopes) != 1 {
			t.Fatal("exact window observation unavailable", err)
		}
		raw, _ := json.Marshal(observed)
		if strings.Contains(string(raw), "PRIVATE_VALUE") {
			t.Fatal("window metadata exported raw values")
		}
		for _, method := range f.calls {
			if method != "doctor" && method != "apps.list" && method != "elements.snapshot" {
				t.Fatal("read observation used extra native authority/query", method)
			}
		}
	}
}
func TestObserveNativeWindowRejectsIncompleteUnownedAndWrongScope(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"unsupported", "staleProcess", "badEcho", "missingEcho", "partial", "wrongOwner", "missingOwner", "orphan", "cycle", "duplicate", "foreignUID", "extraRoot"} {
		t.Run(mode, func(t *testing.T) {
			f := &nativeWindowObserveCaller{mode: mode}
			g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			if err != nil {
				t.Fatal(err)
			}
			surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "123:4"}
			if _, err = g.ObserveNativeWindow(ctx, p, surface, "Insert Sheet", ""); err == nil {
				t.Fatal("unsafe window metadata accepted")
			}
			for _, scope := range f.scopes {
				if scope["title"] != "Insert Sheet" {
					t.Fatal("scope fell back/broadened")
				}
			}
			if (mode == "unsupported" || mode == "staleProcess") && len(f.scopes) != 0 {
				t.Fatal("invalid capability/process reached snapshot")
			}
		})
	}
	for _, test := range []struct {
		surface     model.Surface
		title, role string
	}{
		{model.Surface{Kind: "native", BundleID: "fixture.app"}, "Insert Sheet", ""},
		{model.Surface{Kind: "web", Origin: "https://fixture"}, "Insert Sheet", ""},
		{model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "123:4"}, "", ""},
		{model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "123:4"}, "Insert Sheet", "dialog"},
	} {
		if err := ValidateNativeWindowRequest(test.surface, test.title, test.role); err == nil {
			t.Fatal("invalid exact window request accepted")
		}
	}
}
