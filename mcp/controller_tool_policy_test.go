package mcp

import (
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/engine/recording"
	repairs "github.com/viant/mechanize/engine/recovery"
	scenarios "github.com/viant/mechanize/engine/scenario"
	"reflect"
	"testing"
)

func allCanonicalCatalogDependencies(deps *Dependencies) {
	value := reflect.ValueOf(deps).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Func && field.IsNil() {
			field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value { panic("catalog must not execute tools") }))
		}
	}
	deps.Recording = &recording.Service{}
	deps.Recovery = &repairs.Service{}
	deps.Scenarios = &scenarios.Service{}
}

func TestControllerCanonicalExposurePolicy(t *testing.T) {
	d, id, ctx, _ := controllerFixture(t, allCanonicalCatalogDependencies)
	c, err := d.clientFor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := c.client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tool := range canonical.Tools {
		if seen[tool.Name] {
			t.Fatalf("duplicate canonical tool %s", tool.Name)
		}
		seen[tool.Name] = true
		p, ok := controllerToolPolicies[tool.Name]
		if !ok || p.Contract == "" {
			t.Errorf("unclassified canonical tool %s", tool.Name)
		}
	}
	for name := range controllerToolPolicies {
		if !seen[name] {
			t.Errorf("policy names unregistered tool %s", name)
		}
	}
	exposed, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range exposed.Tools {
		if !controllerToolPolicies[tool.Name].Exposed {
			t.Fatalf("deferred tool exposed: %s", tool.Name)
		}
	}
	if len(exposed.Tools) != len(controllerTools) {
		t.Fatal("exposed catalog mismatch")
	}
	raw, _ := json.Marshal(exposed)
	if len(exposed.Tools) > 64 || len(raw) > 192*1024 {
		t.Fatal("closed catalog budget exceeded")
	}
	t.Logf("canonical=%d exposed=%d deferred=%d bytes=%d", len(canonical.Tools), len(exposed.Tools), len(canonical.Tools)-len(exposed.Tools), len(raw))
}

func TestControllerRecordingStatusClosedProjection(t *testing.T) {
	good := recording.Status{RecordingID: "fixture", State: "paused", CoverageComplete: true}
	if !validControllerRecordingStatus(good) {
		t.Fatal("safe status denied")
	}
	for _, reason := range []string{"private-canary", "controlUnconfirmed;private-canary", "teardownUnconfirmed;teardownUnconfirmed"} {
		v := good
		v.Reason = reason
		if validControllerRecordingStatus(v) {
			t.Fatal("unbounded reason accepted")
		}
	}
	for _, state := range []string{"private-canary", ""} {
		v := good
		v.State = state
		if validControllerRecordingStatus(v) {
			t.Fatal("unknown state accepted")
		}
	}
	for _, reason := range []string{"startUnconfirmed", "controlUnconfirmed;teardownUnconfirmed", "liveStateUnavailable"} {
		v := good
		v.Reason = reason
		if !validControllerRecordingStatus(v) {
			t.Fatal("finite reason denied")
		}
	}
}

func TestControllerCatalogCapacityIsConnectionBoundAndCallsMatch(t *testing.T) {
	for _, cap := range []int{0, 32, 64, 4096} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			d, id, ctx, _ := controllerFixture(t, allCanonicalCatalogDependencies)
			id.CatalogToolLimit = cap
			listed, err := d.ListTools(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			expected := 30
			if cap == 64 {
				expected = 34
			}
			if len(listed.Tools) != expected {
				t.Fatalf("catalog=%d want%d", len(listed.Tools), expected)
			}
			present := map[string]bool{}
			for _, tool := range listed.Tools {
				present[tool.Name] = true
			}
			for _, name := range []string{"mechanize_browser_open_origin", "skill_list", "skill_get", "mechanize_capture", "mechanize_browser_tabs"} {
				if !present[name] {
					t.Fatal("baseline tool lost", name)
				}
			}
			if cap != 64 {
				for _, name := range []string{"mechanize_credential_resume_manual", "mechanize_record_pause", "mechanize_record_stop", "mechanize_record_status"} {
					result := controllerCall(t, d, ctx, id, name, map[string]any{"sessionId": "foreign", "catalogToolLimit": 64, "extensionVersion": "0.1.63"})
					if result.IsError == nil || !*result.IsError || controllerBody(t, result)["dispatchState"] != "notDispatched" {
						t.Fatal("legacy call upgraded")
					}
				}
				forged := id
				forged.CatalogToolLimit = 64
				if _, err = d.ListTools(ctx, forged); err == nil {
					t.Fatal("existing connection capacity changed")
				}
			}
		})
	}
}
