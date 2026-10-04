package host

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/viant/mechanize/model"
)

func recoveryTopologyFixture() (model.Observation, []model.Node) {
	yes, no := true, false
	raw := model.Observation{Nodes: []model.Node{
		{Ref: model.ElementRef{ID: "private-root"}, Name: "private-root-name"},
		{Ref: model.ElementRef{ID: "private-left"}, ParentID: "private-root"},
		{Ref: model.ElementRef{ID: "private-right"}, ParentID: "private-root"},
		{Ref: model.ElementRef{ID: "private-save"}, ParentID: "private-left", Name: "private-button-name", Values: map[string]model.Value{"value": {Kind: model.StringValue, String: "private-payload"}}},
		{Ref: model.ElementRef{ID: "private-cancel"}, ParentID: "private-right"},
		{Ref: model.ElementRef{ID: "private-other-root"}},
	}}
	safe := []model.Node{
		{Role: "application", Name: "Enrolled editor"},
		{Role: "group", Name: "Invoice"},
		{Role: "group", Name: "Purchase order"},
		{Role: "button", Name: "Save", Identifier: "enrolled-save", Enabled: &yes, Visible: &yes, Focused: &no},
		{Role: "button", Name: "Cancel", Enabled: &yes},
		{Role: "window", Name: "Inspector"},
	}
	return raw, safe
}

func TestNativeRecoveryTopologyCanonicalPrivateDigest(t *testing.T) {
	raw, safe := recoveryTopologyFixture()
	beforeRaw, _ := json.Marshal(raw)
	beforeSafe, _ := json.Marshal(safe)
	want, err := nativeRecoveryTopologyHash(raw, safe)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(want) || strings.Contains(want, "private") {
		t.Fatalf("topology did not return a private digest: %q", want)
	}
	permutation := []int{5, 4, 2, 0, 3, 1}
	shuffled := model.Observation{Nodes: make([]model.Node, len(raw.Nodes))}
	shuffledSafe := make([]model.Node, len(safe))
	renames := map[string]string{}
	for i, node := range raw.Nodes {
		renames[node.Ref.ID] = string(rune('a' + i))
	}
	for i, source := range permutation {
		shuffled.Nodes[i] = raw.Nodes[source]
		shuffled.Nodes[i].Ref = model.ElementRef{ID: renames[raw.Nodes[source].Ref.ID], Epoch: "different-epoch", Generation: 999}
		shuffled.Nodes[i].ParentID = renames[raw.Nodes[source].ParentID]
		shuffled.Nodes[i].Name = "different-private-name"
		shuffled.Nodes[i].Values = map[string]model.Value{"value": {Kind: model.StringValue, String: "different-private-payload"}}
		shuffledSafe[i] = safe[source]
	}
	got, err := nativeRecoveryTopologyHash(shuffled, shuffledSafe)
	if err != nil || got != want {
		t.Fatalf("ref renaming/input order/private metadata changed digest: %q %q %v", want, got, err)
	}
	afterRaw, _ := json.Marshal(raw)
	afterSafe, _ := json.Marshal(safe)
	if string(beforeRaw) != string(afterRaw) || string(beforeSafe) != string(afterSafe) {
		t.Fatal("hash mutated source observations")
	}
}

func TestNativeRecoveryTopologyBindsSemanticParentage(t *testing.T) {
	for _, change := range []string{"move_button", "change_label", "change_identifier", "change_role", "change_enabled", "change_visible", "change_focused", "remove_node", "add_node"} {
		t.Run(change, func(t *testing.T) {
			raw, safe := recoveryTopologyFixture()
			before, err := nativeRecoveryTopologyHash(raw, safe)
			if err != nil {
				t.Fatal(err)
			}
			no, yes := false, true
			switch change {
			case "move_button":
				raw.Nodes[3].ParentID = raw.Nodes[2].Ref.ID
			case "change_label":
				safe[1].Name = "Other enrolled group"
			case "change_identifier":
				safe[3].Identifier = "other-safe-button"
			case "change_role":
				safe[3].Role = "textbox"
			case "change_enabled":
				safe[3].Enabled = &no
			case "change_visible":
				safe[3].Visible = &no
			case "change_focused":
				safe[3].Focused = &yes
			case "remove_node":
				raw.Nodes, safe = raw.Nodes[:5], safe[:5]
			case "add_node":
				raw.Nodes = append(raw.Nodes, model.Node{Ref: model.ElementRef{ID: "private-added"}, ParentID: raw.Nodes[2].Ref.ID})
				safe = append(safe, model.Node{Role: "button", Name: "Safe added button"})
			}
			after, err := nativeRecoveryTopologyHash(raw, safe)
			if err != nil || before == after {
				t.Fatalf("semantic/topology change did not alter digest: before=%q after=%q err=%v", before, after, err)
			}
		})
	}
}

func TestNativeRecoveryTopologyRejectsIncompleteGraphsWithoutPayloadErrors(t *testing.T) {
	for _, malformed := range []string{"empty", "mismatched_redaction", "missing_id", "duplicate_id", "orphan", "self_parent", "cycle", "disconnected_cycle", "too_many"} {
		t.Run(malformed, func(t *testing.T) {
			raw, safe := recoveryTopologyFixture()
			switch malformed {
			case "empty":
				raw.Nodes, safe = nil, nil
			case "mismatched_redaction":
				safe = safe[:5]
			case "missing_id":
				raw.Nodes[3].Ref.ID = ""
			case "duplicate_id":
				raw.Nodes[4].Ref.ID = raw.Nodes[3].Ref.ID
			case "orphan":
				raw.Nodes[3].ParentID = "private-orphan-secret"
			case "self_parent":
				raw.Nodes[3].ParentID = raw.Nodes[3].Ref.ID
			case "cycle":
				raw.Nodes[0].ParentID = raw.Nodes[3].Ref.ID
			case "disconnected_cycle":
				raw.Nodes[2].ParentID = raw.Nodes[4].Ref.ID
			case "too_many":
				for len(raw.Nodes) < 257 {
					raw.Nodes = append(raw.Nodes, model.Node{Ref: model.ElementRef{ID: string(rune(1000 + len(raw.Nodes)))}})
					safe = append(safe, model.Node{Role: "button"})
				}
			}
			digest, err := nativeRecoveryTopologyHash(raw, safe)
			if err == nil || digest != "" {
				t.Fatalf("malformed graph accepted: digest=%q err=%v", digest, err)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "payload") {
				t.Fatalf("raw topology details exposed: %v", err)
			}
		})
	}
}

func TestNativeRecoveryTopologyNodeBound(t *testing.T) {
	raw := model.Observation{Nodes: make([]model.Node, 256)}
	safe := make([]model.Node, 256)
	for i := range raw.Nodes {
		raw.Nodes[i].Ref.ID = string(rune(1000 + i))
		if i > 0 {
			raw.Nodes[i].ParentID = raw.Nodes[i-1].Ref.ID
		}
		safe[i].Role = "group"
	}
	if _, err := nativeRecoveryTopologyHash(raw, safe); err != nil {
		t.Fatalf("bounded maximum-depth tree rejected: %v", err)
	}
}
