package darwin

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func indexedRoleTarget(index int) model.Selector {
	t := scopedWindowSelector()
	t.Surface.ProcessID = 42
	t.Surface.ProcessStartToken = "100:1"
	t.Locator = &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "AXPopUpButton"}, Exact: true}
	t.Cardinality = "nth"
	t.Index = &index
	t.Order = "tree"
	return t
}
func indexedRoleTree() []model.Node {
	nodes := scopedWindowTree()
	return append(nodes, scopedWindowNode("first", "group", "AXPopUpButton", "", ""), scopedWindowNode("second", "group", "AXPopUpButton", "", ""), scopedWindowNode("outside", "otherwindow", "AXPopUpButton", "", ""))
}
func TestIndexedNativeRoleKeepsObservedTreeOrderInsideExactWindow(t *testing.T) {
	obs := model.Observation{Nodes: indexedRoleTree()}
	for index, want := range []string{"first", "second"} {
		n, e := resolve(obs, indexedRoleTarget(index), nil)
		if e != nil || n.Ref.ID != want {
			t.Fatalf("index=%d node=%s error=%v", index, n.Ref.ID, e)
		}
	}
	target := indexedRoleTarget(0)
	target.Cardinality = "one"
	target.Index = nil
	target.Order = ""
	if _, e := resolve(obs, target, nil); e == nil {
		t.Fatal("strict uniqueness weakened")
	}
}
func TestIndexedNativeRoleRejectsIncompleteOrMalformedObservation(t *testing.T) {
	for _, mode := range []string{"truncated", "missing-role", "role-unavailable", "dangling-parent", "duplicate-ref", "outside-index"} {
		t.Run(mode, func(t *testing.T) {
			obs := model.Observation{Nodes: indexedRoleTree()}
			target := indexedRoleTarget(0)
			switch mode {
			case "truncated":
				obs.Truncated = true
			case "missing-role":
				obs.Nodes = append(obs.Nodes, scopedWindowNode("unknown", "group", "", "", ""))
			case "role-unavailable":
				n := scopedWindowNode("unknown", "group", "AXButton", "", "")
				n.Unavailable = []string{"role"}
				obs.Nodes = append(obs.Nodes, n)
			case "dangling-parent":
				obs.Nodes = append(obs.Nodes, scopedWindowNode("unknown", "missing", "AXPopUpButton", "", ""))
			case "duplicate-ref":
				obs.Nodes = append(obs.Nodes, obs.Nodes[3])
			case "outside-index":
				target = indexedRoleTarget(2)
			}
			if _, e := resolve(obs, target, nil); e == nil {
				t.Fatal("unsafe indexed observation accepted")
			}
		})
	}
}
func TestIndexedNativeRoleCannotBroadenScopeOrBypassIdentifierUniqueness(t *testing.T) {
	for _, mode := range []string{"global", "no-pid", "no-birth", "wrong-order", "id", "name", "negative", "overflow", "nil-index", "all", "limit"} {
		t.Run(mode, func(t *testing.T) {
			target := indexedRoleTarget(0)
			switch mode {
			case "global":
				target.Scope.Window = nil
			case "no-pid":
				target.Surface.ProcessID = 0
			case "no-birth":
				target.Surface.ProcessStartToken = ""
			case "wrong-order":
				target.Order = "document"
			case "id":
				target.Locator.Strategy = "id"
			case "name":
				target.Locator.Strategy = "name"
			case "negative":
				target = indexedRoleTarget(-1)
			case "overflow":
				target = indexedRoleTarget(1000)
			case "nil-index":
				target.Index = nil
			case "all":
				target.Cardinality = "all"
			case "limit":
				target.Limit = 1
			}
			if _, e := resolve(model.Observation{Nodes: indexedRoleTree()}, target, nil); e == nil {
				t.Fatal("unsafe indexed target accepted")
			}
		})
	}
}
