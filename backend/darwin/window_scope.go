package darwin

import (
	"strings"

	"github.com/viant/mechanize/model"
)

func windowScopeValues(scope map[string]model.Value, values map[string]model.Value) (string, string, error) {
	if len(scope) == 0 {
		return "", "", nil
	}
	for key := range scope {
		if key != "title" && key != "role" {
			return "", "", nativeError("unsupportedScope", "Native window scope supports exact title and optional window role only")
		}
	}
	titleValue, ok := scope["title"]
	if !ok {
		return "", "", nativeError("unsupportedScope", "Native window scope requires an exact title")
	}
	title, err := model.ResolveValue(titleValue, values)
	if err != nil || title.Kind != model.StringValue || strings.TrimSpace(title.String) == "" || len(title.String) > 512 || strings.ContainsRune(title.String, 0) {
		return "", "", nativeError("invalidScope", "Window title must resolve to a bounded nonempty string")
	}
	role := ""
	if roleValue, exists := scope["role"]; exists {
		resolved, err := model.ResolveValue(roleValue, values)
		if err != nil || resolved.Kind != model.StringValue || (resolved.String != "window" && resolved.String != "AXWindow") {
			return "", "", nativeError("unsupportedScope", "Window role must resolve to window or AXWindow")
		}
		role = resolved.String
	}
	return title.String, role, nil
}

func unavailableAttribute(node model.Node, field string) bool {
	for _, missing := range node.Unavailable {
		if missing == field || missing == "truncated:"+field {
			return true
		}
	}
	return false
}

// A window boundary is proven from the complete parent graph, rather than
// inferred from proximity or AX traversal order. The selected root remains a
// candidate so explicit window locators can read the boundary itself. Validate even unrelated nodes
// so malformed edges cannot silently hide another matching descendant.
func windowScopedNodes(observation model.Observation, scope map[string]model.Value, values map[string]model.Value) ([]model.Node, error) {
	title, wantedRole, err := windowScopeValues(scope, values)
	if err != nil {
		return nil, err
	}
	if len(scope) == 0 {
		return observation.Nodes, nil
	}
	if len(observation.WindowScope) > 0 {
		if observation.WindowScope["title"] != title || observation.WindowScope["role"] != wantedRole || len(observation.WindowScope) != len(scope) {
			return nil, nativeError("unsupportedScope", "Observation differs from exact requested window scope")
		}
		byID, err := validatedParentGraph(observation)
		if err != nil {
			return nil, err
		}
		root := ""
		for _, node := range observation.Nodes {
			if node.ParentID == "" {
				if root != "" || node.NativeRole != "AXWindow" {
					return nil, nativeError("incompleteObservation", "One exact selected window root required")
				}
				root = node.Ref.ID
			}
		}
		if root == "" {
			return nil, nativeError("incompleteObservation", "Selected window root unavailable")
		}
		var result []model.Node
		for _, node := range observation.Nodes {
			if node.Ref.ID == root {
				result = append(result, node)
				continue
			}
			for parent := node.ParentID; parent != ""; parent = byID[parent].ParentID {
				if parent == root {
					result = append(result, node)
					break
				}
			}
		}
		return result, nil
	}
	byID, err := validatedParentGraph(observation)
	if err != nil {
		return nil, err
	}
	var window string
	for _, node := range observation.Nodes {
		if unavailableAttribute(node, "role") || (node.Role == "" && node.NativeRole == "") {
			return nil, nativeError("incompleteObservation", "Window candidate role is unavailable")
		}
		if node.NativeRole != "AXWindow" && node.Role != "window" {
			continue
		}
		if wantedRole != "" && wantedRole != node.Role && wantedRole != node.NativeRole {
			continue
		}
		if unavailableAttribute(node, "name") {
			return nil, nativeError("incompleteObservation", "Window candidate title is unavailable")
		}
		if node.Name != title {
			continue
		}
		if window != "" {
			return nil, nativeError("ambiguousTarget", "Window title matches more than one window")
		}
		window = node.Ref.ID
	}
	if window == "" {
		return nil, nativeError("targetNotFound", "Exact window title was not found")
	}
	var result []model.Node
	for _, node := range observation.Nodes {
		if node.Ref.ID == window {
			result = append(result, node)
			continue
		}
		for parent := node.ParentID; parent != ""; parent = byID[parent].ParentID {
			if parent == window {
				result = append(result, node)
				break
			}
		}
	}
	return result, nil
}

func validatedParentGraph(observation model.Observation) (map[string]model.Node, error) {
	if observation.Truncated || len(observation.Nodes) == 0 || len(observation.Nodes) > 1000 {
		return nil, nativeError("incompleteObservation", "Native scope requires a complete bounded AX tree")
	}
	byID := make(map[string]model.Node, len(observation.Nodes))
	for _, node := range observation.Nodes {
		if node.Ref.ID == "" || len(node.Ref.ID) > 256 || strings.ContainsRune(node.Ref.ID, 0) {
			return nil, nativeError("incompleteObservation", "AX tree has an invalid node reference")
		}
		if _, exists := byID[node.Ref.ID]; exists {
			return nil, nativeError("incompleteObservation", "AX tree has duplicate node references")
		}
		byID[node.Ref.ID] = node
	}
	for _, node := range observation.Nodes {
		seen := map[string]bool{node.Ref.ID: true}
		parent := node.ParentID
		depth := 0
		for parent != "" {
			ancestor, exists := byID[parent]
			if !exists || seen[parent] || depth >= 20 {
				return nil, nativeError("incompleteObservation", "AX tree has orphaned, cyclic or excessive parent paths")
			}
			seen[parent] = true
			parent = ancestor.ParentID
			depth++
		}
	}
	return byID, nil
}

func resolvedWindowScope(scope map[string]model.Value, values map[string]model.Value) (map[string]string, error) {
	title, role, err := windowScopeValues(scope, values)
	if err != nil || len(scope) == 0 {
		return nil, err
	}
	result := map[string]string{"title": title}
	if role != "" {
		result["role"] = role
	}
	return result, nil
}
