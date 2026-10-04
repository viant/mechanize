package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/viant/mechanize/model"
)

// nativeRecoveryTopologyHash binds private AX topology to separately redacted
// semantic nodes. The two node lists must have the same order; callers must
// invoke it before sorting the redacted list. Raw handles select edges only and
// never enter the hash payload, errors or planner observation.
func nativeRecoveryTopologyHash(raw model.Observation, redacted []model.Node) (string, error) {
	invalid := func() (string, error) {
		return "", errors.New("complete bounded native recovery topology required")
	}
	if len(raw.Nodes) == 0 || len(raw.Nodes) > 256 || len(redacted) != len(raw.Nodes) {
		return invalid()
	}
	positions := make(map[string]int, len(raw.Nodes))
	for i, node := range raw.Nodes {
		if node.Ref.ID == "" {
			return invalid()
		}
		if _, duplicate := positions[node.Ref.ID]; duplicate {
			return invalid()
		}
		positions[node.Ref.ID] = i
	}
	children := make([][]int, len(raw.Nodes))
	roots := make([]int, 0, len(raw.Nodes))
	for i, node := range raw.Nodes {
		if node.ParentID == "" {
			roots = append(roots, i)
			continue
		}
		parent, exists := positions[node.ParentID]
		if !exists || parent == i {
			return invalid()
		}
		children[parent] = append(children[parent], i)
	}
	// Explicit fields prevent private refs/values/ownership metadata from
	// accidentally entering provenance if model.Node grows in the future.
	type semanticNode struct {
		Role       string   `json:"role"`
		Name       string   `json:"name"`
		Identifier string   `json:"identifier"`
		Enabled    *bool    `json:"enabled"`
		Visible    *bool    `json:"visible"`
		Focused    *bool    `json:"focused"`
		Children   []string `json:"children"`
	}
	digest := func(value any) string {
		body, _ := json.Marshal(value)
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:])
	}
	state := make([]uint8, len(raw.Nodes))
	hashes := make([]string, len(raw.Nodes))
	var visit func(int) bool
	visit = func(index int) bool {
		switch state[index] {
		case 1:
			return false
		case 2:
			return true
		}
		state[index] = 1
		childHashes := make([]string, 0, len(children[index]))
		for _, child := range children[index] {
			if !visit(child) {
				return false
			}
			childHashes = append(childHashes, hashes[child])
		}
		sort.Strings(childHashes)
		node := redacted[index]
		hashes[index] = digest(struct {
			Domain string       `json:"domain"`
			Node   semanticNode `json:"node"`
		}{Domain: "native-recovery-topology-node-v1", Node: semanticNode{Role: node.Role, Name: node.Name, Identifier: node.Identifier, Enabled: node.Enabled, Visible: node.Visible, Focused: node.Focused, Children: childHashes}})
		state[index] = 2
		return true
	}
	// Visit every node so a disconnected parent cycle cannot hide outside the
	// root traversals of an otherwise valid forest.
	for i := range raw.Nodes {
		if !visit(i) {
			return invalid()
		}
	}
	rootHashes := make([]string, 0, len(roots))
	for _, root := range roots {
		rootHashes = append(rootHashes, hashes[root])
	}
	sort.Strings(rootHashes)
	return digest(struct {
		Domain string   `json:"domain"`
		Roots  []string `json:"roots"`
	}{Domain: "native-recovery-topology-forest-v1", Roots: rootHashes}), nil
}
