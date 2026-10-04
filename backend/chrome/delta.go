package chrome

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// ObservationDelta is a compact scoped semantic view. CompleteScope refers to
// the reported semantic traversal, with its explicit coverage limitations.
type ObservationDelta struct {
	ObservationID string             `json:"observationId"`
	PreviousID    string             `json:"previousId,omitempty"`
	Epoch         string             `json:"epoch"`
	Generation    uint64             `json:"generation"`
	Sequence      uint64             `json:"sequence"`
	Nodes         []model.Node       `json:"nodes,omitempty"`
	Removed       []string           `json:"removed,omitempty"`
	Reset         bool               `json:"reset"`
	CompleteScope bool               `json:"completeScope"`
	Coverage      []string           `json:"coverage"`
	Snapshot      *model.Observation `json:"snapshot,omitempty"`
}

func (g *Gateway) remember(p auth.Principal, observation model.Observation) {
	// Defensive copy: the caller cannot alter a retained per-user observation.
	data, _ := json.Marshal(observation)
	var copy model.Observation
	_ = json.Unmarshal(data, &copy)
	key := p.Namespace + "\x00" + observation.ID
	g.observationMu.Lock()
	defer g.observationMu.Unlock()
	g.observations[key] = copy
	g.observationOrder = append(g.observationOrder, key)
	if len(g.observationOrder) > 32 {
		delete(g.observations, g.observationOrder[0])
		g.observationOrder = g.observationOrder[1:]
	}
}
func (g *Gateway) ObserveSince(ctx context.Context, p auth.Principal, surface model.Surface, since string) (ObservationDelta, error) {
	if err := authorize(ctx, p, false); err != nil {
		return ObservationDelta{}, err
	}
	g.observationMu.Lock()
	previous, known := g.observations[p.Namespace+"\x00"+since]
	g.observationMu.Unlock()
	current, err := g.Observe(ctx, p, surface)
	if err != nil {
		return ObservationDelta{}, err
	}
	result := ObservationDelta{ObservationID: current.ID, Epoch: current.Epoch, Sequence: current.Sequence, CompleteScope: !current.Truncated, Coverage: current.Unavailable}
	if len(current.Nodes) > 0 {
		result.Generation = current.Nodes[0].Ref.Generation
	}
	if !known || previous.Surface != surface || previous.Epoch != current.Epoch || previous.Truncated || current.Truncated {
		result.Reset = true
		result.Snapshot = &current
		return result, nil
	}
	result.PreviousID = since
	old := map[string]model.Node{}
	for _, node := range previous.Nodes {
		old[node.Ref.ID] = node
	}
	for _, node := range current.Nodes {
		prior, exists := old[node.Ref.ID]
		delete(old, node.Ref.ID)
		if exists {
			prior.Ref.Generation = node.Ref.Generation
		}
		if !exists || !reflect.DeepEqual(prior, node) {
			result.Nodes = append(result.Nodes, node)
		}
	}
	for id := range old {
		result.Removed = append(result.Removed, id)
	}
	return result, nil
}
