package leaseeffects

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

// Init requires the exact trusted namespace and physical generation. This reader
// has no pagination, caller SQL, selectors, or scope-widening defaults.
func (input *LeaseEffectsInput) Init(ctx context.Context) error {
	scope, err := data.RequireScope(ctx, input.Namespace)
	if err != nil {
		return err
	}
	if input.LeaseEpoch <= 0 || scope.LeaseEpoch != input.LeaseEpoch {
		return errors.New("verified exact desktop lease generation required")
	}
	return nil
}
