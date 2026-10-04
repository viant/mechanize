package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
)

// BoundMutation contains only the detached logical identity needed to persist
// the dispatch binding. Values and locator strings are represented by its hash.
type BoundMutation struct {
	Action           string
	BrowserAttemptID string
	Identity         Identity
	BrokerEpoch      string
	ChannelEpoch     string
	ScopeHash        string
	ControlLease     Lease
	Fingerprint      MutationFingerprint
}
type BindingCommit struct {
	BindingID       string
	CommitConfirmed bool
	ReadbackMatched bool
}
type CommitMutationBinding func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error)
