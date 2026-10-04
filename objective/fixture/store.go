// Package fixture supplies an independent in-memory receipt oracle for disposable
// fixture tests. It is not a qualified production business adapter.
package fixture

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"sync"
	"time"
)

type Receipt struct {
	Reference, BusinessKey string
	Completed              bool
	ObservedAt             time.Time
}
type Store struct {
	mu       sync.RWMutex
	receipts map[string]map[string][]Receipt
	offline  bool
}

func New() *Store { return &Store{receipts: map[string]map[string][]Receipt{}} }

// Put is the fixture application's independent outcome write, never a UI receipt.
func (s *Store) Put(p auth.Principal, receipt Receipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipts[p.Namespace] == nil {
		s.receipts[p.Namespace] = map[string][]Receipt{}
	}
	s.receipts[p.Namespace][receipt.BusinessKey] = append(s.receipts[p.Namespace][receipt.BusinessKey], receipt)
}
func (s *Store) SetOffline(offline bool) { s.mu.Lock(); s.offline = offline; s.mu.Unlock() }
func (s *Store) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (objective.Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return objective.Result{}, auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return objective.Result{}, err
	}
	if name != "receiptCompleted" || inputs["businessKey"].Kind != model.StringValue || inputs["businessKey"].String == "" {
		return objective.Result{Truth: objective.Unknown, Reason: "fixture predicate input unavailable"}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.offline {
		return objective.Result{}, errors.New("fixture oracle offline")
	}
	receipts := s.receipts[p.Namespace][inputs["businessKey"].String]
	if len(receipts) != 1 {
		return objective.Result{Truth: objective.Unknown, Reason: "receipt absent or duplicated"}, nil
	}
	receipt := receipts[0]
	truth := objective.False
	if receipt.Completed {
		truth = objective.True
	}
	return objective.Result{Truth: truth, Authority: objective.Authoritative, ObservedAt: receipt.ObservedAt, Evidence: []objective.Evidence{{Kind: "fixtureReceipt", Reference: receipt.Reference, BusinessKey: receipt.BusinessKey}}}, nil
}
func (s *Store) Enrollment() objective.Enrollment {
	return objective.Enrollment{Adapter: s, MaximumAuthority: objective.Authoritative, AllowedPredicates: map[string]bool{"receiptCompleted": true}, BusinessKeyInput: "businessKey"}
}
