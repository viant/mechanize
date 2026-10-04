package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/viant/mechanize/auth"
)

// StopBoundaryAuthority is host-issued metadata while Endly admission and the
// physical input fence are held. It is never a caller-supplied tool contract.
// QuiescenceProof identifies the host's actual guard/correlation attestation;
// it is not an assertion of effect absence or successful business execution.
type StopBoundaryAuthority struct {
	Namespace, RunID, PlanID, RequestID string
	EndlySessionID, EndlyOperationID    string
	QuiescenceProof                     string
	RunRevision, AuditSequence          int
	Now                                 string
	AuditID, AuditPayloadJSON           string
}

type StopBoundaryAudit struct {
	PriorRunRevision int    `json:"priorRunRevision"`
	RunID            string `json:"runId"`
	PlanID           string `json:"planId"`
	RequestID        string `json:"requestId"`
	EndlySessionID   string `json:"endlySessionId"`
	EndlyOperationID string `json:"endlyOperationId"`
	QuiescenceProof  string `json:"quiescenceProof"`
}

type stopBoundaryAuthorityKey struct{}

func StopBoundaryAuditID(namespace, runID, requestID string) string {
	return ReconcileEffectKey("stopped-boundary", namespace, runID, requestID)
}
func validateStopBoundaryAuthority(ctx context.Context, a StopBoundaryAuthority) error {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != a.Namespace {
		return auth.ErrUnauthorized
	}
	if err := RequireStateMutationPermit(ctx, a.Namespace, a.RunID); err != nil {
		return err
	}
	for _, id := range []string{a.RunID, a.PlanID, a.RequestID, a.EndlySessionID, a.EndlyOperationID} {
		if !reconcileID(id) {
			return errors.New("bounded exact stopped-boundary correlation required")
		}
	}
	if a.QuiescenceProof == "" || len(a.QuiescenceProof) > 4096 || a.RunRevision < 1 || a.AuditSequence < 1 {
		return errors.New("host quiescence proof and positive revision/cursor required")
	}
	at, err := time.Parse(time.RFC3339Nano, a.Now)
	if err != nil || at.After(time.Now().Add(time.Second)) || time.Since(at) > 30*time.Second {
		return errors.New("fresh stopped-boundary audit time required")
	}
	return ctx.Err()
}
func WithStopBoundaryAuthority(ctx context.Context, a StopBoundaryAuthority) (context.Context, error) {
	if err := validateStopBoundaryAuthority(ctx, a); err != nil {
		return nil, err
	}
	a.AuditID = StopBoundaryAuditID(a.Namespace, a.RunID, a.RequestID)
	raw, err := json.Marshal(StopBoundaryAudit{a.RunRevision, a.RunID, a.PlanID, a.RequestID, a.EndlySessionID, a.EndlyOperationID, a.QuiescenceProof})
	if err != nil {
		return nil, err
	}
	a.AuditPayloadJSON = string(raw)
	raw, err = json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, stopBoundaryAuthorityKey{}, string(raw)), nil
}
func RequireStopBoundaryAuthority(ctx context.Context) (StopBoundaryAuthority, error) {
	raw, ok := ctx.Value(stopBoundaryAuthorityKey{}).(string)
	if !ok {
		return StopBoundaryAuthority{}, errors.New("trusted held stopped-boundary authority required")
	}
	var a StopBoundaryAuthority
	if json.Unmarshal([]byte(raw), &a) != nil {
		return a, errors.New("invalid stopped-boundary authority")
	}
	if err := validateStopBoundaryAuthority(ctx, a); err != nil {
		return StopBoundaryAuthority{}, err
	}
	return a, nil
}

// MatchStopBoundaryAudit validates exact durable adoption after reply loss. The
// original correlation and proof are retained; an audit cannot be rebound to a
// newer revision, operation or request. It does not grant authority to dispatch.
func MatchStopBoundaryAudit(payload string, expected StopBoundaryAudit) error {
	var actual StopBoundaryAudit
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.DisallowUnknownFields()
	if len(payload) > 8192 || decoder.Decode(&actual) != nil || actual != expected || expected.PriorRunRevision < 1 || expected.QuiescenceProof == "" {
		return errors.New("stopped-boundary audit differs from original request/correlation")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("stopped-boundary audit has trailing data")
	}
	return nil
}
