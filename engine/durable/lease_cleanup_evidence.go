package durable

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/leasecleanupevidence"
	integration "github.com/viant/mechanize/integration/endly"
	"net/url"
	"os"
	"time"
)

// ProofKnown certifies a complete all-attempt check, including an empty set.
// This evidence never resolves business effects from another generation.
type LeaseNeverDispatchedEvidence struct {
	Namespace       string    `json:"namespace"`
	LeaseEpoch      int       `json:"leaseEpoch"`
	ProofKnown      bool      `json:"proofKnown"`
	NeverDispatched bool      `json:"neverDispatched"`
	AttemptCount    int       `json:"attemptCount"`
	ObservedAt      time.Time `json:"observedAt"`
}

// LeaseNeverDispatched reads the original committed outcome of EVERY attempt
// in the exact owner/physical generation. Only first-commit absent effects with
// matching canonical intent/outcome events and notDispatched evidence qualify.
// Later absence reconciliation is not evidence that input was never posted.
// Storage must already exist; no provisioning, mutation, or replay occurs.
func (b *Builder) LeaseNeverDispatched(ctx context.Context, p auth.Principal, epoch int) (LeaseNeverDispatchedEvidence, error) {
	evidence := LeaseNeverDispatchedEvidence{Namespace: p.Namespace, LeaseEpoch: epoch}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return evidence, auth.ErrUnauthorized
	}
	if epoch <= 0 {
		return evidence, errors.New("positive physical lease generation required")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return evidence, errors.New("durable host closed")
	}
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
	if err != nil {
		return evidence, err
	}
	path, info, err := existingLeaseDatabase(b.options.StorageRoot, p.Namespace)
	if err != nil {
		return evidence, err
	}
	const pkg = "github.com/viant/mechanize/data/leasecleanupevidence"
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_query_only=true&_foreign_keys=on&_busy_timeout=5000"}).String()
	server, err := standalone.New(ctx, standalone.Options{Config: &config.Config{BaseDir: b.options.SourceRoot, Connector: "user", Connectors: []connector.Config{{Name: "user", Driver: "sqlite3", DSN: dsn, MaxOpenConns: 1, MaxIdleConns: 1}}, GoBootstrap: &config.Packages{Packages: []string{pkg}}}, Holders: []any{leasecleanupevidence.LeaseCleanupEvidenceComponent{}}})
	if err != nil {
		return evidence, err
	}
	defer server.Shutdown(context.Background())
	if err = server.Reload(ctx, 1); err != nil {
		return evidence, err
	}
	input := &leasecleanupevidence.LeaseCleanupEvidenceInput{}
	input.SetNamespace(p.Namespace)
	input.SetLeaseEpoch(epoch)
	value, err := invoke(ctx, server, "leasecleanupevidence", "LeaseCleanupEvidence", "GET", input, false)
	if err != nil {
		return evidence, err
	}
	output, ok := value.(*leasecleanupevidence.LeaseCleanupEvidenceOutput)
	if !ok || output == nil {
		return evidence, errors.New("missing physical cleanup evidence projection")
	}
	count, err := validateNeverDispatched(output.Data, p.Namespace, epoch)
	if err != nil {
		return evidence, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		return evidence, errors.New("lease use database replaced during read")
	}
	if err = ctx.Err(); err != nil {
		return evidence, err
	}
	evidence.ProofKnown = true
	evidence.NeverDispatched = true
	evidence.AttemptCount = count
	evidence.ObservedAt = time.Now().UTC()
	return evidence, nil
}

func validateNeverDispatched(rows []*leasecleanupevidence.AttemptEvidence, namespace string, epoch int) (int, error) {
	if len(rows) > 4096 {
		return 0, errors.New("physical cleanup evidence exceeds complete bounded projection")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if row == nil || row.Namespace == nil || *row.Namespace != namespace || row.Id == nil || *row.Id == "" || row.RunId == nil || *row.RunId == "" || row.LeaseEpoch == nil || *row.LeaseEpoch != epoch || row.TotalAttempts != len(rows) || seen[*row.Id] {
			return 0, errors.New("incomplete or mismatched physical cleanup attempt projection")
		}
		seen[*row.Id] = true
		if row.EffectId == nil || *row.EffectId != key("effect", *row.Id) || row.EffectState == nil || *row.EffectState != "absent" || row.EffectRevision == nil || *row.EffectRevision != 2 || row.EvidenceJson == nil || row.IntentEventId == nil || *row.IntentEventId != key("intent-event", *row.Id) || row.OutcomeEventId == nil || *row.OutcomeEventId != key("outcome-event", *row.Id) || row.IntentSequence == nil || *row.IntentSequence <= 0 || row.OutcomeSequence == nil || *row.OutcomeSequence != *row.IntentSequence+1 || row.OutcomePayloadJson == nil || *row.EvidenceJson != *row.OutcomePayloadJson {
			return 0, errors.New("original committed pre-dispatch outcome unavailable")
		}
		var outcome integration.StepResult
		if json.Unmarshal([]byte(*row.EvidenceJson), &outcome) != nil || outcome.DispatchState != "notDispatched" || outcome.VerificationState == "verified" {
			return 0, errors.New("attempt may have dispatched; physical cleanup requires reconciliation")
		}
	}
	return len(rows), nil
}
