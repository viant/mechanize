package data

import (
	"context"
	"errors"
)

type ArtifactReference struct {
	ID           string `json:"id"`
	ContentHash  string `json:"contentHash"`
	SizeBytes    int    `json:"sizeBytes"`
	MediaType    string `json:"mediaType"`
	KeyReference string `json:"keyReference,omitempty"`
}
type CheckpointManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Namespace     string              `json:"namespace"`
	RunID         string              `json:"runId"`
	PlanID        string              `json:"planId"`
	RunRevision   int                 `json:"runRevision"`
	EventSequence int                 `json:"eventSequence"`
	Artifacts     []ArtifactReference `json:"artifacts"`
	Workspace     any                 `json:"workspace,omitempty"`
}
type artifactVerificationKey struct{}
type artifactVerification struct {
	namespace string
	refs      map[string]ArtifactReference
}

// WithVerifiedArtifacts carries trusted host evidence after scoped file bytes
// were verified. It is not bindable from a client body or Datly request field.
func WithVerifiedArtifacts(ctx context.Context, namespace string, refs []ArtifactReference) (context.Context, error) {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return nil, err
	}
	indexed := map[string]ArtifactReference{}
	for _, ref := range refs {
		if ref.ID == "" || !namespacePattern.MatchString(ref.ContentHash) || ref.SizeBytes < 0 {
			return nil, errors.New("complete artifact verification required")
		}
		if _, duplicate := indexed[ref.ID]; duplicate {
			return nil, errors.New("duplicate artifact reference")
		}
		indexed[ref.ID] = ref
	}
	return context.WithValue(ctx, artifactVerificationKey{}, artifactVerification{namespace, indexed}), nil
}
func RequireVerifiedArtifact(ctx context.Context, namespace string, ref ArtifactReference) error {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return err
	}
	evidence, ok := ctx.Value(artifactVerificationKey{}).(artifactVerification)
	verified, exists := evidence.refs[ref.ID]
	if !ok || !exists || evidence.namespace != namespace || verified != ref || ref.ID == "" || !namespacePattern.MatchString(ref.ContentHash) {
		return errors.New("scoped verified artifact evidence required")
	}
	return nil
}
