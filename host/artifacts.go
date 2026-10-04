package host

import (
	"context"
	"errors"
	"io"

	"github.com/viant/mechanize/artifact"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

// ArtifactOptions is trusted host configuration. Publish must use the generated
// durable publication graph; readers and request fields cannot select storage or
// key resources. Consent authorizes the exact source surface before ingestion.
type ArtifactOptions struct {
	Store     *artifact.Store
	Authorize func(context.Context, auth.Principal) error
	Consent   func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error)
	Publish   func(context.Context, auth.Principal, data.ArtifactReference) error
}

// ArtifactService bridges encrypted immutable bytes and Datly metadata. It does
// not itself dispatch capture. The Host native capture path publishes trusted
// scoped bytes under the same retained lease; Chrome capture remains unsupported.
type ArtifactService struct{ options ArtifactOptions }

func NewArtifactService(options ArtifactOptions) (*ArtifactService, error) {
	if options.Store == nil || options.Authorize == nil || options.Consent == nil || options.Publish == nil {
		return nil, errors.New("complete encrypted artifact, identity, consent and durable publication bindings required")
	}
	return &ArtifactService{options: options}, nil
}

func (s *ArtifactService) bound(ctx context.Context, requested auth.Principal) (context.Context, auth.Principal, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || actual.Namespace != requested.Namespace {
		return nil, auth.Principal{}, auth.ErrUnauthorized
	}
	// Authorize with verified context facts, never caller-provided scope claims.
	if err = s.options.Authorize(ctx, actual); err != nil {
		return nil, auth.Principal{}, err
	}
	if err = ctx.Err(); err != nil {
		return nil, auth.Principal{}, err
	}
	if existing, ok := data.CurrentScope(ctx); ok {
		if existing.Namespace != actual.Namespace {
			return nil, auth.Principal{}, auth.ErrUnauthorized
		}
		return ctx, actual, nil
	}
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: actual.Namespace})
	return ctx, actual, err
}

// ArtifactPublicationError retains the immutable reference when metadata commit
// fails or its outcome is unknown. Bytes must not be deleted: publication may
// have committed before an acknowledgement was lost. Reachability-aware Datly
// reconciliation/GC is required; this service never claims rollback or cleanup.
type ArtifactPublicationError struct {
	Reference data.ArtifactReference
	Cause     error
}

func (e *ArtifactPublicationError) Error() string {
	return "artifact bytes durable; metadata publication failed or unknown"
}
func (e *ArtifactPublicationError) Unwrap() error { return e.Cause }

// Publish persists bounded host-provided evidence under exact-surface consent.
// It performs no platform dispatch, so its lease cleanup is known after this
// synchronous storage/publication call returns. A capture caller must separately
// retain its dispatch lease until the backend confirms capture cleanup.
func (s *ArtifactService) Publish(ctx context.Context, requested auth.Principal, surface model.Surface, mediaType string, source io.Reader) (data.ArtifactReference, error) {
	var zero data.ArtifactReference
	ctx, p, err := s.bound(ctx, requested)
	if err != nil {
		return zero, err
	}
	if _, err = ConsentScope(surface); err != nil {
		return zero, err
	}
	if source == nil {
		return zero, errors.New("host-provided artifact bytes required")
	}
	lease, err := s.options.Consent(ctx, p, surface)
	if err != nil {
		return zero, err
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
		return zero, errors.New("complete artifact consent lease required")
	}
	defer lease.Release()
	return s.publishBound(lease.Context, p, mediaType, source)
}

// publishBound is only called by host code already retaining a consent lease.
// It binds identity and durable scope without consuming a second once grant.
func (s *ArtifactService) publishBound(ctx context.Context, requested auth.Principal, mediaType string, source io.Reader) (data.ArtifactReference, error) {
	var zero data.ArtifactReference
	ctx, p, err := s.bound(ctx, requested)
	if err != nil {
		return zero, err
	}
	if source == nil {
		return zero, errors.New("host-provided artifact bytes required")
	}
	ref, err := s.options.Store.Put(ctx, p.Namespace, mediaType, source)
	if err != nil {
		return zero, err
	}
	if err = s.options.Publish(ctx, p, ref); err != nil {
		return ref, &ArtifactPublicationError{Reference: ref, Cause: err}
	}
	return ref, nil
}

// VerifyArtifact is the trusted durable.Options.VerifyArtifact callback. It
// authenticates every reference field and immutable bytes in the verified
// owner's root before generated publication/checkpoint graphs may accept it.
func (s *ArtifactService) VerifyArtifact(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
	ctx, p, err := s.bound(ctx, p)
	if err != nil {
		return err
	}
	return s.options.Store.Verify(ctx, p.Namespace, ref)
}

// Read is an authenticated owner read of existing evidence, not a new capture.
// It grants no platform authority. A reference is never a bearer credential;
// all metadata/hash/key fields are authenticated before returning plaintext.
func (s *ArtifactService) Read(ctx context.Context, p auth.Principal, ref data.ArtifactReference) ([]byte, error) {
	ctx, p, err := s.bound(ctx, p)
	if err != nil {
		return nil, err
	}
	return s.options.Store.Read(ctx, p.Namespace, ref)
}

// Capture cannot dispatch through the standalone artifact service. Native window
// capture is exposed by Host.CaptureWindow under one retained dispatch lease.
func (s *ArtifactService) Capture(ctx context.Context, p auth.Principal, surface model.Surface) (data.ArtifactReference, error) {
	if _, _, err := s.bound(ctx, p); err != nil {
		return data.ArtifactReference{}, err
	}
	if _, err := ConsentScope(surface); err != nil {
		return data.ArtifactReference{}, err
	}
	return data.ArtifactReference{}, &model.MechanizeError{Code: "unsupported", Message: "Direct artifact-service capture is unavailable; use the consent-bound native window capture API", Stage: "capture", DispatchState: "notDispatched"}
}
func (s *ArtifactService) Close() error { return s.options.Store.Close() }
