package durable

import (
	"context"
	"errors"
	"fmt"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/getartifact"
	"github.com/viant/mechanize/data/publishartifact"
)

var ErrArtifactPublicationConflict = errors.New("immutable artifact publication conflicts with verified reference")

type artifactComponentInvoke func(context.Context, string, string, string, any, bool) (any, error)

func (b *Builder) PublishArtifact(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return err
	}
	if b.options.VerifyArtifact == nil {
		return ErrArtifactVerificationUnavailable
	}
	if err = b.options.VerifyArtifact(ctx, p, ref); err != nil {
		return err
	}
	ctx, err = data.WithVerifiedArtifacts(ctx, p.Namespace, []data.ArtifactReference{ref})
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	return publishVerifiedArtifact(ctx, p.Namespace, ref, func(ctx context.Context, pkg, name, method string, input any, commit bool) (any, error) {
		return invoke(ctx, user.server, pkg, name, method, input, commit)
	})
}

// The caller holds the namespace-bound server lock through reads and publication.
// A failed commit acknowledgement is resolved only by an exact scoped read after
// immutable bytes have been verified; neither reader nor writer repairs metadata.
func publishVerifiedArtifact(ctx context.Context, namespace string, ref data.ArtifactReference, call artifactComponentInvoke) error {
	if err := data.RequireVerifiedArtifact(ctx, namespace, ref); err != nil {
		return err
	}
	found, err := artifactPublicationMatches(ctx, namespace, ref, call)
	if err != nil || found {
		return err
	}
	row := &publishartifact.Artifact{}
	row.SetNamespace(pointer(namespace))
	row.SetId(pointer(ref.ID))
	row.SetContentHash(pointer(ref.ContentHash))
	row.SetSizeBytes(pointer(ref.SizeBytes))
	row.SetMediaType(pointer(ref.MediaType))
	row.SetPublicationState(pointer("published"))
	if ref.KeyReference != "" {
		row.SetKeyReference(pointer(ref.KeyReference))
	}
	input := &publishartifact.PublishArtifactInput{}
	input.SetNamespace(namespace)
	input.SetPublishArtifact([]*publishartifact.Artifact{row})
	_, commitErr := call(ctx, "publishartifact", "PublishArtifact", "POST", input, true)
	if commitErr == nil {
		return nil
	}
	found, readErr := artifactPublicationMatches(ctx, namespace, ref, call)
	if readErr != nil {
		return errors.Join(commitErr, readErr)
	}
	if found {
		return nil
	}
	return commitErr
}

func artifactPublicationMatches(ctx context.Context, namespace string, ref data.ArtifactReference, call artifactComponentInvoke) (bool, error) {
	input := &getartifact.GetArtifactInput{}
	input.SetNamespace(namespace)
	input.SetArtifactID(ref.ID)
	result, err := call(ctx, "getartifact", "GetArtifact", "GET", input, false)
	if err != nil {
		return false, err
	}
	output, ok := result.(*getartifact.GetArtifactOutput)
	if !ok || output == nil {
		return false, errors.New("artifact publication read unavailable")
	}
	if len(output.Data) == 0 {
		return false, nil
	}
	if len(output.Data) != 1 {
		return false, ErrArtifactPublicationConflict
	}
	row := output.Data[0]
	if row == nil || row.Namespace == nil || row.Id == nil || row.ContentHash == nil || row.SizeBytes == nil || row.MediaType == nil || row.PublicationState == nil {
		return false, ErrArtifactPublicationConflict
	}
	keyReference := ""
	if row.KeyReference != nil {
		keyReference = *row.KeyReference
	}
	if *row.Namespace != namespace || *row.Id != ref.ID || *row.ContentHash != ref.ContentHash || *row.SizeBytes != ref.SizeBytes || *row.MediaType != ref.MediaType || keyReference != ref.KeyReference || *row.PublicationState != "published" {
		return false, fmt.Errorf("%w: %s", ErrArtifactPublicationConflict, ref.ID)
	}
	return true, nil
}
