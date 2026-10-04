package durable

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/getartifact"
)

var ownedArtifactID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// ResolveOwnedArtifact supplies imported-media consumers with committed metadata
// through the generated Datly component. It never reads bytes or confers capture
// authority; the encrypted store independently authenticates the returned fields.
func (b *Builder) ResolveOwnedArtifact(ctx context.Context, p auth.Principal, id string) (data.ArtifactReference, error) {
	var zero data.ArtifactReference
	if !ownedArtifactID.MatchString(id) {
		return zero, errors.New("opaque artifact identity required")
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return zero, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	input := &getartifact.GetArtifactInput{}
	input.SetNamespace(p.Namespace)
	input.SetArtifactID(id)
	result, err := invoke(ctx, user.server, "getartifact", "GetArtifact", "GET", input, false)
	if err != nil {
		return zero, errors.New("owned artifact metadata unavailable")
	}
	output, ok := result.(*getartifact.GetArtifactOutput)
	if !ok || output == nil || len(output.Data) != 1 {
		return zero, errors.New("owned published artifact unavailable")
	}
	row := output.Data[0]
	if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.Id == nil || *row.Id != id || row.ContentHash == nil || row.SizeBytes == nil || *row.SizeBytes < 0 || row.MediaType == nil || *row.MediaType == "" || row.PublicationState == nil || *row.PublicationState != "published" {
		return zero, errors.New("owned published artifact metadata invalid")
	}
	digest, err := hex.DecodeString(*row.ContentHash)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != *row.ContentHash {
		return zero, errors.New("owned artifact digest invalid")
	}
	ref := data.ArtifactReference{ID: id, ContentHash: *row.ContentHash, SizeBytes: *row.SizeBytes, MediaType: *row.MediaType}
	if row.KeyReference != nil {
		ref.KeyReference = *row.KeyReference
	}
	return ref, nil
}
