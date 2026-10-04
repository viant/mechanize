package artifact

import (
	"context"
	"errors"
	"github.com/viant/scy"
)

// ScyResolver uses a fixed administrator-approved key-version/resource map.
// Resources contain a JSON {"key":"<base64 AES-256 key>"}. Unknown references
// fail closed. Rotation retains old configured versions for decryption.
// This adapter does not claim a macOS Keychain provider is implemented.
type ScyResolver struct{ resources map[string]scy.Resource }

func NewScyResolver(resources map[string]scy.Resource) (*ScyResolver, error) {
	if len(resources) == 0 {
		return nil, errors.New("configured Scy key resources required")
	}
	copied := make(map[string]scy.Resource, len(resources))
	for version, resource := range resources {
		if version == "" || len(version) > 256 || resource.URL == "" || resource.Fallback != nil {
			return nil, errors.New("explicit Scy key versions without fallback required")
		}
		resource.Data = append([]byte(nil), resource.Data...)
		resource.Options = append(resource.Options[:0:0], resource.Options...)
		copied[version] = resource
	}
	return &ScyResolver{resources: copied}, nil
}
func (r *ScyResolver) Resolve(ctx context.Context, version string) ([]byte, error) {
	resource, ok := r.resources[version]
	if !ok {
		return nil, ErrKeyUnavailable
	}
	secret, err := scy.New().Load(ctx, &resource)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	var value struct {
		Key []byte `json:"key"`
	}
	if err = secret.Decode(&value); err != nil || len(value.Key) != 32 {
		return nil, ErrKeyUnavailable
	}
	return value.Key, nil
}
