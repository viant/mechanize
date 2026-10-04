package vault

import (
	"context"
	"encoding/hex"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/kms"
	_ "github.com/viant/scy/kms/blowfish"
	"reflect"
	"strings"
)

// LegacyEnrollment is trusted operator configuration for existing Scy resources,
// never an agent-provided filesystem URL. Each resource binds one verified user,
// exact origin and opaque account. Legacy CBC resources remain compatibility
// input; newly entered credentials always use the authenticated Store format.
type LegacyEnrollment struct {
	Namespace string
	Target    Target
	Resource  scy.Resource
}
type LegacyResolver struct{ entries map[string]LegacyEnrollment }

var basicType = reflect.TypeOf(cred.Basic{})

func NewLegacyResolver(enrollments []LegacyEnrollment) (*LegacyResolver, error) {
	r := &LegacyResolver{entries: map[string]LegacyEnrollment{}}
	for _, e := range enrollments {
		if len(e.Namespace) != 64 || e.Target.Validate() != nil || e.Resource.URL == "" || e.Resource.Fallback != nil || len(e.Resource.Data) != 0 || len(e.Resource.Options) != 0 {
			return nil, ErrScope
		}
		if decoded, err := hex.DecodeString(e.Namespace); err != nil || len(decoded) != 32 || strings.ToLower(e.Namespace) != e.Namespace {
			return nil, ErrScope
		}
		// Explicit env/MAC compatibility only. Default/public and inline/file key
		// choices are rejected here; key values never appear in an agent reference.
		key, err := kms.NewKey(e.Resource.Key)
		if err != nil || key.Scheme != "blowfish" {
			return nil, ErrScope
		}
		if e.Resource.Key != "blowfish://mac" {
			name := strings.TrimPrefix(key.Path, "/")
			if key.Kind != "env" || !envName.MatchString(name) || e.Resource.Key != "blowfish://env/"+name {
				return nil, ErrScope
			}
		}
		ref := reference(e.Namespace, e.Target)
		if _, ok := r.entries[ref]; ok {
			return nil, ErrScope
		}
		r.entries[ref] = e
	}
	return r, nil
}
func (r *LegacyResolver) Reference(ctx context.Context, t Target) (Reference, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return Reference{}, err
	}
	if t.Validate() != nil {
		return Reference{}, ErrScope
	}
	ref := reference(p.Namespace, t)
	if _, ok := r.entries[ref]; !ok {
		return Reference{}, ErrMissing
	}
	return Reference{ResourceURL: ref}, nil
}

// Consume is a private compatibility boundary. Caller first freshly verifies
// browser binding, then applies bytes synchronously with recording suppressed.
func (r *LegacyResolver) Consume(ctx context.Context, t Target, ref Reference, consume func(Credentials) error) (result error) {
	// Scy's legacy Blowfish decoder slices its IV before length validation.
	// Corrupt legacy data must fail closed rather than crash the signed broker.
	defer func() {
		if recover() != nil {
			result = ErrUnavailable
		}
	}()
	p, err := auth.FromContext(ctx)
	if err != nil {
		return err
	}
	if t.Validate() != nil || ref.ResourceURL != reference(p.Namespace, t) || consume == nil {
		return ErrScope
	}
	e, ok := r.entries[ref.ResourceURL]
	if !ok {
		return ErrMissing
	}
	resource := e.Resource
	// Typed Scy basic decoding understands EncryptedPassword rather than assuming
	// whole-file CBC. No secret or underlying Scy error escapes this boundary.
	resource.SetTarget(basicType)
	secret, err := scy.New().Load(ctx, &resource)
	if err != nil {
		return ErrUnavailable
	}
	value, ok := secret.Target.(*cred.Basic)
	if !ok || value.Username == "" || value.Password == "" {
		return ErrUnavailable
	}
	c := Credentials{username: []byte(value.Username), password: []byte(value.Password)}
	value.Username = ""
	value.Password = ""
	secret.Target = nil
	defer clear(c.username)
	defer clear(c.password)
	if err := consume(c); err != nil {
		return ErrUnavailable
	}
	return nil
}
