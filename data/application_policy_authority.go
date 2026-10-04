package data

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth"
	"io"
	"strings"
	"time"
)

// ApplicationPolicyAuthority is the exact write proof issued by the broker after
// verifying the native human transport. Request body fields cannot create it.
type ApplicationPolicyAuthority struct {
	Namespace        string
	ExpectedRevision int
	PolicyJSON       string
	CreatedAt        string
	UpdatedAt        string
}
type applicationPolicyAuthorityKey struct{}

func WithApplicationPolicyAuthority(ctx context.Context, a ApplicationPolicyAuthority) context.Context {
	return context.WithValue(ctx, applicationPolicyAuthorityKey{}, a)
}
func RequireApplicationPolicyAuthority(ctx context.Context, namespace string) (ApplicationPolicyAuthority, error) {
	a, ok := ctx.Value(applicationPolicyAuthorityKey{}).(ApplicationPolicyAuthority)
	p, err := auth.FromContext(ctx)
	if !ok || err != nil || !auth.NativeHuman(ctx) || p.Namespace != namespace || a.Namespace != namespace || a.ExpectedRevision < 0 {
		return a, fmt.Errorf("verified native human application policy authority required")
	}
	if _, err = RequireScope(ctx, namespace); err != nil {
		return a, err
	}
	for _, at := range []string{a.CreatedAt, a.UpdatedAt} {
		if _, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return a, fmt.Errorf("trusted policy timestamp required")
		}
	}
	var policy ApplicationPolicy
	decoder := json.NewDecoder(strings.NewReader(a.PolicyJSON))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil {
		return a, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return a, fmt.Errorf("single application policy required")
	}
	canonical, err := ApplicationPolicyJSON(policy)
	if err != nil {
		return a, err
	}
	if canonical != a.PolicyJSON {
		return a, fmt.Errorf("canonical application policy proof required")
	}
	return a, nil
}
