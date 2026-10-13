package durable

import (
	"context"
	"errors"
	"fmt"
	bootstrapindex "github.com/viant/datly/bootstrap/index"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/data/credentialprotectionscopelist"
	"strings"
	"testing"
)

func TestCredentialProtectionDiagnosticKeepsClosedCauseAndBarrier(t *testing.T) {
	ctx, p := privateActor(t)
	for _, test := range []struct {
		name, cause string
		output      any
		failure     error
	}{
		{"source changed", "metadataSourceChanged", nil, fmt.Errorf("%w: private path and data", bootstrapindex.ErrStaleSource)},
		{"deadline", "requestDeadline", nil, context.DeadlineExceeded},
		{"wrong shape", "projectionShapeInvalid", struct{}{}, nil},
		{"nil typed shape", "projectionShapeInvalid", (*credentialprotectionscopelist.CredentialProtectionScopeListOutput)(nil), nil},
		{"capacity", "projectionCapacityExceeded", &credentialprotectionscopelist.CredentialProtectionScopeListOutput{Data: make([]*credentialprotectionscopelist.ProtectionScope, 513)}, nil},
		{"bad row", "projectionShapeInvalid", &credentialprotectionscopelist.CredentialProtectionScopeListOutput{Data: []*credentialprotectionscopelist.ProtectionScope{{}}}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			result, err := readCredentialProtectionProjection(ctx, p, []string{"https://public.invalid"}, func(context.Context, exec.ComponentRequest) (any, error) { calls++; return test.output, test.failure })
			if err == nil || result != nil || calls != 1 {
				t.Fatal("unreadable scopes became empty protection authority")
			}
			phase, cause := ClosedProtectionMetadataDiagnostic(err)
			if cause != test.cause || phase != "scopeList" && phase != "projection" {
				t.Fatal("closed phase/cause lost")
			}
			if test.failure != nil && !errors.Is(err, test.failure) {
				t.Fatal("underlying cause lost")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("reader detail exposed")
			}
		})
	}
}
