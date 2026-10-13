package durable

import (
	"context"
	"errors"
	"fmt"
	bootstrapindex "github.com/viant/datly/bootstrap/index"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/getartifact"
	"strings"
	"testing"
)

func TestArtifactPublicationClosedPhaseDiagnostic(t *testing.T) {
	ctx, p, ref := publicationFixture(t)
	private := errors.New("private database path and bound values")
	for _, test := range []struct {
		name, phase, cause string
		failAt             string
		failure            error
	}{
		{"reader source changed", "read", "metadataSourceUnavailable", "firstRead", fmt.Errorf("%w: private source path", bootstrapindex.ErrStaleSource)},
		{"reader unavailable", "read", "metadataUnavailable", "firstRead", private},
		{"reader ownership", "read", "authorizationDenied", "firstRead", auth.ErrUnauthorized},
		{"reader canceled", "read", "requestCancelled", "firstRead", context.Canceled},
		{"writer lost ack and absent", "writeAck", "metadataUnavailable", "write", private},
		{"readback deadline", "readback", "requestDeadline", "readback", context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads, writes := 0, 0
			err := publishVerifiedArtifact(ctx, p.Namespace, ref, func(_ context.Context, pkg, _, _ string, _ any, _ bool) (any, error) {
				if pkg == "publishartifact" {
					writes++
					return nil, private
				}
				reads++
				if test.failAt == "firstRead" && reads == 1 || test.failAt == "readback" && reads == 2 {
					return nil, test.failure
				}
				return &getartifact.GetArtifactOutput{}, nil
			})
			var diagnostic *ArtifactPublicationFailure
			if !errors.As(err, &diagnostic) || diagnostic.Phase != test.phase || diagnostic.Cause != test.cause {
				t.Fatalf("closed phase %s cause %s not preserved", test.phase, test.cause)
			}
			if !errors.Is(err, test.failure) {
				t.Fatal("original internal cause lost")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("internal detail exposed")
			}
			if test.failAt == "firstRead" && writes != 0 {
				t.Fatal("failed reader attempted publication")
			}
			if test.failAt != "firstRead" && (writes != 1 || reads != 2) {
				t.Fatal("publication was replayed")
			}
		})
	}
}
