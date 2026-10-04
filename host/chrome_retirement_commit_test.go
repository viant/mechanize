package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	write "github.com/viant/mechanize/data/chromeretirementwrite"
	"github.com/viant/xdatly/handler"
	"testing"
	"time"
)

func TestRetirementCommitDoesNotRetryOrAcceptUnconfirmedReadback(t *testing.T) {
	for _, mode := range []string{"valid", "writeError", "unknownCommit", "noCompletion", "readError", "nilRow", "wrongClient", "wrongRevision", "missingAudit", "changedAudit", "unexpectedManifest"} {
		t.Run(mode, func(t *testing.T) {
			ctx, a := retirementAuthorityFixture(t)
			a.Phase = "intended"
			a.PriorRevision = 0
			a.Manifests = nil
			ctx, err := data.WithChromeRetirementAuthority(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			writes, reads := 0, 0
			var saved *write.Retirement
			invoke := func(ctx context.Context, p auth.Principal, r exec.ComponentRequest) (any, error) {
				switch r.Target.Component.Name {
				case "WriteChromeRetirement":
					writes++
					saved = r.Input.(*write.WriteChromeRetirementInput).WriteChromeRetirement[0]
					if mode == "writeError" {
						return nil, errors.New("fixture")
					}
					if mode != "noCompletion" {
						state := handler.TransactionCommitted
						if mode == "unknownCommit" {
							state = handler.TransactionCommitUnknown
						}
						r.Completion(handler.Outcome{Transactions: []handler.TransactionOutcome{{State: state}}})
					}
					return &write.WriteChromeRetirementOutput{}, nil
				case "LoadChromeRetirement":
					reads++
					if reads == 1 {
						return &get.LoadChromeRetirementOutput{}, nil
					}
					if mode == "readError" {
						return nil, errors.New("fixture")
					}
					raw, _ := json.Marshal(saved)
					var row get.Retirement
					if err := json.Unmarshal(raw, &row); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "nilRow":
						return &get.LoadChromeRetirementOutput{Data: []*get.Retirement{nil}}, nil
					case "wrongClient":
						row.ClientId = retirementValue("other-client")
					case "wrongRevision":
						row.Revision = retirementValue(2)
					case "missingAudit":
						row.Audit = nil
					case "changedAudit":
						row.Audit[0].PayloadJson = retirementValue("{}")
					case "unexpectedManifest":
						row.Manifests = []*get.Manifest{{Id: retirementValue("unexpected")}}
					}
					return &get.LoadChromeRetirementOutput{Data: []*get.Retirement{&row}}, nil
				default:
					t.Fatal("unexpected component")
				}
				return nil, errors.New("unreachable")
			}
			got, err := commitChromeRetirement(ctx, invoke)
			if mode == "valid" {
				if err != nil || got == nil {
					t.Fatal(err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unconfirmed readback accepted")
			}
			if writes != 1 || reads > 2 {
				t.Fatal("commit or readback replayed")
			}
			if (mode == "writeError" || mode == "unknownCommit" || mode == "noCompletion") && reads != 1 {
				t.Fatal("uncertain commit proceeded to success readback")
			}
		})
	}
}

func TestRetirementCommitAdoptsHistoricalIntentionWithoutWrite(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		ctx, a := retirementAuthorityFixture(t)
		a.Phase = "intended"
		a.PriorRevision = 0
		a.Manifests = nil
		a.Now = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		a.CreatedAt = a.Now
		a.EvidenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		ctx, err := data.WithChromeRetirementAuthority(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		input, err := chromeRetirementInput(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(input.WriteChromeRetirement[0])
		var stored get.Retirement
		if err = json.Unmarshal(raw, &stored); err != nil {
			t.Fatal(err)
		}
		if tamper {
			stored.Audit[0].PayloadJson = retirementValue("{}")
		}
		calls := 0
		out, err := commitChromeRetirement(ctx, func(_ context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
			calls++
			if r.Target.Route.Method != "GET" {
				t.Fatal("adoption attempted write")
			}
			return &get.LoadChromeRetirementOutput{Data: []*get.Retirement{&stored}}, nil
		})
		if tamper {
			if err == nil || out != nil {
				t.Fatal("changed audit adopted")
			}
		} else if err != nil || out == nil || *out.UpdatedAt != a.Now {
			t.Fatal("historical phase changed", err)
		}
		if calls != 1 {
			t.Fatal("adoption retried")
		}
	}
}
