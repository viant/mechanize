package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChromeRetirementHostMapperGeneratedCommitReadback(t *testing.T) {
	ctx, a := retirementAuthorityFixture(t)
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.FromContext(ctx)
	builder, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, errors.New("desktop dispatch forbidden in database test")
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := builder.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	var escaped context.Context
	var escapedInvoke durable.RetirementComponentInvoker
	err = builder.WithChromeRetirementComponents(ctx, p, func(ctx context.Context, invoke durable.RetirementComponentInvoker) error {
		request := func(pkg, name, method string, input any, completion func(handler.Outcome)) exec.ComponentRequest {
			return exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: completion}
		}
		manifests := a.Manifests
		manifests[0].Version = 2
		manifests[0].Receipts[0].FingerprintVersion = 2
		canonical, digest, err := data.ChromeRetirementManifestJSON(manifests[0])
		if err != nil {
			t.Fatal(err)
		}
		for index, phase := range []string{"intended", "prepared", "released", "adopted"} {
			a.Phase = phase
			a.PriorRevision = index
			a.Now = time.Now().UTC().Format(time.RFC3339Nano)
			if index == 0 {
				a.CreatedAt = a.Now
				a.Manifests = nil
			} else {
				a.Manifests = manifests
			}
			if index >= 2 {
				a.Proof.FenceReleaseConfirmed = true
			}
			if phase == "adopted" {
				a.Adoption = &data.ChromeRetirementAdoptionEvidence{Version: 1, BrokerEpoch: "new-broker", ChannelEpoch: "new-channel", ScopeHash: a.OldScopeHash, Process: a.Process, Policy: a.Policy, FreshDocumentsQualified: true}
			}
			bound, err := data.WithChromeRetirementAuthority(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			var outcome handler.Outcome
			committed, err := commitChromeRetirement(bound, func(callCtx context.Context, p auth.Principal, r exec.ComponentRequest) (any, error) {
				return invoke(callCtx, p, r)
			})
			if err != nil || committed == nil {
				t.Fatalf("%s commit/readback: %v", phase, err)
			}

			read := &get.LoadChromeRetirementInput{}
			read.SetNamespace(a.Namespace)
			read.SetClientID(a.ClientID)
			read.SetTransitionID(a.TransitionID)
			value, err := invoke(bound, p, request("chromeretirementget", "LoadChromeRetirement", "GET", read, nil))
			if err != nil {
				t.Fatal(err)
			}
			out, ok := value.(*get.LoadChromeRetirementOutput)
			if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil {
				t.Fatal("missing generated readback")
			}
			row := out.Data[0]
			if row.Phase == nil || *row.Phase != phase || row.Revision == nil || *row.Revision != index+1 || len(row.Audit) != index+1 {
				t.Fatal("phase or audit history mismatch")
			}
			if index > 0 {
				if len(row.Manifests) != 1 || row.Manifests[0].CanonicalManifestJson == nil || *row.Manifests[0].CanonicalManifestJson != canonical || *row.Manifests[0].ManifestDigest != digest {
					t.Fatal("v2 receipt history altered")
				}
			}
			if phase == "intended" || phase == "prepared" {
				adopted, err := commitChromeRetirement(bound, func(c context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
					if r.Target.Route.Method != "GET" {
						t.Fatal("readback adoption attempted a write")
					}
					return invoke(c, actor, r)
				})
				if err != nil || adopted == nil || *adopted.Revision != index+1 {
					t.Fatal("exact committed phase not adopted", err)
				}
			}
			// Reusing the same prior revision must fail without changing generated state.
			baseline, _ := json.Marshal(out)
			stale, err := chromeRetirementInput(bound)
			if err != nil {
				t.Fatal(err)
			}
			outcome = handler.Outcome{}
			_, err = invoke(bound, p, request("chromeretirementwrite", "WriteChromeRetirement", "PATCH", stale, func(v handler.Outcome) { outcome = v }))
			if err == nil || outcome.CommitConfirmed() {
				t.Fatal("duplicate phase committed")
			}
			value, err = invoke(bound, p, request("chromeretirementget", "LoadChromeRetirement", "GET", read, nil))
			if err != nil {
				t.Fatal(err)
			}
			unchanged, _ := json.Marshal(value)
			if string(unchanged) != string(baseline) {
				t.Fatal("rejected phase changed stored history")
			}
			escaped = bound
			escapedInvoke = invoke
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	read := &get.LoadChromeRetirementInput{}
	read.SetNamespace(a.Namespace)
	read.SetClientID(a.ClientID)
	read.SetTransitionID(a.TransitionID)
	request := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementget", Name: "LoadChromeRetirement"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeretirementget"}}, Input: read}
	if _, err = escapedInvoke(escaped, p, request); err == nil {
		t.Fatal("escaped lifecycle context remained usable")
	}
}
