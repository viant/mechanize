package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPrivateAdministrationClosedAuthenticatedProfile(t *testing.T) {
	uid := uint32(123)
	if _, e := NewPrivateAdministration(Options{HelperPath: "/fixture", ExpectedUID: &uid}); e == nil {
		t.Fatal("missing signature accepted")
	}
	if _, e := NewPrivateAdministration(Options{HelperPath: "/fixture", Requirement: "pin", ExpectedUID: &uid, AllowSemantic: true}); e == nil {
		t.Fatal("mixed profile accepted")
	}
	p, e := NewPrivateAdministration(Options{HelperPath: "/fixture", Requirement: "pin", ExpectedUID: &uid})
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"good", "feature", "epoch", "nonce", "missing", "extra", "duplicate", "error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			call := func(ctx context.Context, r Request) (Reply, error) {
				calls++
				if r.Method == "doctor" {
					version := 1
					if mode == "feature" {
						version = 0
					}
					b, _ := json.Marshal(map[string]any{"privateAdministrationVersion": version})
					return Reply{HelperEpoch: "epoch", Result: b}, nil
				}
				if !p.options.PrivateAdministration || r.Method != "private.consoleWindows" || r.HelperEpoch != "epoch" {
					t.Fatal("wrong private request")
				}
				if mode == "error" {
					return Reply{}, ErrPrivateProof
				}
				var params map[string]any
				json.Unmarshal(r.Params, &params)
				body := map[string]any{"version": 1, "nonce": params["nonce"], "consoles": 1, "entries": 0, "matched": 0}
				epoch := "epoch"
				switch mode {
				case "epoch":
					epoch = "changed"
				case "nonce":
					body["nonce"] = "substituted"
				case "missing":
					delete(body, "entries")
				case "extra":
					body["rawText"] = "forbidden"
				}
				b, _ := json.Marshal(body)
				if mode == "duplicate" {
					b = append(b[:len(b)-1], []byte(",\"entries\":0}")...)
				}
				return Reply{HelperEpoch: epoch, Result: b}, nil
			}
			var out PrivateConsoleWindows
			e := p.exchange(context.Background(), call, "private.consoleWindows", map[string]any{}, &out)
			if (e == nil) != (mode == "good") {
				t.Fatalf("unexpected outcome for %s", mode)
			}
			if mode == "feature" && calls != 1 {
				t.Fatal("missing feature dispatched private query")
			}
		})
	}
}

func TestPrivateNativeFailurePreservesOnlyClosedDiagnosticCodes(t *testing.T) {
	for _, code := range []string{"privateAXTrustDenied", "privateConsoleSignatureInvalid", "privateConsoleProcessInvalid", "privateConsoleInventoryUnavailable", "privateAXIPCUnavailable", "privateWindowShapeUnavailable", "private-raw-value-canary"} {
		err := privateNativeFailure(&NativeError{Code: code, Message: "private-title-secret-canary"})
		var diagnostic *PrivateProofError
		if !errors.As(err, &diagnostic) || !errors.Is(err, ErrPrivateProof) || strings.Contains(err.Error(), "canary") {
			t.Fatal("unsafe or untyped private error")
		}
		expected := code
		if code == "private-raw-value-canary" {
			expected = "privateHelperExchangeUnavailable"
		}
		if diagnostic.Code() != expected {
			t.Fatal("stage lost")
		}
	}
}
