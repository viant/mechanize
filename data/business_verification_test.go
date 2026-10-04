package data

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/objective"
	"testing"
	"time"
)

func TestBusinessVerificationCannotBeForgedByAuditFields(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	proof := BusinessVerification{Namespace: p.Namespace, RunID: "run", PlanID: "plan", ObjectiveHash: "immutable-objective-hash", BusinessKey: "case-1", FreshnessMs: 30000, Result: objective.Result{Truth: objective.True, Authority: objective.Authoritative, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "receipt", Reference: "fixture-receipt", BusinessKey: "case-1"}}}}
	payload := func(p BusinessVerification) string {
		raw, _ := json.Marshal(struct {
			Status string `json:"status"`
			BusinessVerification
		}{"succeeded", p})
		return string(raw)
	}
	if RequireBusinessVerification(ctx, p.Namespace, "run", "plan", payload(proof)) == nil {
		t.Fatal("audit field minted trusted permit")
	}
	trusted, err := WithBusinessVerification(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = RequireBusinessVerification(trusted, p.Namespace, "run", "plan", payload(proof)); err != nil {
		t.Fatal(err)
	}
	mutated := proof
	mutated.BusinessKey = "case-2"
	if RequireBusinessVerification(trusted, p.Namespace, "run", "plan", payload(mutated)) == nil {
		t.Fatal("wrong business key audit accepted")
	}
	if RequireBusinessVerification(trusted, p.Namespace, "other-run", "plan", payload(proof)) == nil {
		t.Fatal("wrong run accepted")
	}
	proof.Result.Truth = objective.Unknown
	if _, err = WithBusinessVerification(ctx, proof); err == nil {
		t.Fatal("unknown objective granted success permit")
	}
}
