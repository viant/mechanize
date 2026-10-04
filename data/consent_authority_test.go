package data

import (
	"context"
	"encoding/json"
	"testing"
)

func TestConsentPermanentDecisionProofRetainsImmutableRequest(t *testing.T) {
	old := map[string]any{"namespace": "namespace", "id": "request", "clientId": "client", "clientName": "Client", "sessionId": "session", "scopeJson": "scope", "modesJson": "modes", "purpose": "original", "durationSeconds": float64(60), "createdAt": float64(100), "requestExpiresAt": float64(10000), "requestState": "pending", "decision": "", "grantId": "grant", "grantCreatedAt": float64(0), "grantExpiresAt": float64(0), "grantState": "none", "revocationState": "", "revision": float64(1)}
	original, _ := json.Marshal(old)
	proof := func(mut func(map[string]any)) error {
		expected := map[string]any{}
		for k, v := range old {
			expected[k] = v
		}
		expected["requestState"] = "decided"
		expected["decision"] = "allow_until_revoked"
		expected["grantState"] = "active"
		expected["grantCreatedAt"] = float64(1000)
		expected["revision"] = float64(2)
		if mut != nil {
			mut(expected)
		}
		raw, _ := json.Marshal(expected)
		authority := ConsentAuthority{Operation: "decide", ActorID: "human", AuditID: "audit", Now: 1000, Payload: string(raw), Expected: expected}
		return ValidateConsentMutation(WithConsentAuthority(context.Background(), authority), "decide", raw, original, "audit", "human", "decide", 1000, string(raw))
	}
	if err := proof(nil); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"namespace", "clientId", "sessionId", "scopeJson", "modesJson", "purpose", "durationSeconds"} {
		t.Run(key, func(t *testing.T) {
			if err := proof(func(m map[string]any) { m[key] = "changed" }); err == nil {
				t.Fatalf("permanent decision changed immutable %s", key)
			}
		})
	}
	if err := proof(func(m map[string]any) { m["grantExpiresAt"] = float64(61000) }); err == nil {
		t.Fatal("permanent decision accepted fabricated expiry")
	}
	if err := proof(func(m map[string]any) { m["decision"] = "allow_session" }); err == nil {
		t.Fatal("session decision accepted zero expiry")
	}
	if err := proof(func(m map[string]any) { m["decision"] = "allow_once" }); err == nil {
		t.Fatal("once decision accepted zero expiry")
	}
}

func TestOwnClientConsentReadProof(t *testing.T) {
	ctx := WithConsentAuthority(context.Background(), ConsentAuthority{Operation: "read", ActorID: "client", Now: 1000})
	if err := RequireConsentClientRead(ctx, "client"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "other"} {
		if err := RequireConsentClientRead(ctx, id); err == nil {
			t.Fatalf("read authority accepted %q", id)
		}
	}
	if err := RequireConsentClientRead(context.Background(), "client"); err == nil {
		t.Fatal("missing broker proof accepted")
	}
}
