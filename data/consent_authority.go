package data

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
)

// ConsentAuthority is issued by the authenticated broker after client/actor,
// ceiling, session and exact-target checks. Tool request fields are never authority.
// Expected is the complete resulting record; hooks reject extra changed columns.
type ConsentAuthority struct {
	Operation, ActorID, AuditID, Payload string
	Now                                  int
	Expected                             map[string]any
}
type consentAuthorityKey struct{}

func WithConsentAuthority(ctx context.Context, authority ConsentAuthority) context.Context {
	copy := authority
	copy.Expected = make(map[string]any, len(authority.Expected))
	for k, v := range authority.Expected {
		copy.Expected[k] = v
	}
	return context.WithValue(ctx, consentAuthorityKey{}, copy)
}
func RequireConsentAuthority(ctx context.Context, operation string) error {
	a, ok := ctx.Value(consentAuthorityKey{}).(ConsentAuthority)
	if !ok || a.Operation != operation || a.ActorID == "" || a.Now <= 0 {
		return fmt.Errorf("authenticated consent broker authority required")
	}
	return nil
}

// RequireConsentClientRead limits discovery to the verified client for which the
// broker issued read authority; human-wide snapshot reads use separate components.
func RequireConsentClientRead(ctx context.Context, clientID string) error {
	if err := RequireConsentAuthority(ctx, "read"); err != nil {
		return err
	}
	a := ctx.Value(consentAuthorityKey{}).(ConsentAuthority)
	if clientID == "" || a.ActorID != clientID {
		return fmt.Errorf("verified own-client consent read required")
	}
	return nil
}

func ValidateConsentMutation(ctx context.Context, operation string, raw, previous []byte, auditID, actorID, kind string, at int, payload string) error {
	if err := RequireConsentAuthority(ctx, operation); err != nil {
		return err
	}
	a := ctx.Value(consentAuthorityKey{}).(ConsentAuthority)
	if a.AuditID == "" || auditID != a.AuditID || actorID != a.ActorID || kind != operation || at != a.Now || payload != a.Payload {
		return fmt.Errorf("trusted immutable consent audit mismatch")
	}
	var current, old map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if len(previous) > 0 {
		if err := json.Unmarshal(previous, &old); err != nil {
			return err
		}
	}
	if operation == "create" {
		if old != nil {
			return fmt.Errorf("consent request identity already exists")
		}
	} else if old == nil {
		return fmt.Errorf("authorized consent request not found")
	}
	for key, want := range a.Expected {
		value, ok := current[key]
		if !ok || value == nil {
			value = old[key]
		}
		if !reflect.DeepEqual(value, want) {
			return fmt.Errorf("consent authority mismatch for %s", key)
		}
	}
	for key, value := range current {
		if key == "audit" || value == nil {
			continue
		}
		if _, ok := a.Expected[key]; !ok {
			return fmt.Errorf("unexpected consent column %s", key)
		}
	}
	if old != nil {
		for _, key := range []string{"namespace", "id", "clientId", "clientName", "sessionId", "scopeJson", "modesJson", "purpose", "durationSeconds", "createdAt", "requestExpiresAt"} {
			if !reflect.DeepEqual(old[key], a.Expected[key]) {
				return fmt.Errorf("immutable consent request %s", key)
			}
		}
		revision, ok := old["revision"].(float64)
		if !ok || a.Expected["revision"] != revision+1 {
			return fmt.Errorf("consent CAS revision required")
		}
	}
	switch operation {
	case "create":
		if a.Expected["requestState"] != "pending" || a.Expected["grantState"] != "none" || a.Expected["decision"] != "" {
			return fmt.Errorf("invalid new consent request")
		}
	case "decide":
		expiry, _ := old["requestExpiresAt"].(float64)
		if old["requestState"] != "pending" || expiry <= float64(a.Now) || a.Expected["requestState"] != "decided" {
			return fmt.Errorf("expired or decided consent request")
		}
		decision := a.Expected["decision"]
		if decision != "allow_once" && decision != "allow_session" && decision != "allow_until_revoked" && decision != "deny" {
			return fmt.Errorf("invalid decision")
		}
		if decision == "deny" {
			if a.Expected["grantState"] != "none" {
				return fmt.Errorf("denied request cannot grant")
			}
		} else {
			duration, _ := old["durationSeconds"].(float64)
			expiresAt := float64(a.Now) + duration*1000
			if decision == "allow_until_revoked" {
				expiresAt = 0
			}
			if a.Expected["grantState"] != "active" || a.Expected["grantCreatedAt"] != float64(a.Now) || a.Expected["grantExpiresAt"] != expiresAt {
				return fmt.Errorf("grant duration mismatch")
			}
		}
	case "consume":
		expiry, _ := old["grantExpiresAt"].(float64)
		if old["grantState"] != "active" || old["decision"] != "allow_once" || expiry <= float64(a.Now) || old["revocationState"] != "" || a.Expected["grantState"] != "consumed" {
			return fmt.Errorf("once consent unavailable")
		}
		for _, key := range []string{"requestState", "decision", "grantId", "grantCreatedAt", "grantExpiresAt", "revocationState"} {
			if !reflect.DeepEqual(old[key], a.Expected[key]) {
				return fmt.Errorf("consume cannot change %s", key)
			}
		}
	case "revoke":
		next := a.Expected["revocationState"]
		previous := old["revocationState"]
		allowed := previous == "" && next == "requested" || previous == "requested" && next == "stopping" || previous == "stopping" && (next == "revoked" || next == "cleanupUnknown") || previous == "cleanupUnknown" && next == "stopping"
		if !allowed {
			return fmt.Errorf("invalid revocation transition")
		}
		if next == "revoked" {
			if a.Expected["grantState"] != "revoked" {
				return fmt.Errorf("revoked confirmation required")
			}
		} else if !reflect.DeepEqual(old["grantState"], a.Expected["grantState"]) {
			return fmt.Errorf("pending revocation cannot report completion")
		}
		for _, key := range []string{"requestState", "decision", "grantId", "grantCreatedAt", "grantExpiresAt"} {
			if !reflect.DeepEqual(old[key], a.Expected[key]) {
				return fmt.Errorf("revoke cannot change %s", key)
			}
		}
	default:
		return fmt.Errorf("unsupported consent operation")
	}
	return nil
}

// ValidateConsentAudit makes audit inserts immutable even when an attacker tries
// to attach an existing audit identity from a different request to the graph.
func ValidateConsentAudit(ctx context.Context, namespace, requestID, id, actor, kind string, at int, payload string, exists bool) error {
	a, ok := ctx.Value(consentAuthorityKey{}).(ConsentAuthority)
	if !ok || exists {
		return fmt.Errorf("consent audit is append-only")
	}
	if _, err := RequireScope(ctx, namespace); err != nil {
		return err
	}
	if a.Expected["id"] != requestID || a.AuditID != id || a.ActorID != actor || a.Operation != kind || a.Now != at || a.Payload != payload {
		return fmt.Errorf("consent audit authority mismatch")
	}
	return nil
}
