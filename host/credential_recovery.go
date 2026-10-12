package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/vault"
	"os"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

// credentialRecoverySurface extracts a single verified quit from its immutable
// plan. Caller-provided PID, birth, dispatch knowledge and cleanup booleans are
// never accepted. The OS birth observation below remains mandatory afterwards.
func credentialRecoverySurface(state durable.State, content, expectedHash string) (model.Surface, error) {
	fail := func() (model.Surface, error) { return model.Surface{}, errPrivateCredential }
	hash := sha256.Sum256([]byte(content))
	if hex.EncodeToString(hash[:]) != expectedHash || len(state.UnresolvedEffects) != 0 || len(state.Progress) != 1 || state.Progress[0].State == nil || *state.Progress[0].State != "verified" {
		return fail()
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	if json.Unmarshal([]byte(content), &envelope) != nil || len(envelope.Plan.Steps) != 1 || len(envelope.Inputs) != 0 || !privateChromeQuit(envelope.Plan.Steps[0]) {
		return fail()
	}
	return envelope.Plan.Steps[0].Target.Surface, nil
}

func credentialOriginalProcessGone(surface model.Surface, inspect session.ProcessInspector) error {
	if inspect == nil || surface.Kind != "native" || surface.BundleID != "com.google.Chrome" || surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil {
		return errPrivateCredential
	}
	actual, alive, e := inspect(surface.ProcessID)
	if e != nil || alive && actual.StartToken == surface.ProcessStartToken {
		return errPrivateCredential
	}
	return nil
}

// CredentialRecover performs metadata-only cleanup after a separately executed
// and verified normal Chrome quit. It retains original identities, outcomes and
// all audits, requires current reusable consent, and never resumes login input.
func (h *Host) CredentialRecover(ctx context.Context, p auth.Principal, in gateway.CredentialRecoverInput) (gateway.CredentialResult, error) {
	out := gateway.CredentialResult{PreparationID: in.PreparationID, State: "needsNativeAction"}
	actual, e := auth.FromContext(ctx)
	if h == nil || h.durable == nil || h.Runtime == nil || h.vaultExposure == nil || e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || p.Validate() != nil || !p.HasScope("desktop:control") || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil || len(in.Purpose) == 0 || len(in.Purpose) > 512 {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	id, e := hex.DecodeString(in.PreparationID)
	if e != nil || len(id) != 32 || hex.EncodeToString(id) != in.PreparationID {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	state, e := h.durable.StateGet(ctx, p, in.RetirementRunID)
	if e != nil {
		return out, nil
	}
	revision, e := h.durable.LoadPlan(ctx, p, state.PlanID)
	if e != nil || revision.ContentJson == nil || revision.ContentHash == nil {
		return out, nil
	}
	surface, e := credentialRecoverySurface(state, *revision.ContentJson, *revision.ContentHash)
	if e != nil {
		return out, nil
	}
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: in.Purpose})
	lease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(ctx), p, surface, true, consent.Control)
	if e != nil {
		return out, nil
	}
	defer lease.Release()
	guard := func(c context.Context) error {
		if c.Err() != nil || h.Runtime.CheckSession(c, p, in.SessionID) != nil {
			return errPrivateCredential
		}
		return credentialOriginalProcessGone(surface, session.InspectProcess)
	}
	if guard(lease.Context) != nil {
		return out, nil
	}
	retire := func(c context.Context) error {
		return h.retireCredentialRecovery(c, p, in.PreparationID, surface, guard)
	}
	e = h.withCredentialRecoveryProtection(lease.Context, p, in.PreparationID, surface, guard, retire)
	if e != nil {
		out.State = "needsNativeAction"
	} else {
		out.State = "recovered"
	}
	return out, nil
}

// The exact retired local capability is selected only from trusted host state;
// caller identifiers cannot choose another lease or supply process-exit proof.
func (h *Host) withCredentialRecoveryProtection(ctx context.Context, p auth.Principal, preparationID string, surface model.Surface, guard, retire func(context.Context) error) error {
	if surface.Kind != "native" || surface.BundleID != "com.google.Chrome" || surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil || guard == nil || retire == nil {
		return errPrivateCredential
	}
	var item *credentialSession
	if h.credentials != nil {
		h.credentials.mu.Lock()
		item = h.credentials.pending[preparationID]
		h.credentials.mu.Unlock()
	}
	if item != nil {
		item.mu.Lock()
		defer item.mu.Unlock()
		if item.actor.Namespace != p.Namespace || item.actor.ClientID != p.ClientID || item.id != preparationID || item.done == nil || item.done.Err() == nil {
			return errPrivateCredential
		}
		original := item.authority.Evidence.ChromeParent
		if original.PID != surface.ProcessID || original.StartToken != surface.ProcessStartToken {
			previousGuard := guard
			guard = func(c context.Context) error {
				if previousGuard(c) != nil {
					return errPrivateCredential
				}
				return session.VerifyProcessBirthAbsent(c, uint32(os.Getuid()), original.StartToken)
			}
		}
		exposure := item.exposure.Load()
		if exposure != nil && exposure.lease != nil {
			if e := exposure.lease.RecoverRetired(ctx, guard, retire); !errors.Is(e, vault.ErrRetiredDeliveryAbsent) {
				return e
			}
		}
	}
	release, e := h.vaultExposure.AcquireExposureContext(ctx)
	if e != nil {
		return errPrivateCredential
	}
	defer release()
	if guard(ctx) != nil {
		return errPrivateCredential
	}
	return retire(ctx)
}

func (h *Host) retireCredentialRecovery(recoveryCtx context.Context, p auth.Principal, preparationID string, surface model.Surface, guard func(context.Context) error) error {
	return h.durable.WithCredentialDeliveryComponents(recoveryCtx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		prep, attempts, e := h.durable.LoadCredentialRecovery(held, p, preparationID)
		if e != nil {
			return e
		}
		if len(attempts) == 0 && prep.ProtectionState != "closed" {
			return errPrivateCredential
		}
		retiredBirth := surface.ProcessStartToken
		retirementGuard := guard
		if len(attempts) > 0 {
			retiredBirth = attempts[0].ChromeStartToken
			for _, old := range attempts {
				if old.ChromeStartToken == "" || old.ChromeStartToken != retiredBirth {
					return errPrivateCredential
				}
			}
			if retiredBirth != surface.ProcessStartToken {
				retirementGuard = func(c context.Context) error {
					if guard(c) != nil {
						return errPrivateCredential
					}
					return session.VerifyProcessBirthAbsent(c, uint32(os.Getuid()), retiredBirth)
				}
				if retirementGuard(held) != nil {
					return errPrivateCredential
				}
			}
		}
		if prep.ProtectionState == "closed" {
			for _, old := range attempts {
				if old.ProtectionState != "closed" && !(old.ProtectionState == "retired" && old.DispatchState == "unknown") {
					return errPrivateCredential
				}
			}
			return nil
		}
		clean, stop, e := data.WithCredentialRetirementAuthority(held, prep, attempts, retiredBirth, retirementGuard)
		if e != nil {
			return e
		}
		defer stop()
		for _, old := range attempts {
			if old.ProtectionState == "closed" || old.ProtectionState == "retired" && old.DispatchState == "unknown" {
				continue
			}
			next := old
			next.ProtectionState = "closed"
			if old.DispatchState == "unknown" {
				next.ProtectionState = "retired"
			}
			next.Revision++
			next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			bound, revoke, e := data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Before: &old, Record: next}, retirementGuard)
			if e != nil {
				return e
			}
			e = h.durable.FinishCredentialDelivery(bound, p)
			revoke()
			if e != nil {
				return e
			}
		}
		prep.ProtectionState = "closed"
		prep.Revision++
		bound, revoke, e := data.WithCredentialPreparationAuthority(clean, prep, retirementGuard)
		if e != nil {
			return e
		}
		defer revoke()
		if e = h.durable.CloseCredentialPreparation(bound, p); e != nil {
			return e
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(bound, p); e != nil || blocked {
			return errPrivateCredential
		}
		if retirementGuard(bound) != nil {
			return errPrivateCredential
		}
		return nil
	})
}
