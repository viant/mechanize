package host

import (
	"context"
	"errors"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	repairs "github.com/viant/mechanize/engine/recovery"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
)

// HostOptions carries trusted deployment providers, never client JSON claims.
// New remains observe-only. The host owns the supplied manager's lifecycle and
// binds its enrollment and owner context independently of provider assertions.
type HostOptions struct {
	// NativeRecoveryPolicy supplies deployment-qualified locator contracts and
	// explicit safe display labels. The host retains observation/consent control;
	// neither workflow JSON nor MCP clients can supply this resolver.
	// It must only resolve trusted metadata: repair admission calls it while the
	// physical executor fence is held, so it must not acquire or dispatch input.
	NativeRecoveryPolicy func(context.Context, auth.Principal, repairs.Snapshot) (NativeRecoveryEvidencePolicy, error)
	NativeControl        *NativeControlOptions
	NativeRecording      *NativeRecordingOptions
	WebControl           *WebControlOptions
	// NativeVaultInput is a trusted preprovisioned encrypted store plus qualified
	// native entry protection. It cannot come from configuration JSON or MCP.
	// The embedding provider owns the store and must retain it until host shutdown.
	NativeVaultInput    *vault.NativeInputService
	NativeVaultEntry    *vault.NativeEntryController
	NativeVaultKeySetup *vault.NativeKeySetup
	NativeVaultRecords  *vault.NativeRecordInputService
	// Independent bounded budget for generated consent cleanup transitions after
	// the physical stop finishes. This option carries no dispatch authority.
	NativeCleanupPersistenceTimeout time.Duration
}

var ErrNativeControlCleanupPersistence = errors.New("native cleanup metadata durability unconfirmed; reconciliation requires attention")

const defaultNativeCleanupPersistenceTimeout = 10 * time.Second

func (h *Host) configureNativeControl(ctx context.Context, c Config, options HostOptions) error {
	if options.NativeCleanupPersistenceTimeout < 0 || options.NativeCleanupPersistenceTimeout > 30*time.Second {
		return errors.New("native cleanup persistence timeout must be zero for the default or positive and at most 30 seconds")
	}
	h.nativeCleanupPersistenceTimeout = options.NativeCleanupPersistenceTimeout
	if options.NativeControl == nil {
		return nil
	}
	o := *options.NativeControl
	if c.NativeHelper == "" || o.HelperPath != c.NativeHelper {
		return errors.New("native control must use the configured helper executable")
	}
	o.Owner = ctx
	o.Enrolled = func(ctx context.Context, p auth.Principal) ([]string, error) {
		u, err := h.authorize(ctx, p)
		return append([]string(nil), u.NativeBundles...), err
	}
	o.EnrolledScope = func(ctx context.Context, p auth.Principal) (session.Scope, error) {
		u, err := h.authorize(ctx, p)
		if err != nil {
			return session.Scope{}, err
		}
		return nativeUserScope(u).Normalize()
	}
	// Control observations withhold values; the read-only transport retains its
	// separately configured value policy. A union of different users' identifiers
	// must never expand a controlled helper's per-user authority.
	o.AllowedValueIdentifiers = nil
	// The observation client is initialized later during Host construction.
	// Bind the method now; it resolves the authenticated client at proof time.
	o.ReleasedInputProof = h.proveReleasedNativeInput
	var err error
	h.nativeControl, err = NewNativeControlManager(o)
	return err
}

func (h *Host) admitNativeControl(ctx context.Context, p auth.Principal) (NativeControlAdmission, error) {
	u, err := h.authorize(ctx, p)
	if err != nil {
		return NativeControlAdmission{}, err
	}
	if h.nativeControl == nil {
		return NativeControlAdmission{}, ErrNativeControlUnqualified
	}
	return h.nativeControl.AdmitScope(ctx, p, nativeUserScope(u))
}

// Called by durable.Builder before BeginAttempt commits an effect intent. No
// scheduler or dispatch lives here; Endly remains the sole workflow owner.
func (h *Host) controlLeaseEpoch(ctx context.Context, p auth.Principal) (int, error) {
	admission, err := h.admitNativeControl(ctx, p)
	if err != nil {
		return 0, err
	}
	return admission.Epoch, nil
}

func nativeControlAdmissionReason(err error) string {
	switch {
	case errors.Is(err, ErrNativeControlCleanupUnknown), errors.Is(err, session.ErrCleanupUnknown):
		return "nativeCleanupUnknown"
	case errors.Is(err, session.ErrNoLease), errors.Is(err, session.ErrContended):
		return "nativeLeaseUnavailable"
	case errors.Is(err, context.DeadlineExceeded):
		return "nativeAdmissionDeadline"
	case errors.Is(err, context.Canceled):
		return "nativeAdmissionCancelled"
	case errors.Is(err, auth.ErrUnauthorized):
		return "nativeAdmissionUnauthorized"
	default:
		return "nativeControlUnqualified"
	}
}
func nativeControlUnavailable(caps map[string]bool, reasons []map[string]string, reason string) {
	if len(reasons) == 0 || reasons[0] == nil {
		return
	}
	for _, name := range []string{"appLaunch", "appActivation", "appQuit", "semanticPress", "replaceValue", "semanticSubmit", "targetedFocus", "targetedKeyboard", "sessionKeyboard", "windowSessionText", "windowFrameClick"} {
		key := "native:" + name
		caps[key] = false
		reasons[0][key] = reason
	}
}
func (h *Host) nativeControlPolicy(ctx context.Context, p auth.Principal, caps map[string]bool, reasons ...map[string]string) bool {
	return h.nativeControlPolicyAdmitted(ctx, p, caps, nil, reasons...)
}

func (h *Host) nativeControlPolicyAdmitted(ctx context.Context, p auth.Principal, caps map[string]bool, admission *NativeControlAdmission, reasons ...map[string]string) bool {
	tabActivation := caps["web:browser.activateTab"] && p.HasScope("desktop:control")
	originOpening := caps["web:browser.openOrigin"] && p.HasScope("desktop:control")
	// A native grant cannot qualify a renderer or browser executor generation.
	for _, action := range model.Actions() {
		if !action.ReadOnly {
			delete(caps, "web:"+action.Capability)
		}
	}
	for _, name := range []string{"element.press", "element.fill", "browser.navigate", "browser.activate", "semanticPress", "replaceValue", "navigation", "tabActivation"} {
		delete(caps, "web:"+name)
	}
	webMutation := originOpening || tabActivation
	if tabActivation {
		caps["web:browser.activateTab"] = true
	}
	if originOpening {
		caps["web:browser.openOrigin"] = true
	}
	if h.webControl != nil && p.HasScope("desktop:control") {
		// Renderer authority has its own signed-channel/document admission. A
		// native lease neither qualifies nor suppresses a qualified web route.
		for name, supported := range h.webControl.Capabilities(ctx, p) {
			if supported {
				caps[name] = true
				webMutation = true
			}
		}
	}
	if h.nativeControl == nil || !p.HasScope("desktop:control") {
		reason := "nativeControlUnqualified"
		if !p.HasScope("desktop:control") {
			reason = "nativeAdmissionUnauthorized"
		}
		nativeControlUnavailable(caps, reasons, reason)
		return webMutation
	}
	if admission == nil || !h.nativeControl.admissionCurrent(ctx, p, *admission) {
		if _, err := h.admitNativeControl(ctx, p); err != nil {
			nativeControlUnavailable(caps, reasons, nativeControlAdmissionReason(err))
			return webMutation
		}
	}
	caps["native:appLaunch"] = true
	if h.nativeControl.options.SessionText {
		caps["native:windowSessionText"] = true
	}
	if h.nativeControl.options.SessionKeyboard {
		caps["native:sessionKeyboard"] = true
	}
	if h.nativeControl.options.TargetedKeyboard {
		caps["native:targetedKeyboard"] = true
	}
	if h.nativeControl.options.WindowFrameClick {
		caps["native:windowFrameClick"] = true
	}
	if h.nativeControl.options.LaunchOnly {
		return true
	}
	// These capabilities describe the narrow qualified route. Exact human grant
	// authorization is still required for every individual dispatch.
	for _, name := range []string{"boundedObservation", "roleLocator", "idLocator", "nameLocator", "windowScope", "ancestorScope", "attributeRead", "appActivation", "appQuit", "semanticPress", "replaceValue", "semanticSubmit", "targetedFocus"} {
		caps["native:"+name] = true
	}
	return true
}

func (h *Host) executeNativeControl(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
	result := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	// The durable callback must carry the same fence admitted before intent. A
	// takeover between intent and action is a barrier, never a new admission.
	scope, err := data.RequireScope(ctx, p.Namespace)
	if err != nil || scope.LeaseEpoch <= 0 {
		return result, errors.Join(err, session.ErrNoLease)
	}
	admission, err := h.admitNativeControl(ctx, p)
	if err != nil {
		return result, err
	}
	if admission.Epoch != scope.LeaseEpoch {
		return result, session.ErrNoLease
	}
	policy, err := h.policy(ctx, p, &admission)
	if err != nil {
		return result, err
	}
	if err = (script.Validator{}).CheckStepPolicy(step, policy); err != nil {
		return result, err
	}
	var lease *consent.Lease
	var finish func()
	if step.Action == "window.clickFrame" {
		lease, finish, err = h.consumeWindowFrame(ctx, p, step, values, admission)
		if finish != nil {
			defer finish()
		}
	} else if prepared, ok := ctx.Value(nativeStepAuthorityKey{}).(*nativeStepAuthority); ok {
		lease, err = prepared.consume(ctx, h, p, step, admission.Epoch)
	} else {
		lease, err = h.authorizeNativeControlStep(ctx, p, step)
	}
	if err != nil {
		return result, err
	}
	result, dispatchErr := admission.Gateway.Execute(lease.Context, p, step, values)
	// Revocation cancels Lease.Context even during a native call. After Execute
	// returns, stop/reap and prove cleanup with a fresh bounded identity context.
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	report, cleanupErr := h.nativeControl.Revoke(stopCtx, p)
	stopCancel()
	if cleanupErr == nil && report.InputInhibited && report.HelperStopped && report.FenceReleased && !report.UnknownInputs {
		lease.Release()
	} else {
		// Keep the admitted lease registered: an empty registry is not cleanup proof.
		// Stop and metadata persistence have independent budgets. Slow generated
		// database transitions cannot spend the physical stop's deadline, and a
		// canceled request cannot discard the cleanup record.
		timeout := h.nativeCleanupPersistenceTimeout
		if timeout == 0 {
			timeout = defaultNativeCleanupPersistenceTimeout
		}
		// The admitted lease carries the resolved reusable GrantID. The outer
		// caller binding may intentionally omit it; cancellation must not lose
		// that verified binding when persisting cleanup uncertainty.
		metadataCtx, metadataCancel := context.WithTimeout(context.WithoutCancel(lease.Context), timeout)
		metadataErr := h.markControlCleanupUnknown(metadataCtx, p)
		metadataCancel()
		cleanupErr = errors.Join(cleanupErr, ErrNativeControlCleanupUnknown, metadataErr)
		if metadataErr != nil {
			cleanupErr = errors.Join(cleanupErr, ErrNativeControlCleanupPersistence, &model.MechanizeError{
				Code: "cleanupPersistenceUnknown", Stage: "cleanup", DispatchState: result.DispatchState, EffectState: "unknown",
				Message: "Native cleanup is uncertain and its durable consent update is unconfirmed. Control remains inhibited; reconcile the helper and consent record before resuming.",
			})
		}
	}
	return result, errors.Join(dispatchErr, cleanupErr)
}

func (h *Host) markControlCleanupUnknown(ctx context.Context, p auth.Principal) error {
	if h.consent == nil {
		return errors.New("native permission broker unavailable during cleanup")
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.GrantID == "" {
		return auth.ErrUnauthorized
	}
	ctx, service, err := h.consent.bound(ctx, p)
	if err != nil {
		return err
	}
	_, err = service.ReportDispatchCleanupUnknown(ctx, binding.GrantID)
	return err
}

func nativeUserScope(user User) session.Scope {
	if user.DesktopAccess {
		return session.Scope{AllApplications: true}
	}
	return session.Scope{AllowedBundles: append([]string(nil), user.NativeBundles...)}
}
