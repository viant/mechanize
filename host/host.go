// Package host composes the selected MCP, Scy, Endly and Datly runtimes.
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	mcpserver "github.com/viant/mcp/server"
	"github.com/viant/mechanize/artifact"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/engine/recording"
	repairs "github.com/viant/mechanize/engine/recovery"
	scenarios "github.com/viant/mechanize/engine/scenario"
	"github.com/viant/mechanize/host/localrpc"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/security/keychain"
	"github.com/viant/scy"
)

type Host struct {
	frameMu                         sync.Mutex
	framePermits                    map[string]*windowFramePermit
	framesClosed                    bool
	chromeRetirementEvidence        retirementEvidenceProvider
	applicationAccess               *applicationAccessService
	recovery                        *repairs.Service
	scenarios                       *scenarios.Service
	captureHelper                   string
	captureMaxBytes                 int
	captureWindow                   func(context.Context, native.WindowCaptureOptions) (native.CapturedImage, error)
	captureWindows                  func(context.Context, native.CaptureWindowListOptions) (native.CaptureWindowList, error)
	artifacts                       *ArtifactService
	nativeCleanupPersistenceTimeout time.Duration
	nativeControl                   *NativeControlManager
	nativeRecording                 nativeRecordingBackend
	webControl                      *WebControlManager
	nativeClient                    native.Caller
	nativeByUser                    map[string]*native.Gateway
	consentListener                 *localrpc.Server
	owner                           context.Context
	recordingLeases                 map[string]*consent.Lease
	consent                         *ConsentBroker
	Server                          *mcpserver.Server
	Verifier                        *auth.Verifier
	Runtime                         *automation.Runtime
	native                          *native.Gateway
	chrome                          *chrome.Gateway
	durable                         *durable.Builder
	recording                       *recording.Service
	users                           map[string]User
	mu                              sync.Mutex
	sessions                        []string
}

func New(ctx context.Context, c Config) (*Host, error) {
	options, err := launchHostOptions(c)
	if err != nil {
		return nil, err
	}
	return NewWithOptions(ctx, c, options)
}

func NewWithOptions(ctx context.Context, c Config, options HostOptions) (*Host, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Keychain != nil {
		if err := keychain.Register(*c.Keychain); err != nil {
			return nil, err
		}
	}
	verifier, err := auth.NewVerifier(ctx, &c.Keys, c.IdentityPolicy)
	if err != nil {
		return nil, err
	}
	h := &Host{owner: ctx, captureHelper: c.NativeHelper, captureWindow: native.CaptureWindow, captureWindows: native.ListCaptureWindows, recordingLeases: map[string]*consent.Lease{}, Verifier: verifier, users: map[string]User{}}
	if c.Artifacts != nil {
		h.captureMaxBytes = int(min(c.Artifacts.MaxBytes, int64(native.MaximumCaptureBytes)))
	}
	fail := func(err error) (*Host, error) { _ = h.Close(context.Background()); return nil, err }
	union := map[string]bool{}
	allApplications := false
	valueIDs := map[string][]string{}
	for _, u := range c.Users {
		p, _ := auth.NewPrincipal(c.IdentityPolicy.Issuer, u.Tenant, u.Subject, nil)
		h.users[p.Namespace] = u
		allApplications = allApplications || u.DesktopAccess
		for _, bundle := range u.NativeBundles {
			union[bundle] = true
		}
		for bundle, ids := range u.ValueIdentifiers {
			valueIDs[bundle] = append(valueIDs[bundle], ids...)
		}
	}
	if err := h.configureNativeControl(ctx, c, options); err != nil {
		return fail(err)
	}
	if err := h.configureNativeRecording(ctx, c, options); err != nil {
		return fail(err)
	}
	if c.NativeHelper != "" && (len(union) > 0 || allApplications) {
		readOptions := native.Options{HelperPath: c.NativeHelper, Stderr: os.Stderr}
		if c.NativeLaunch != nil {
			readOptions.Requirement = c.NativeLaunch.HelperRequirement
			readOptions.ExpectedUID = c.NativeLaunch.ExpectedUID
		}
		initial, err := native.NewClient(ctx, readOptions)
		if err != nil {
			return fail(err)
		}
		client, err := native.NewReadOnlyCaller(initial, func(request context.Context) (native.Caller, error) {
			if err := request.Err(); err != nil {
				return nil, err
			}
			if err := h.owner.Err(); err != nil {
				return nil, err
			}
			next, err := native.NewClient(h.owner, readOptions)
			if next == nil {
				return nil, err
			}
			return next, err
		})
		if err != nil {
			_ = initial.Close()
			return fail(err)
		}
		h.nativeClient = client
		bundles := []string{}
		for bundle := range union {
			bundles = append(bundles, bundle)
		}
		h.native, err = native.NewGateway(client, native.GatewayOptions{AllApplications: allApplications, AllowedBundles: func() []string {
			if allApplications {
				return nil
			}
			return bundles
		}(), AllowedValueIdentifiers: valueIDs})
		if err != nil {
			_ = client.Close()
			return fail(err)
		}
		h.nativeByUser = map[string]*native.Gateway{}
		for namespace, user := range h.users {
			if !user.DesktopAccess && len(user.NativeBundles) == 0 {
				continue
			}
			allowed := user.NativeBundles
			if user.DesktopAccess {
				allowed = nil
			}
			gateway, gatewayErr := native.NewGateway(client, native.GatewayOptions{AllApplications: user.DesktopAccess, AllowedBundles: allowed, AllowedValueIdentifiers: user.ValueIdentifiers, AllowedStaticTextBundles: user.StaticTextBundles})
			if gatewayErr != nil {
				return fail(gatewayErr)
			}
			h.nativeByUser[namespace] = gateway
		}
	}
	if c.Chrome != nil {
		for _, grant := range c.Chrome.Grants {
			if _, ok := h.users[grant.Principal.Namespace]; !ok {
				return fail(errors.New("Chrome grant is outside enrolled user set"))
			}
		}
		broker, err := chrome.NewBroker(ctx, *c.Chrome)
		if err != nil {
			return fail(err)
		}
		h.chrome, err = chrome.NewGateway(broker, chrome.GatewayOptions{})
		if err != nil {
			_ = broker.Close()
			return fail(err)
		}
	}
	if err := h.configureChromeRetirement(c); err != nil {
		return fail(err)
	}
	if err := h.configureWebControl(ctx, c, options); err != nil {
		return fail(err)
	}
	var verifyArtifact func(context.Context, auth.Principal, data.ArtifactReference) error
	if c.Artifacts != nil {
		keys, keyErr := artifact.NewScyResolver(c.Artifacts.KeyResources)
		if keyErr != nil {
			return fail(keyErr)
		}
		store, storeErr := artifact.New(artifact.Config{Root: filepath.Join(c.StorageRoot, "artifacts"), SourceKeyReference: c.Artifacts.SourceKeyReference, Keys: keys, MaxBytes: c.Artifacts.MaxBytes, NamespaceQuotaBytes: c.Artifacts.NamespaceQuotaBytes})
		if storeErr != nil {
			return fail(storeErr)
		}
		h.artifacts, err = NewArtifactService(ArtifactOptions{Store: store, Authorize: func(ctx context.Context, p auth.Principal) error {
			_, err := h.authorize(ctx, p)
			return err
		}, Consent: func(ctx context.Context, p auth.Principal, surface model.Surface) (*consent.Lease, error) {
			return h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
		}, Publish: func(ctx context.Context, p auth.Principal, ref data.ArtifactReference) error {
			if h.durable == nil {
				return durable.ErrArtifactVerificationUnavailable
			}
			return h.durable.PublishArtifact(ctx, p, ref)
		}})
		if err != nil {
			_ = store.Close()
			return fail(err)
		}
		verifyArtifact = h.artifacts.VerifyArtifact
	}
	nativeEvaluator, evaluatorErr := h.nativeObjective(c)
	if evaluatorErr != nil {
		return fail(evaluatorErr)
	}
	if err = validateNativeEffectReconciliationEnrollment(c.NativeEffectReconciliation); err != nil {
		return fail(err)
	}
	h.durable, err = durable.New(durable.Options{ObjectiveEvaluator: nativeEvaluator, ReconciliationGuard: h.effectReconciliationGuard, ResolveReconciliation: nativeEffectReconciliationResolver(c.NativeEffectReconciliation), SourceRoot: c.SourceRoot, StorageRoot: c.StorageRoot, MaxUsers: c.MaxUsers, VerifyArtifact: verifyArtifact, StateMutationGuard: func(ctx context.Context, p auth.Principal, runID string) (func(), error) {
		if h.Runtime == nil {
			return nil, durable.ErrStatePatchUnavailable
		}
		return h.Runtime.StateMutationGuard(ctx, p, runID)
	}, RefreshVariables: func(ctx context.Context, p auth.Principal, runID string, variables map[string]model.Value) error {
		if h.Runtime == nil {
			return durable.ErrStatePatchUnavailable
		}
		return h.Runtime.RefreshVariables(ctx, p, runID, variables)
	}, LeaseEpoch: h.controlLeaseEpoch, PrepareStepAuthority: h.prepareStepExecutor,
	}, h.execute)
	if err != nil {
		return fail(err)
	}
	h.applicationAccess = &applicationAccessService{invoke: h.durable.InvokePrivateComponent, enrolled: h.enrolled}
	h.Runtime, err = automation.NewWithOptions(h.durable.Execute, automation.Options{OnSessionClose: h.cancelWindowFrameSession, PreparePlan: h.durable.PreparePlan, EvaluatePostcondition: h.durable.EvaluatePostcondition, CompleteObjective: h.durable.CompleteObjective, LoadResume: h.durable.LoadResume, AttachInitialOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
		_, err := h.durable.AttachOperation(ctx, p, runID, revision, sessionID, operationID)
		return err
	}, AttachOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
		_, err := h.durable.AttachResumedOperation(ctx, p, runID, revision, sessionID, operationID)
		return err
	}})
	if err != nil {
		return fail(err)
	}
	if h.chrome != nil || h.nativeRecording != nil {
		h.recording, err = recording.New(ctx, &recordingBackend{host: h}, recording.ComponentFuncs{AppendEvents: h.durable.AppendRecordingEvents, ReadEvents: h.durable.ReadRecordingEvents})
		if err != nil {
			return fail(err)
		}
	}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: h.durable.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy})
	if err != nil {
		return fail(err)
	}
	if c.NativeConsole != nil {
		peer, err := nativepeer.NewVerifier(nativepeer.Options{ExpectedUID: c.NativeConsole.ExpectedUID, DesignatedRequirement: c.NativeConsole.DesignatedRequirement})
		if err != nil {
			return fail(err)
		}
		h.consentListener, err = OpenConsentListener(ctx, ConsentListenerOptions{SocketPath: c.NativeConsole.SocketPath, Verifier: h.Verifier, VerifyPeer: peer, Broker: h.consent, Additional: h.NativeInformation})
		if err != nil {
			return fail(err)
		}
	}
	h.scenarios, err = scenarios.New(scenarios.Options{Invoke: h.durable.InvokePrivateComponent, Authorize: h.AuthorizeScenarioSurface})
	if err != nil {
		return fail(err)
	}
	recoveryOptions := repairs.Options{Invoke: h.durable.InvokePrivateComponent, Authorize: h.AuthorizeScenarioSurface, Guard: h.recoveryGuard, RuntimeReady: h.recoveryRuntimeReady}
	if options.NativeRecoveryPolicy != nil {
		if h.nativeControl == nil {
			return fail(errors.New("native recovery policy requires native executor guard"))
		}
		provider, providerErr := NewNativeRecoveryEvidence(NativeRecoveryEvidenceOptions{Observe: h.Observe, Resolve: options.NativeRecoveryPolicy})
		if providerErr != nil {
			return fail(providerErr)
		}
		recoveryOptions.PrepareEvidence = provider.Prepare
		recoveryOptions.VerifyEvidence = provider.Verify
	}
	h.recovery, err = repairs.New(recoveryOptions)
	if err != nil {
		return fail(err)
	}
	h.Server, err = gateway.New(gateway.Dependencies{BrowserStatus: h.BrowserStatus, StateStopBoundary: h.durable.StopBoundary, EffectReconcile: h.durable.ReconcileEffect, Recovery: h.recovery, Scenarios: h.scenarios, CaptureWindow: h.CaptureWindow, CaptureWindows: h.CaptureWindows, CaptureWindowFrame: h.CaptureWindowFrame, StateResume: h.ResumeRun, PermissionRequest: h.consent.Request, PermissionStatus: h.consent.RequestStatus, Recording: h.recording, Runtime: h.Runtime, Observe: h.Observe, ObserveNativeRoot: h.ObserveNativeRoot, ObserveNativeWindow: h.ObserveNativeWindow, Policy: h.Policy, StateGet: h.durable.StateGet, StatePatch: h.durable.StatePatch, StatePause: h.PauseRun})
	if err != nil {
		return fail(err)
	}
	return h, nil
}
func (h *Host) authorize(ctx context.Context, p auth.Principal) (User, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace {
		return User{}, auth.ErrUnauthorized
	}
	user, ok := h.users[p.Namespace]
	if !ok {
		return User{}, auth.ErrUnauthorized
	}
	if !p.HasScope("desktop:observe") && !p.HasScope("desktop:control") {
		return User{}, auth.ErrUnauthorized
	}
	return user, nil
}
func (h *Host) Policy(ctx context.Context, p auth.Principal) (script.Policy, error) {
	u, err := h.authorize(ctx, p)
	if err != nil {
		return script.Policy{}, err
	}
	allowed := map[string]bool{}
	for _, v := range u.NativeBundles {
		allowed[v] = true
	}
	for _, v := range u.WebOrigins {
		allowed[v] = true
	}
	caps := map[string]bool{}
	// These describe configured transport/publication, not TCC readiness or a
	// permission grant. The helper rechecks exact ownership and permission on use.
	caps["native:captureWindowTransport"] = h.captureHelper != "" && h.captureWindow != nil && h.captureMaxBytes > 0 && (u.DesktopAccess || len(u.NativeBundles) > 0)
	caps["native:captureDiscoveryTransport"] = h.captureHelper != "" && h.captureWindows != nil && (u.DesktopAccess || len(u.NativeBundles) > 0)
	caps["native:encryptedCapturePublication"] = h.artifacts != nil
	caps["native:recordingTransport"] = h.nativeRecording != nil && h.recording != nil && u.DesktopAccess && u.RecordingAllowed
	caps["web:recordingTransport"] = h.chrome != nil && h.recording != nil && u.RecordingAllowed
	reasons := map[string]string{}
	for _, surface := range []string{"native", "web"} {
		reason := "Configured transport; recording still requires scoped consent and runtime permission checks"
		if !u.RecordingAllowed {
			reason = "Recording disabled by operator enrollment"
		} else if surface == "native" && !u.DesktopAccess {
			reason = "Desktop recording is outside enrolled desktop scope"
		} else if !caps[surface+":recordingTransport"] {
			reason = "Recording backend or durable service is not configured"
		}
		reasons[surface+":recordingTransport"] = reason
	}
	nativeReadReady := false
	nativeWindowPositionSupported := false
	nativeWindowKeyboardSupported := false
	nativeTextReplaceSupported := false
	nativeWindowScopeSupported := false
	if h.nativeFor(p.Namespace) != nil && h.nativeClient != nil {
		// Capability discovery must establish current read readiness without
		// borrowing the gateway's possibly stale in-memory doctor result. This
		// raw read client is configured without mutation authority; doctor does
		// not inspect application content or send input.
		var requestIDBytes [16]byte
		if _, randomErr := rand.Read(requestIDBytes[:]); randomErr == nil {
			reply, doctorErr := h.nativeClient.Call(ctx, native.Request{
				ProtocolVersion:     native.ProtocolVersion,
				RequestID:           hex.EncodeToString(requestIDBytes[:]),
				Method:              "doctor",
				DeadlineRemainingMS: 3000,
				Params:              json.RawMessage(`{}`),
			})
			if doctorErr == nil && reply.Error == nil {
				var doctor struct {
					AXTrusted           bool     `json:"axTrusted"`
					NativeRootScopes    []string `json:"nativeRootScopes"`
					NativeWindowScopes  []string `json:"nativeWindowScopes"`
					NativeWindowActions []string `json:"nativeWindowActions"`
					NativeTextActions   []string `json:"nativeTextActions"`
					NativeTextReads     []string `json:"nativeTextReads"`
				}
				if json.Unmarshal(reply.Result, &doctor) == nil && doctor.AXTrusted && ctx.Err() == nil {
					nativeReadReady = true
					caps["native:boundedObservation"] = true
					caps["native:roleLocator"] = true
					caps["native:idLocator"] = true
					caps["native:nameLocator"] = true
					caps["native:attributeRead"] = true
					for _, scope := range doctor.NativeWindowScopes {
						if scope == "exactTitle" {
							nativeWindowScopeSupported = true
							caps["native:windowScope"] = true
						}
					}
					caps["native:ancestorScope"] = true
					for _, rootScope := range doctor.NativeRootScopes {
						switch rootScope {
						case "menuBar":
							caps["native:menuBarScope"] = true
						case "focusedElement":
							caps["native:focusedElementScope"] = true
						}
					}
					for _, action := range doctor.NativeTextActions {
						if action == "replaceText" {
							nativeTextReplaceSupported = true
						}
					}
					for _, read := range doctor.NativeTextReads {
						if read == "valueMatches" && p.HasScope("desktop:control") {
							caps["native:valueMatches"] = true
						}
					}
					for _, action := range doctor.NativeWindowActions {
						if action == "pressSessionKey" {
							nativeWindowKeyboardSupported = true
						}
						if action == "setPosition" {
							nativeWindowPositionSupported = true
						}
					}
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return script.Policy{}, err
		}
	}
	if h.chrome != nil {
		capabilities, err := h.chrome.CapabilitiesFor(ctx, p)
		if err != nil {
			return script.Policy{}, err
		}
		for _, cap := range capabilities {
			if cap.Supported {
				caps[cap.Surface+":"+cap.Name] = true
			}
		}
	}
	allowMutation := h.nativeControlPolicy(ctx, p, caps)
	if !nativeReadReady || !nativeWindowScopeSupported {
		delete(caps, "native:windowScope")
	}
	// semanticPress is set only after native control admission succeeds for a
	// non-launch-only helper. A ready web route cannot qualify native movement.
	if nativeReadReady && nativeWindowPositionSupported && caps["native:semanticPress"] {
		caps["native:windowPosition"] = true
	}
	if nativeReadReady && nativeWindowKeyboardSupported && caps["native:semanticPress"] && caps["native:sessionKeyboard"] {
		caps["native:windowSessionKeyboard"] = true
	}
	if nativeReadReady && nativeTextReplaceSupported && caps["native:semanticPress"] {
		caps["native:replaceText"] = true
	}
	if !nativeReadReady {
		// The control helper can independently qualify selectors and target
		// scopes even when the read gateway has no fresh AX doctor evidence.
		// Only capabilities that require the read gateway itself are withheld.
		for _, name := range []string{"boundedObservation", "attributeRead", "menuBarScope", "focusedElementScope", "valueMatches"} {
			delete(caps, "native:"+name)
		}
	}
	return script.Policy{AllowAllNative: u.DesktopAccess, AllowAllWeb: u.DesktopAccess, AllowedSurfaces: allowed, AllowMutation: allowMutation, Capabilities: caps, CapabilityReasons: reasons}, nil
}
func (h *Host) Observe(ctx context.Context, p auth.Principal, surface model.Surface) (model.Observation, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return model.Observation{}, err
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return model.Observation{}, err
	}
	defer lease.Release()
	ctx = lease.Context
	permitted := user.DesktopAccess
	switch surface.Kind {
	case "native":
		for _, bundle := range user.NativeBundles {
			if bundle == surface.BundleID {
				permitted = true
			}
		}
		if gateway := h.nativeFor(p.Namespace); permitted && gateway != nil {
			return gateway.Observe(ctx, p, surface)
		}
	case "web":
		for _, origin := range user.WebOrigins {
			if origin == surface.Origin {
				permitted = true
			}
		}
		if permitted && h.chrome != nil {
			return h.chrome.Observe(ctx, p, surface)
		}
	}
	if !permitted {
		return model.Observation{}, auth.ErrUnauthorized
	}
	return model.Observation{}, fmt.Errorf("requested backend is not connected")
}
func (h *Host) execute(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
	if step.Effect.Class != model.ReadOnly {
		if step.Target.Surface.Kind == "web" {
			if h.webControl == nil {
				return automation.StepResult{DispatchState: "notDispatched"}, ErrWebControlUnqualified
			}
			return h.webControl.Execute(ctx, p, step, values)
		}
		if step.Target.Surface.Kind != "native" {
			return automation.StepResult{DispatchState: "notDispatched"}, ErrNativeControlUnqualified
		}
		return h.executeNativeControl(ctx, p, step, values)
	}
	policy, err := h.Policy(ctx, p)
	if err != nil {
		return automation.StepResult{}, err
	}
	if err = (script.Validator{}).CheckStepPolicy(step, policy); err != nil {
		return automation.StepResult{}, err
	}
	lease, err := h.AuthorizeOperation(ctx, p, step.Target.Surface, step.Effect.Class != model.ReadOnly, consent.Control)
	if err != nil {
		return automation.StepResult{}, err
	}
	ctx = lease.Context
	switch step.Target.Surface.Kind {
	case "native":
		if gateway := h.nativeFor(p.Namespace); gateway != nil {
			result, err := gateway.Execute(ctx, p, step, values)
			if result.DispatchState == "notDispatched" {
				lease.Release()
			}
			return result, err
		}
	case "web":
		if h.chrome != nil {
			result, err := h.chrome.Execute(ctx, p, step, values)
			if result.DispatchState == "notDispatched" {
				lease.Release()
			}
			return result, err
		}
	}
	lease.Release()
	return automation.StepResult{}, errors.New("backend unavailable")
}
func (h *Host) StdioContext(ctx context.Context, resource *scy.Resource) (context.Context, error) {
	if resource == nil {
		return nil, errors.New("Scy stdio credential resource required")
	}
	secret, err := scy.New().Load(ctx, resource)
	if err != nil {
		return nil, errors.New("stdio credential unavailable")
	}
	p, err := h.Verifier.Verify(ctx, secret.String())
	if err != nil {
		return nil, err
	}
	ctx = auth.WithPrincipal(ctx, p)
	if _, err = h.authorize(ctx, p); err != nil {
		return nil, err
	}
	return ctx, nil
}
func (h *Host) Close(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	var failures []error
	frameDone := h.inhibitWindowFrames(ctx)
	// Physical inhibition cannot wait behind an Endly action or a Datly writer.
	// The manager serializes dispatch/teardown and retains any unknown fence.
	nativeDone := make(chan error, 1)
	go func() {
		if h.nativeControl != nil {
			_, err := h.nativeControl.Close(ctx)
			nativeDone <- err
		} else {
			nativeDone <- nil
		}
	}()
	recordingDone := make(chan error, 1)
	go func() {
		if h.nativeRecording != nil {
			recordingDone <- h.nativeRecording.Close(ctx)
		} else {
			recordingDone <- nil
		}
	}()
	webDone := make(chan error, 1)
	go func() {
		if h.webControl != nil {
			webDone <- h.webControl.Close(ctx)
		} else {
			webDone <- nil
		}
	}()
	if h.consentListener != nil {
		failures = append(failures, h.consentListener.Close())
	}
	var runtimeErr error
	if h.Runtime != nil {
		runtimeErr = h.Runtime.Shutdown(ctx)
		failures = append(failures, runtimeErr)
	}
	var frameErr error
	select {
	case frameErr = <-frameDone:
		failures = append(failures, frameErr)
	case <-ctx.Done():
		frameErr = ctx.Err()
		failures = append(failures, frameErr)
	}
	for _, cleanup := range []<-chan error{nativeDone, recordingDone, webDone} {
		select {
		case err := <-cleanup:
			failures = append(failures, err)
		case <-ctx.Done():
			failures = append(failures, ErrNativeControlCleanupUnknown, ctx.Err())
		}
	}
	if runtimeErr != nil || frameErr != nil || ctx.Err() != nil {
		// An action or objective worker may still write. Preserve durable storage,
		// artifacts and transports for bounded cleanup/reconciliation; never claim
		// that cancelling a context proves quiescence.
		return errors.Join(failures...)
	}
	if h.recording != nil {
		failures = append(failures, h.recording.Close(ctx))
	}
	if h.durable != nil {
		failures = append(failures, h.durable.Close(ctx))
	}
	if h.artifacts != nil {
		failures = append(failures, h.artifacts.Close())
	}
	if h.chrome != nil {
		failures = append(failures, h.chrome.Close())
	}
	closedNative := map[*native.Gateway]bool{}
	for _, gateway := range h.nativeByUser {
		if gateway != nil && !closedNative[gateway] {
			failures = append(failures, gateway.Close())
			closedNative[gateway] = true
		}
	}
	if h.native != nil && !closedNative[h.native] {
		failures = append(failures, h.native.Close())
	}
	return errors.Join(failures...)
}

func (h *Host) PauseRun(ctx context.Context, p auth.Principal, runID string, revision int) (durable.State, error) {
	if _, err := h.authorize(ctx, p); err != nil {
		return durable.State{}, err
	}
	if err := h.Runtime.QuiesceRun(ctx, p, runID); err != nil {
		return durable.State{}, err
	}
	return h.durable.TransitionRun(ctx, p, runID, revision, "paused")
}

// Native read policies belong to the verified principal, never a user union.
func (h *Host) nativeFor(namespace string) *native.Gateway {
	if h.nativeByUser != nil {
		return h.nativeByUser[namespace]
	}
	return h.native
}
