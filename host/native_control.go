package host

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

var ErrNativeControlUnqualified = errors.New("qualified native control identity, graphical session and permission evidence unavailable")
var ErrNativeControlCleanupUnknown = errors.New("native input cleanup unknown; physical fence retained")

type NativeControlHelper interface {
	native.Caller
	Identity() (session.ProcessIdentity, error)
	Stop(context.Context) (session.CleanupReport, error)
}
type NativeControlReadiness struct {
	IdentityQualified         bool
	ActiveGraphicalSession    bool
	Unlocked                  bool
	Accessibility             bool
	EventPost                 bool
	WatchdogLive              bool
	MutationQualified         bool
	LaunchQualified           bool
	SemanticQualified         bool
	TargetedKeyboardQualified bool
	SessionKeyboardQualified  bool
	WindowFrameClickQualified bool
	SecureInputEnabled        bool
	QualifiedBundles          []string
	AllApplicationsQualified  bool
	ValidUntil                time.Time
}
type NativeControlOptions struct {
	// LaunchOnly grants no AX, keyboard, pointer or activation authority.
	LaunchOnly bool
	// SemanticOnly is a development AX-only route, with no Quartz input authority.
	SemanticOnly     bool
	TargetedKeyboard bool
	SessionKeyboard  bool
	WindowFrameClick bool
	// One fixed shared login-desktop path, never derived from principal namespace.
	LockPath   string
	HelperPath string
	// Operator-enrolled launch pins, never caller/tool parameters.
	HelperRequirement string
	ExpectedUID       *uint32
	Owner             context.Context
	Enrolled          func(context.Context, auth.Principal) ([]string, error)
	EnrolledScope     func(context.Context, auth.Principal) (session.Scope, error)
	VerifyExecutable  func(context.Context, string) error
	VerifyIdentity    func(context.Context, session.ProcessIdentity) error
	Qualify           func(context.Context, auth.Principal, session.ProcessIdentity, []string) (NativeControlReadiness, error)
	QualifyHelper     func(context.Context, auth.Principal, session.ProcessIdentity, []string, NativeControlHelper) (NativeControlReadiness, error)
	// A nil helper on error guarantees no process was started. A started
	// process must be returned even on error, so it can be fenced and reaped.
	HelperFactory           func(context.Context, native.Options) (NativeControlHelper, error)
	Inspect                 session.ProcessInspector
	Stderr                  io.Writer
	AllowedValueIdentifiers map[string][]string
}
type NativeControlAdmission struct {
	Gateway *native.Gateway
	Epoch   int
}
type nativeControlHeld struct {
	principal auth.Principal
	bundles   []string
	scope     session.Scope
	helper    NativeControlHelper
	identity  session.ProcessIdentity
	gateway   *native.Gateway
	lease     session.Lease
	cancel    context.CancelFunc
	inhibited bool
}

// NativeControlManager owns lifecycle/fence admission only. Exact operation
// consent is still enforced by Host before each Gateway action; no grant is minted.
type NativeControlManager struct {
	options    NativeControlOptions
	supervisor *session.Supervisor
	mu         sync.Mutex
	held       *nativeControlHeld
	closed     bool
}

func NewNativeControlManager(options NativeControlOptions) (*NativeControlManager, error) {
	if (options.TargetedKeyboard || options.SessionKeyboard || options.WindowFrameClick) && (!options.SemanticOnly || options.LaunchOnly) {
		return nil, errors.New("native input routes require semantic composite enrollment")
	}
	if options.LaunchOnly && options.SemanticOnly {
		return nil, errors.New("native action profiles are mutually exclusive")
	}
	if !filepath.IsAbs(options.LockPath) || !filepath.IsAbs(options.HelperPath) || options.Owner == nil || options.Enrolled == nil && options.EnrolledScope == nil {
		return nil, errors.New("fixed shared absolute desktop fence, helper, owner context and verified enrollment required")
	}
	if options.HelperFactory == nil {
		if options.HelperRequirement == "" || options.ExpectedUID == nil {
			return nil, ErrNativeControlUnqualified
		}
		uid := *options.ExpectedUID
		options.ExpectedUID = &uid
		options.HelperFactory = func(ctx context.Context, opts native.Options) (NativeControlHelper, error) {
			opts.Requirement = options.HelperRequirement
			opts.ExpectedUID = options.ExpectedUID
			return native.NewClient(ctx, opts)
		}
	}
	supervisor, err := session.NewSupervisor(session.Options{LockPath: options.LockPath, HelperExecutable: options.HelperPath, Inspect: options.Inspect})
	if err != nil {
		return nil, err
	}
	copyIDs := map[string][]string{}
	for bundle, ids := range options.AllowedValueIdentifiers {
		copyIDs[bundle] = append([]string(nil), ids...)
	}
	options.AllowedValueIdentifiers = copyIDs
	manager := &NativeControlManager{options: options, supervisor: supervisor}
	if options.Owner.Done() != nil {
		go func() {
			<-options.Owner.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = manager.Close(ctx)
		}()
	}
	return manager, nil
}
func (m *NativeControlManager) actor(ctx context.Context, requested auth.Principal, scope session.Scope) (auth.Principal, session.Scope, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || actual.Namespace != requested.Namespace || !actual.HasScope("desktop:control") {
		return auth.Principal{}, session.Scope{}, auth.ErrUnauthorized
	}
	scope, err = scope.Normalize()
	if err != nil {
		return auth.Principal{}, session.Scope{}, err
	}
	var enrolled session.Scope
	if m.options.EnrolledScope != nil {
		enrolled, err = m.options.EnrolledScope(ctx, actual)
	} else {
		enrolled.AllowedBundles, err = m.options.Enrolled(ctx, actual)
	}
	if err != nil {
		return auth.Principal{}, session.Scope{}, err
	}
	enrolled, err = enrolled.Normalize()
	if err != nil {
		return auth.Principal{}, session.Scope{}, auth.ErrUnauthorized
	}
	if scope.AllApplications && !enrolled.AllApplications {
		return auth.Principal{}, session.Scope{}, auth.ErrUnauthorized
	}
	for _, bundle := range scope.AllowedBundles {
		if !enrolled.AllowsBundle(bundle) {
			return auth.Principal{}, session.Scope{}, auth.ErrUnauthorized
		}
	}
	if err = ctx.Err(); err != nil {
		return auth.Principal{}, session.Scope{}, err
	}
	return actual, scope, nil
}
func (m *NativeControlManager) Admit(ctx context.Context, requested auth.Principal, bundles []string) (NativeControlAdmission, error) {
	return m.AdmitScope(ctx, requested, session.Scope{AllowedBundles: bundles})
}

func (m *NativeControlManager) AdmitScope(ctx context.Context, requested auth.Principal, requestedScope session.Scope) (NativeControlAdmission, error) {
	actual, scope, err := m.actor(ctx, requested, requestedScope)
	if err != nil {
		return NativeControlAdmission{}, err
	}
	if m.options.VerifyExecutable == nil || m.options.VerifyIdentity == nil || m.options.Qualify == nil && m.options.QualifyHelper == nil {
		return NativeControlAdmission{}, ErrNativeControlUnqualified
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err = m.options.VerifyExecutable(bounded, m.options.HelperPath); err != nil {
		return NativeControlAdmission{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.options.Owner.Err() != nil {
		return NativeControlAdmission{}, errors.New("native control manager closed")
	}
	if m.held != nil {
		if m.held.principal.Namespace != actual.Namespace {
			return NativeControlAdmission{}, session.ErrContended
		}
		if m.held.inhibited {
			return NativeControlAdmission{}, ErrNativeControlCleanupUnknown
		}
		if !m.held.scope.Equal(scope) {
			return NativeControlAdmission{}, errors.New("held native scope differs; revoke before explicit transfer")
		}
		if err = m.qualify(bounded, actual, m.held); err != nil {
			return NativeControlAdmission{}, err
		}
		lease, err := m.supervisor.Lease(bounded, actual)
		if err != nil {
			return NativeControlAdmission{}, err
		}
		if lease.ID != m.held.lease.ID || lease.Generation != m.held.lease.Generation || !lease.Scope.Equal(m.held.scope) {
			return NativeControlAdmission{}, session.ErrNoLease
		}
		return NativeControlAdmission{Gateway: m.held.gateway, Epoch: int(lease.Generation)}, nil
	}
	lease, err := m.supervisor.Acquire(bounded, actual, scope)
	if err != nil {
		return NativeControlAdmission{}, err
	}
	fence, err := m.supervisor.FenceFile(bounded, actual)
	if err != nil {
		_, _ = m.supervisor.Close(context.Background())
		return NativeControlAdmission{}, err
	}
	// Owner cancellation inhibits admission immediately, but cannot kill the
	// helper ahead of the manager's independent cleanup/reap deadline. Keep
	// identity/context values while giving process teardown its own lifetime.
	life, lifeCancel := context.WithCancel(context.WithoutCancel(m.options.Owner))
	helper, err := m.options.HelperFactory(life, native.Options{HelperPath: m.options.HelperPath, AllowMutations: !m.options.LaunchOnly && !m.options.SemanticOnly, AllowLaunch: m.options.LaunchOnly, AllowSemantic: m.options.SemanticOnly, AllowTargetedKeyboard: m.options.TargetedKeyboard, AllowSessionKeyboard: m.options.SessionKeyboard, AllowWindowFrameClick: m.options.WindowFrameClick, Fence: fence, Stderr: m.options.Stderr})
	if err != nil && helper == nil {
		lifeCancel()
		_, cleanupErr := m.supervisor.Close(context.Background())
		return NativeControlAdmission{}, errors.Join(err, cleanupErr)
	}
	if helper == nil {
		lifeCancel()
		_, cleanupErr := m.supervisor.Close(context.Background())
		return NativeControlAdmission{}, errors.Join(errors.New("helper factory returned no helper"), cleanupErr)
	}
	held := &nativeControlHeld{principal: actual, bundles: append([]string(nil), scope.AllowedBundles...), scope: scope, helper: helper, lease: lease, cancel: lifeCancel, inhibited: true}
	m.held = held
	if err != nil {
		held.identity, _ = helper.Identity()
		return NativeControlAdmission{}, m.failedLaunchLocked(held, err)
	}
	identity, err := helper.Identity()
	if err != nil {
		return NativeControlAdmission{}, m.failedLaunchLocked(held, err)
	}
	held.identity = identity
	if err = m.options.VerifyIdentity(bounded, identity); err != nil {
		return NativeControlAdmission{}, m.failedLaunchLocked(held, err)
	}
	// Public process identity and exact executable/UID are independently checked
	// by Supervisor before its inherited record can enable native dispatch.
	profile := session.InputProfileRaw
	if m.options.SemanticOnly && !m.options.TargetedKeyboard && !m.options.SessionKeyboard && !m.options.WindowFrameClick {
		profile = session.InputProfileSemantic
	}
	if m.options.LaunchOnly {
		profile = session.InputProfileLaunch
	}
	if err = m.supervisor.AttachHelperProfile(bounded, actual, identity, profile, m.stop(held)); err != nil {
		return NativeControlAdmission{}, m.failedLaunchLocked(held, err)
	}
	if err = m.qualify(bounded, actual, held); err != nil {
		report, cleanupErr := m.closeLocked(bounded)
		if cleanupErr != nil || !report.FenceReleased {
			return NativeControlAdmission{}, errors.Join(err, cleanupErr)
		}
		return NativeControlAdmission{}, err
	}
	gateway, err := native.NewGateway(&nativeControlCaller{manager: m, held: held}, native.GatewayOptions{AllApplications: scope.AllApplications, AllowedBundles: scope.AllowedBundles, AllowedValueIdentifiers: m.options.AllowedValueIdentifiers, Lease: func(ctx context.Context, p auth.Principal) (native.Lease, error) { return m.lease(ctx, p, held) }})
	if err != nil {
		_, cleanupErr := m.closeLocked(bounded)
		return NativeControlAdmission{}, errors.Join(err, cleanupErr)
	}
	held.gateway = gateway
	held.inhibited = false
	if lease.Generation == 0 || lease.Generation > uint64(math.MaxInt) {
		_, _ = m.closeLocked(bounded)
		return NativeControlAdmission{}, session.ErrNoLease
	}
	return NativeControlAdmission{Gateway: gateway, Epoch: int(lease.Generation)}, nil
}
func (m *NativeControlManager) qualify(ctx context.Context, p auth.Principal, held *nativeControlHeld) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.options.VerifyIdentity(ctx, held.identity); err != nil {
		return err
	}
	var ready NativeControlReadiness
	var err error
	if m.options.QualifyHelper != nil {
		ready, err = m.options.QualifyHelper(ctx, p, held.identity, append([]string(nil), held.bundles...), held.helper)
	} else {
		ready, err = m.options.Qualify(ctx, p, held.identity, append([]string(nil), held.bundles...))
	}
	if err != nil {
		return err
	}
	now := time.Now()
	if !ready.IdentityQualified || !ready.ActiveGraphicalSession || !ready.WatchdogLive || ready.ValidUntil.Before(now) || ready.ValidUntil.After(now.Add(5*time.Second)) {
		return ErrNativeControlUnqualified
	}
	if m.options.LaunchOnly {
		if !ready.LaunchQualified {
			return ErrNativeControlUnqualified
		}
	} else if m.options.SemanticOnly {
		if !ready.SemanticQualified || !ready.Accessibility || ready.SecureInputEnabled || (m.options.TargetedKeyboard && (!ready.TargetedKeyboardQualified || !ready.EventPost) || m.options.SessionKeyboard && (!ready.SessionKeyboardQualified || !ready.EventPost) || m.options.WindowFrameClick && (!ready.WindowFrameClickQualified || !ready.EventPost)) {
			return ErrNativeControlUnqualified
		}
	} else if !ready.Unlocked || !ready.Accessibility || !ready.EventPost || !ready.MutationQualified {
		return ErrNativeControlUnqualified
	}
	if held.scope.AllApplications {
		if !ready.AllApplicationsQualified || len(ready.QualifiedBundles) != 0 {
			return ErrNativeControlUnqualified
		}
	} else {
		scopes := append([]string(nil), ready.QualifiedBundles...)
		sort.Strings(scopes)
		if !reflect.DeepEqual(scopes, held.bundles) {
			return ErrNativeControlUnqualified
		}
	}
	return ctx.Err()
}
func (m *NativeControlManager) stop(held *nativeControlHeld) func(context.Context) (session.CleanupReport, error) {
	return func(ctx context.Context) (session.CleanupReport, error) {
		report, err := held.helper.Stop(ctx)
		err = errors.Join(err, ctx.Err())
		if err != nil || !report.InputInhibited || !report.HelperStopped || report.UnknownInputs {
			report.UnknownInputs = true
			return report, errors.Join(err, ErrNativeControlCleanupUnknown)
		}
		return report, nil
	}
}
func (m *NativeControlManager) failedLaunchLocked(held *nativeControlHeld, cause error) error {
	// Unattached helper still retains its inherited fence. Do not unlock merely
	// because enrollment failed: first stop/reap and independently inspect identity.
	bounded, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	report, err := held.helper.Stop(bounded)
	err = errors.Join(err, bounded.Err())
	retain := func(problem error) error {
		report.UnknownInputs = true
		report.FenceReleased = false
		return errors.Join(cause, problem, ErrNativeControlCleanupUnknown, m.supervisor.RetainUnknown(auth.WithPrincipal(context.Background(), held.principal), held.principal, report))
	}
	if err != nil || report.UnknownInputs || !report.InputInhibited || !report.HelperStopped {
		return retain(err)
	}
	inspect := m.options.Inspect
	if inspect == nil {
		inspect = session.InspectProcess
	}
	if held.identity.PID <= 0 {
		return retain(nil)
	}
	actual, alive, err := inspect(held.identity.PID)
	if err != nil || alive && actual.StartToken == held.identity.StartToken {
		return retain(err)
	}
	held.cancel()
	m.held = nil
	_, err = m.supervisor.Close(bounded)
	return errors.Join(cause, err)
}
func (m *NativeControlManager) lease(ctx context.Context, p auth.Principal, held *nativeControlHeld) (native.Lease, error) {
	actual, _, err := m.actor(ctx, p, held.scope)
	if err != nil {
		return native.Lease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.options.Owner.Err() != nil || m.held != held || held.inhibited || actual.Namespace != held.principal.Namespace {
		return native.Lease{}, session.ErrNoLease
	}
	if err = m.qualify(ctx, actual, held); err != nil {
		return native.Lease{}, err
	}
	lease, err := m.supervisor.Lease(ctx, actual)
	if err != nil {
		return native.Lease{}, err
	}
	if lease.ID != held.lease.ID || lease.Generation != held.lease.Generation || lease.Owner != actual.Namespace || !lease.Scope.Equal(held.scope) {
		return native.Lease{}, session.ErrNoLease
	}
	return native.Lease{ID: lease.ID, Generation: lease.Generation}, nil
}

// ReconcileNoRawInput releases only a stopped historical non-raw helper's
// physical barrier. It does not clear durable action or consent uncertainty.
func (m *NativeControlManager) ReconcileNoRawInput(ctx context.Context, requested auth.Principal, generation uint64) (session.CleanupReport, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || actual.Namespace != requested.Namespace || !actual.HasScope("desktop:control") {
		return session.CleanupReport{}, auth.ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.options.Owner.Err() != nil || m.held != nil {
		return session.CleanupReport{}, session.ErrContended
	}
	return m.supervisor.ReconcileNoRawInput(ctx, actual, generation)
}

func (m *NativeControlManager) Revoke(ctx context.Context, requested auth.Principal) (session.CleanupReport, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || actual.Namespace != requested.Namespace || !actual.HasScope("desktop:control") {
		return session.CleanupReport{}, auth.ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held != nil && m.held.principal.Namespace != actual.Namespace {
		return session.CleanupReport{}, auth.ErrUnauthorized
	}
	return m.closeLocked(ctx)
}
func (m *NativeControlManager) Close(ctx context.Context) (session.CleanupReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeLocked(ctx)
}
func (m *NativeControlManager) closeLocked(ctx context.Context) (session.CleanupReport, error) {
	if m.held != nil {
		m.held.inhibited = true
	}
	report, err := m.supervisor.Close(ctx)
	if err != nil || report.UnknownInputs || !report.FenceReleased {
		return report, errors.Join(err, ErrNativeControlCleanupUnknown)
	}
	if m.held != nil {
		m.held.cancel()
		m.held = nil
	}
	return report, nil
}

type nativeControlCaller struct {
	manager *NativeControlManager
	held    *nativeControlHeld
}

func (c *nativeControlCaller) Call(ctx context.Context, request native.Request) (native.Reply, error) {
	actual, _, err := c.manager.actor(ctx, c.held.principal, c.held.scope)
	if err != nil {
		return native.Reply{}, err
	}
	m := c.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.options.Owner.Err() != nil || m.held != c.held || c.held.inhibited || actual.Namespace != c.held.principal.Namespace {
		return native.Reply{}, session.ErrNoLease
	}
	if err = m.qualify(ctx, actual, c.held); err != nil {
		return native.Reply{}, err
	}
	lease, err := m.supervisor.Lease(ctx, actual)
	if err != nil {
		return native.Reply{}, err
	}
	if lease.ID != c.held.lease.ID || lease.Generation != c.held.lease.Generation || lease.Owner != actual.Namespace || !lease.Scope.Equal(c.held.scope) {
		return native.Reply{}, session.ErrNoLease
	}
	expected := native.Lease{ID: lease.ID, Generation: lease.Generation}
	if m.options.LaunchOnly && request.Method != "doctor" && request.Method != "apps.list" && request.Method != "app.launch" && request.Method != "lease.install" {
		return native.Reply{}, auth.ErrUnauthorized
	}
	switch request.Method {
	case "doctor", "apps.list":
	case "windows.captureFrame", "windows.clickFrame", "windows.list", "windows.setPosition", "windows.pressSessionKey", "elements.snapshot", "elements.read", "elements.valueMatches", "elements.replaceText", "elements.focus", "elements.pressKey", "elements.pressSessionKey", "elements.press", "elements.setValue", "elements.submit", "app.launch", "app.activate":
		var scope struct {
			BundleID    string `json:"bundleID"`
			ExpectedApp string `json:"expectedApp"`
		}
		if json.Unmarshal(request.Params, &scope) != nil {
			return native.Reply{}, auth.ErrUnauthorized
		}
		bundle := scope.ExpectedApp
		if request.Method == "elements.snapshot" || request.Method == "windows.list" {
			bundle = scope.BundleID
		}
		allowed := c.held.scope.AllowsBundle(bundle)
		if !allowed {
			return native.Reply{}, auth.ErrUnauthorized
		}
		if (request.Method == "elements.pressSessionKey" || request.Method == "windows.pressSessionKey") && !m.options.SessionKeyboard {
			return native.Reply{}, auth.ErrUnauthorized
		}
		if request.Method == "elements.pressKey" && !m.options.TargetedKeyboard {
			return native.Reply{}, auth.ErrUnauthorized
		}
		if request.Method == "windows.captureFrame" || request.Method == "windows.clickFrame" {
			var params struct {
				Owner native.WindowFrameOwner `json:"owner"`
			}
			binding, ok := auth.ConsentBindingFromContext(ctx)
			if !m.options.WindowFrameClick || !ok || json.Unmarshal(request.Params, &params) != nil || params.Owner.Validate() != nil || params.Owner.Namespace != actual.Namespace || params.Owner.ClientID != actual.ClientID || params.Owner.SessionID != binding.SessionID {
				return native.Reply{}, auth.ErrUnauthorized
			}
		}
		if request.Method == "windows.captureFrame" || request.Method == "windows.clickFrame" || request.Method == "windows.pressSessionKey" || request.Method == "elements.replaceText" || request.Method == "windows.setPosition" || request.Method == "elements.focus" || request.Method == "elements.pressSessionKey" || request.Method == "elements.pressKey" || request.Method == "elements.press" || request.Method == "elements.setValue" || request.Method == "elements.submit" || request.Method == "app.launch" || request.Method == "app.activate" {
			if request.Lease == nil || *request.Lease != expected {
				return native.Reply{}, session.ErrNoLease
			}
		}
	case "lease.install":
		var supplied native.Lease
		if json.Unmarshal(request.Params, &supplied) != nil || supplied != expected {
			return native.Reply{}, session.ErrNoLease
		}
	default:
		return native.Reply{}, auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return native.Reply{}, err
	}
	// Serialize dispatch with revocation so an admitted request cannot race teardown.
	reply, callErr := c.held.helper.Call(ctx, request)
	var transport *native.TransportError
	var applicationFailure *native.NativeError
	unknownReplacement := (request.Method == "elements.replaceText" || request.Method == "windows.clickFrame") && errors.As(callErr, &applicationFailure) && applicationFailure.DispatchState == "unknown"
	if unknownReplacement || ctx.Err() != nil || errors.As(callErr, &transport) && transport.DispatchState == "unknown" || reply.Receipt != nil && reply.Receipt.DispatchState == "unknown" {
		c.held.inhibited = true
		report := session.CleanupReport{InputInhibited: true, UnknownInputs: true, Reason: "native dispatch interrupted; held inputs require reconciliation"}
		barrierErr := m.supervisor.RetainUnknown(auth.WithPrincipal(context.Background(), actual), actual, report)
		return reply, errors.Join(callErr, ctx.Err(), barrierErr)
	}
	return reply, callErr
}

// Closing a borrowed Gateway is a scoped revocation, never raw helper teardown.
func (c *nativeControlCaller) Close() error {
	ctx := auth.WithPrincipal(context.Background(), c.held.principal)
	_, err := c.manager.Revoke(ctx, c.held.principal)
	return err
}
