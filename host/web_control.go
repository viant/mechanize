package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

var ErrWebControlUnqualified = errors.New("signed Chrome native-host, browser parent and renderer authority are unqualified")
var ErrWebControlIntent = errors.New("same durable web intent and renderer authority required")
var ErrWebControlCleanupUnknown = errors.New("web executor retirement unconfirmed; renderer authority inhibited")

type WebControlProfile struct {
	AllWebsites     bool
	ObservedOrigins []string // Capability candidates only, never enrollment authority.
	TrustScope      string
	ProfileChannel  string
	BrowserInstance string
	ExtensionOrigin string
	Origins         []string
}
type WebControlScope struct{ Profiles []WebControlProfile }

// Authority is provider evidence from an audited channel, never native-host hello
// fields or tool parameters. Renderer generation is independent of desktop input.
type WebControlAuthority struct {
	TrustScope      string
	Owner           string
	ExtensionOrigin string
	Document        chrome.Document
	NativeHost      session.ProcessIdentity
	BrowserParent   session.ProcessIdentity
	BrokerEpoch     string
	ChannelEpoch    string
	ScopeHash       string
	ID              string
	Generation      uint64
}
type WebControlReadiness struct {
	// Server-owned admission provenance; never supplied by a tool or renderer.
	NewlyAcquired                bool
	IndexedQueryQualified        bool
	ScopeQualified               bool
	postconditionRead            *webPostconditionRead
	Authority                    WebControlAuthority
	NativeHostSignatureQualified bool
	KernelPeerQualified          bool
	ChromeParentQualified        bool
	ProfileQualified             bool
	ExtensionQualified           bool
	DocumentQualified            bool
	ExecutorQualified            bool
	UnresolvedExecutors          bool
	Actions                      []string
	Locators                     []string
	ValidUntil                   time.Time
}
type WebControlCleanup struct {
	AuthorityRetired         bool
	ExecutorsQuiesced        bool // Full document shutdown; remains distinct from retiring one authority.
	RetiredAuthorityQuiesced bool // Exact lease revoked at broker and renderer with no pending/unknown action.
	UnknownExecutors         bool
}
type WebControlOptions struct {
	// Production discovery uses signed metadata without acquiring renderer input authority.
	CapabilityProbe func(context.Context, auth.Principal) (map[string]bool, error)
	authorizeRead   func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error)
	Owner           context.Context
	Enrolled        func(context.Context, auth.Principal) (WebControlScope, error)
	// Qualify admits exactly one root document. Only NewlyAcquired transfers a
	// fresh lease to this manager; reused pins remain owned by their preparer.
	// On error, the provider retains or retires its unpublished acquisition.
	// VerifyChannel rechecks the existing pin without another admission.
	Qualify       func(context.Context, auth.Principal, model.Surface) (WebControlReadiness, error)
	VerifyChannel func(context.Context, auth.Principal, WebControlAuthority) error
	Authorize     func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error)
	// ExecutePinned must atomically revalidate this SAME authority immediately
	// before transport write. It must not reselect a tab or substitute a generation.
	// The provider must carry the stable durable Endly attempt, never generic retry.
	ExecutePinned        func(context.Context, auth.Principal, model.Step, map[string]model.Value, WebControlAuthority) (automation.StepResult, error)
	Retire               func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error)
	RecordCleanupUnknown func(context.Context, auth.Principal, WebControlAuthority) error
	Close                func(context.Context) error
}
type WebControlManager struct {
	options        WebControlOptions
	mu             sync.Mutex
	closed         bool
	inhibited      map[string]bool
	prepared       map[*webControlIntent]struct{}
	active         sync.WaitGroup
	drained        chan struct{}
	closeLane      chan struct{}
	providerClosed bool
}
type webControlIntent struct {
	ownerContext      context.Context
	stopCancellation  func() bool
	postconditionRead *webPostconditionRead
	readReady         bool
	manager           *WebControlManager
	principal         auth.Principal
	binding           auth.ConsentBinding
	metadata          automation.ExecutionMetadata
	stepHash          string
	authority         WebControlAuthority
	dispatched        bool
	executing         bool
	consumed          bool
}
type webControlIntentKey struct{}

func NewWebControlManager(options WebControlOptions) (*WebControlManager, error) {
	if options.Owner == nil || options.Enrolled == nil || options.Qualify == nil || options.VerifyChannel == nil || options.Authorize == nil || options.ExecutePinned == nil || options.Retire == nil || options.RecordCleanupUnknown == nil || options.Close == nil {
		return nil, ErrWebControlUnqualified
	}
	return &WebControlManager{options: options, inhibited: map[string]bool{}, prepared: map[*webControlIntent]struct{}{}, closeLane: make(chan struct{}, 1)}, nil
}
func webControlActor(ctx context.Context, p auth.Principal) (auth.Principal, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:control") {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return actual, ctx.Err()
}
func webStepHash(step model.Step) (string, error) {
	bytes, err := json.Marshal(step)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
func webMutationStep(step model.Step) error {
	if err := step.Validate(); err != nil {
		return err
	}
	if step.Target.Surface.Kind != "web" || step.Effect.Class == model.ReadOnly || (step.Action != "element.press" && step.Action != "element.fill" && step.Action != "browser.navigate" && step.Action != "browser.activate") {
		return ErrWebControlUnqualified
	}
	if step.Target.Surface.Origin == "" || step.Target.Surface.BundleID != "" || len(step.Target.Scope.Frame) > 0 || len(step.Target.Scope.Window) > 0 || step.Target.Ancestor != nil {
		return ErrWebControlUnqualified
	}
	if step.Action == "browser.navigate" || step.Action == "browser.activate" {
		return nil
	}
	if step.Target.Locator == nil || !step.Target.Locator.Exact || step.Target.Cardinality != "one" && step.Target.Cardinality != "nth" {
		return fmt.Errorf("%w: mutation.exactUniqueLocatorRequired", ErrWebControlUnqualified)
	}
	if step.Target.Cardinality == "nth" && (step.Target.Index == nil || *step.Target.Index < 0 || *step.Target.Index > 999 || step.Target.Order != "document") {
		return ErrWebControlUnqualified
	}
	switch step.Target.Locator.Strategy {
	case "role", "id", "testId", "label":
	default:
		return ErrWebControlUnqualified
	}
	return nil
}
func webOrigin(origin string) bool {
	return chrome.OrdinaryWebsiteOrigin(origin)
}
func webChannelKey(a WebControlAuthority) string {
	return a.Owner + "\x00" + a.Document.ProfileChannel + "\x00" + a.Document.BrowserInstance
}

func webScopeQualified(ready WebControlReadiness) bool {
	scope, err := chrome.NormalizeTrustScope(ready.Authority.TrustScope)
	if err != nil {
		return false
	}
	if scope == chrome.TrustScopeDesktop {
		// Desktop-wide authority must never be presented as profile isolation.
		return ready.ScopeQualified && !ready.ProfileQualified
	}
	return ready.ProfileQualified
}
func (m *WebControlManager) qualify(ctx context.Context, p auth.Principal, surface model.Surface) (returned WebControlReadiness, returnErr error) {
	if m == nil {
		return WebControlReadiness{}, ErrWebControlUnqualified
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed || m.options.Owner.Err() != nil {
		return WebControlReadiness{}, ErrWebControlUnqualified
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	scope, err := m.options.Enrolled(bounded, p)
	if err != nil {
		return WebControlReadiness{}, err
	}
	if len(scope.Profiles) == 0 || len(scope.Profiles) > 64 || surface.Kind != "web" || !webOrigin(surface.Origin) || surface.BundleID != "" {
		return WebControlReadiness{}, auth.ErrUnauthorized
	}
	ready, err := m.options.Qualify(bounded, p, surface)
	if err != nil {
		return WebControlReadiness{}, err
	}
	defer func() {
		if returnErr != nil && ready.NewlyAcquired {
			returnErr = m.retireOwnedAuthority(ctx, p, ready.Authority, returnErr)
		}
	}()
	a, d := ready.Authority, ready.Authority.Document
	now := time.Now()
	checks := []struct {
		failed bool
		code   string
	}{
		{!ready.NativeHostSignatureQualified, "nativeHostSignature"},
		{!ready.KernelPeerQualified, "kernelPeer"},
		{!ready.ChromeParentQualified, "browserParent"},
		{!webScopeQualified(ready), "scope"},
		{!ready.ExtensionQualified, "extension"},
		{!ready.DocumentQualified, "document"},
		{!ready.ExecutorQualified, "executor"},
		{ready.UnresolvedExecutors, "unresolvedExecutors"},
		{!ready.ValidUntil.After(now) || ready.ValidUntil.After(now.Add(5*time.Second)), "readinessLifetime"},
		{a.Owner != p.Namespace || a.ID == "" || a.Generation == 0 || a.Generation > uint64(math.MaxInt) || a.BrokerEpoch == "" || a.ChannelEpoch == "" || a.ScopeHash == "", "authority"},
		{d.FrameID != 0 || d.TabID <= 0 || d.DocumentID == "" || d.Generation == 0 || d.Origin != surface.Origin, "documentIdentity"},
		{a.NativeHost.PID <= 0 || a.NativeHost.StartToken == "" || !filepath.IsAbs(a.NativeHost.Executable) || a.NativeHost.UID != uint32(os.Getuid()), "nativeHostIdentity"},
		{a.BrowserParent.PID <= 0 || a.BrowserParent.StartToken == "" || !filepath.IsAbs(a.BrowserParent.Executable) || a.BrowserParent.UID != uint32(os.Getuid()), "browserParentIdentity"},
	}
	for _, check := range checks {
		if check.failed {
			return WebControlReadiness{}, fmt.Errorf("%w: readiness.%s", ErrWebControlUnqualified, check.code)
		}
	}
	if surface.Title != "" && (d.TitleTruncated || d.Title != surface.Title) || surface.TabID != "" && surface.TabID != d.QualifiedTabID() && surface.TabID != strconv.Itoa(d.TabID) {
		return WebControlReadiness{}, auth.ErrUnauthorized
	}
	enrolled := false
	for _, profile := range scope.Profiles {
		enrolledScope, scopeErr := chrome.NormalizeTrustScope(profile.TrustScope)
		actualScope, actualErr := chrome.NormalizeTrustScope(a.TrustScope)
		if scopeErr != nil || actualErr != nil || enrolledScope != actualScope {
			continue
		}
		if profile.ProfileChannel == d.ProfileChannel && profile.BrowserInstance == d.BrowserInstance && profile.ExtensionOrigin == a.ExtensionOrigin && regexp.MustCompile(`^chrome-extension://[a-p]{32}/$`).MatchString(profile.ExtensionOrigin) {
			if profile.AllWebsites && len(profile.Origins) == 0 && webOrigin(d.Origin) {
				enrolled = true
			}
			for _, origin := range profile.Origins {
				if profile.AllWebsites {
					continue
				}
				if webOrigin(origin) && origin == d.Origin {
					enrolled = true
				}
			}
		}
	}
	if !enrolled {
		return WebControlReadiness{}, auth.ErrUnauthorized
	}
	m.mu.Lock()
	inhibited := m.inhibited[webChannelKey(a)]
	m.mu.Unlock()
	if inhibited {
		return WebControlReadiness{}, ErrWebControlCleanupUnknown
	}
	if err = m.options.VerifyChannel(bounded, p, a); err != nil {
		return WebControlReadiness{}, err
	}
	if err = bounded.Err(); err != nil {
		return WebControlReadiness{}, err
	}
	ready.Actions = append([]string(nil), ready.Actions...)
	ready.Locators = append([]string(nil), ready.Locators...)
	return ready, nil
}
func supportsWebLocator(ready WebControlReadiness, strategy string) bool {
	for _, allowed := range ready.Locators {
		if allowed == strategy {
			return true
		}
	}
	return false
}
func supportsWebStepLocator(ready WebControlReadiness, step model.Step) bool {
	if step.Action == "browser.navigate" || step.Action == "browser.activate" {
		return step.Target.Locator == nil
	}
	if step.Target.Cardinality == "nth" && !ready.IndexedQueryQualified {
		return false
	}
	return step.Target.Locator != nil && supportsWebLocator(ready, step.Target.Locator.Strategy)
}
func supportsWebAction(ready WebControlReadiness, action string) bool {
	for _, allowed := range ready.Actions {
		if allowed == action {
			return true
		}
	}
	return false
}

// Prepare is a PRE-INTENT admission hook. durable.Builder must preserve returned
// context, commit BeginAttempt, then invoke Execute with that data invocation scope.
// A physical desktop lease is never acquired or borrowed for renderer authority.
func (m *WebControlManager) Prepare(ctx context.Context, p auth.Principal, step model.Step) (returned context.Context, epoch int, returnErr error) {
	if !m.beginWork() {
		return ctx, 0, ErrWebControlUnqualified
	}
	defer m.active.Done()
	actual, err := webControlActor(ctx, p)
	if err != nil {
		return ctx, 0, err
	}
	if err = webMutationStep(step); err != nil {
		return ctx, 0, err
	}
	meta, ok := automation.ExecutionFromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || meta.RunID == "" || meta.PlanID == "" || meta.Resumed && meta.OperationID == "" || meta.SessionID == "" || meta.StepIndex < 0 || !bound || binding.GrantID == "" || binding.Purpose == "" {
		return ctx, 0, ErrWebControlIntent
	}
	ready, err := m.qualify(ctx, actual, step.Target.Surface)
	if err != nil {
		return ctx, 0, err
	}
	if !ready.NewlyAcquired {
		return ctx, 0, ErrWebControlIntent
	}
	defer func() {
		if returnErr != nil {
			returnErr = m.retireOwnedAuthority(ctx, actual, ready.Authority, returnErr)
		}
	}()
	if !supportsWebAction(ready, step.Action) || !supportsWebStepLocator(ready, step) {
		return ctx, 0, ErrWebControlUnqualified
	}
	hash, err := webStepHash(step)
	if err != nil {
		return ctx, 0, err
	}
	if ready.postconditionRead != nil {
		if err := ready.postconditionRead.validate(actual, ready.Authority); err != nil {
			return ctx, 0, err
		}
	} else if step.Postcondition != nil && step.Postcondition.Adapter == "web" {
		return ctx, 0, ErrWebControlUnqualified
	}
	intent := &webControlIntent{ownerContext: context.WithoutCancel(ctx), manager: m, principal: actual, binding: binding, metadata: meta, stepHash: hash, authority: ready.Authority, postconditionRead: ready.postconditionRead}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ctx, 0, ErrWebControlUnqualified
	}
	m.prepared[intent] = struct{}{}
	intent.stopCancellation = context.AfterFunc(ctx, func() { m.cancelPrepared(intent) })
	m.mu.Unlock()
	return context.WithValue(ctx, webControlIntentKey{}, intent), int(ready.Authority.Generation), nil
}

// Execute is called ONLY by the durable dispatcher after intent commit. The
// private permit cannot be lent across manager, owner/client, run/step or grant.
func (m *WebControlManager) Execute(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (result automation.StepResult, returnErr error) {
	result = automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if !m.beginWork() {
		return result, ErrWebControlIntent
	}
	defer m.active.Done()
	actual, err := webControlActor(ctx, p)
	if err != nil {
		return result, err
	}
	if err = webMutationStep(step); err != nil {
		return result, err
	}
	intent, ok := ctx.Value(webControlIntentKey{}).(*webControlIntent)
	scope, scopeErr := data.RequireScope(ctx, p.Namespace)
	meta, metadataOK := automation.ExecutionFromContext(ctx)
	binding, bindingOK := auth.ConsentBindingFromContext(ctx)
	hash, hashErr := webStepHash(step)
	if m == nil || !ok || intent == nil || intent.manager != m || scopeErr != nil || hashErr != nil || scope.LeaseEpoch != int(intent.authority.Generation) || intent.principal.Namespace != actual.Namespace || intent.principal.ClientID != actual.ClientID || !metadataOK || !bindingOK || !reflect.DeepEqual(meta, intent.metadata) || binding != intent.binding || hash != intent.stepHash {
		return result, ErrWebControlIntent
	}
	m.mu.Lock()
	unavailable := m.closed || intent.dispatched || intent.consumed || intent.executing || m.inhibited[webChannelKey(intent.authority)]
	if !unavailable {
		intent.executing = true
	}
	m.mu.Unlock()
	if unavailable {
		return result, ErrWebControlIntent
	}
	// Only the invocation that claimed this validated intent owns abandonment.
	// Every return before ExecutePinned retires the Prepare-installed lease.
	defer func() {
		m.mu.Lock()
		dispatched := intent.dispatched
		m.mu.Unlock()
		if !dispatched {
			returnErr = m.abandonIntent(ctx, actual, intent, returnErr)
		}
		m.mu.Lock()
		intent.executing = false
		m.mu.Unlock()
	}()
	// Revalidate the existing pin; admission here could acquire or borrow a
	// second lease. The immutable intent already fixed action/locator support.
	if err = m.options.VerifyChannel(ctx, actual, intent.authority); err != nil {
		return result, err
	}
	lease, err := m.options.Authorize(ctx, actual, step.Target.Surface)
	if err != nil {
		if lease != nil && lease.Release != nil {
			lease.Release()
		}
		return result, err
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
		if lease != nil && lease.Release != nil {
			lease.Release()
		}
		return result, auth.ErrUnauthorized
	}
	leaseScope, leaseScopeErr := data.RequireScope(lease.Context, actual.Namespace)
	leaseMeta, leaseMetaOK := automation.ExecutionFromContext(lease.Context)
	actualLease, err := webControlActor(lease.Context, actual)
	leaseBinding, hasBinding := auth.ConsentBindingFromContext(lease.Context)
	if err != nil || actualLease.ClientID != actual.ClientID || !hasBinding || leaseBinding != binding || leaseScopeErr != nil || leaseScope.LeaseEpoch != scope.LeaseEpoch || !leaseMetaOK || leaseMeta != meta {
		lease.Release()
		return result, auth.ErrUnauthorized
	}
	// The same durable grant must independently authorize destination access.
	// An origin-only source grant cannot authorize cross-origin navigation.
	var destinationLease *consent.Lease
	if step.Action == "browser.navigate" {
		args, e := step.ResolveArguments(values)
		if e != nil {
			lease.Release()
			return result, e
		}
		origin, e := model.NavigationOrigin(args["url"].String)
		if e != nil {
			lease.Release()
			return result, e
		}
		if origin != step.Target.Surface.Origin {
			destinationLease, e = m.options.Authorize(lease.Context, actual, model.Surface{Kind: "web", Origin: origin})
			if destinationLease != nil && destinationLease.Release != nil {
				defer destinationLease.Release()
			}
			if e != nil || destinationLease == nil || destinationLease.Context == nil || destinationLease.Release == nil {
				lease.Release()
				return result, auth.ErrUnauthorized
			}
			destinationBinding, destinationBound := auth.ConsentBindingFromContext(destinationLease.Context)
			destinationScope, destinationScopeErr := data.RequireScope(destinationLease.Context, actual.Namespace)
			destinationMeta, destinationMetaOK := automation.ExecutionFromContext(destinationLease.Context)
			destinationActor, destinationActorErr := webControlActor(destinationLease.Context, actual)
			if !destinationBound || destinationBinding != binding || destinationScopeErr != nil || destinationScope.LeaseEpoch != scope.LeaseEpoch || !destinationMetaOK || destinationMeta != meta || destinationActorErr != nil || destinationActor.ClientID != actual.ClientID {
				lease.Release()
				return result, auth.ErrUnauthorized
			}
		}
	}
	// Recheck after per-step consent admission. Provider additionally checks at the
	// wire boundary, including cancellation/revocation while waiting in its lane.
	if err = m.options.VerifyChannel(lease.Context, actual, intent.authority); err != nil {
		lease.Release()
		return result, err
	}
	m.mu.Lock()
	if m.closed || m.options.Owner.Err() != nil || intent.dispatched || m.inhibited[webChannelKey(intent.authority)] {
		m.mu.Unlock()
		lease.Release()
		return result, ErrWebControlIntent
	}
	m.mu.Unlock()
	dispatchCtx, cancel := context.WithCancel(lease.Context)
	stopOwner := context.AfterFunc(m.options.Owner, cancel)
	if destinationLease != nil {
		stopDestination := context.AfterFunc(destinationLease.Context, cancel)
		defer stopDestination()
		if destinationLease.Context.Err() != nil {
			cancel()
		}
	}
	defer func() { stopOwner(); cancel() }()
	if err = dispatchCtx.Err(); err != nil {
		lease.Release()
		return result, err
	}
	m.mu.Lock()
	if m.closed || m.options.Owner.Err() != nil || intent.consumed || intent.dispatched || m.inhibited[webChannelKey(intent.authority)] {
		m.mu.Unlock()
		lease.Release()
		return result, ErrWebControlIntent
	}
	intent.dispatched = true
	m.mu.Unlock()
	result, dispatchErr := m.options.ExecutePinned(dispatchCtx, actual, step, values, intent.authority)
	// Renderer receipts do not establish a business postcondition.
	result.VerificationState = "unknown"
	result.Postcondition = nil
	// Preserve a validated transport receipt across a later cancellation. A
	// dispatched receipt proves input delivery, never the requested UI/business
	// result. Lost/error-bearing outcomes still retain uncertainty.
	var dispatchDetail *model.MechanizeError
	confirmedAbsent := result.DispatchState == "notDispatched" && errors.As(dispatchErr, &dispatchDetail) && dispatchDetail.DispatchState == "notDispatched"
	confirmedDispatched := result.DispatchState == "dispatched" && dispatchErr == nil
	if result.DispatchState == "" || dispatchCtx.Err() != nil && !confirmedAbsent && !confirmedDispatched {
		result.DispatchState = "unknown"
	}
	if dispatchErr != nil && result.DispatchState == "notDispatched" {
		var detail *model.MechanizeError
		if !errors.As(dispatchErr, &detail) || detail.DispatchState != "notDispatched" {
			result.DispatchState = "unknown"
		}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	cleanup, cleanupErr := m.retire(cleanupCtx, actual, intent.authority)
	cleanupErr = errors.Join(cleanupErr, cleanupCtx.Err())
	cleanupCancel()
	if cleanupErr == nil && cleanup.AuthorityRetired && (cleanup.ExecutorsQuiesced || cleanup.RetiredAuthorityQuiesced) && !cleanup.UnknownExecutors {
		m.mu.Lock()
		intent.readReady = dispatchErr == nil && result.DispatchState == "dispatched"
		if intent.stopCancellation != nil {
			intent.stopCancellation()
		}
		delete(m.prepared, intent)
		m.mu.Unlock()
		lease.Release()
		return result, dispatchErr
	}
	m.mu.Lock()
	m.inhibited[webChannelKey(intent.authority)] = true
	m.mu.Unlock()
	// Persist uncertainty through the injected generated-use-case callback. The
	// admitted consent lease stays registered until real executor reconciliation.
	recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	recordErr := m.options.RecordCleanupUnknown(recordCtx, actual, intent.authority)
	recordErr = errors.Join(recordErr, recordCtx.Err())
	recordCancel()
	return result, errors.Join(dispatchErr, cleanupErr, recordErr, ErrWebControlCleanupUnknown)
}

// abandonIntent does not infer quiescence from an error or deadline. The exact
// original renderer lease must acknowledge retirement through its normal path.
func (m *WebControlManager) abandonIntent(ctx context.Context, p auth.Principal, intent *webControlIntent, cause error) error {
	m.mu.Lock()
	if intent.dispatched || intent.consumed {
		m.mu.Unlock()
		return cause
	}
	intent.consumed = true
	m.mu.Unlock()
	err := m.retireOwnedAuthority(ctx, p, intent.authority, cause)
	if !errors.Is(err, ErrWebControlCleanupUnknown) {
		m.mu.Lock()
		if intent.stopCancellation != nil {
			intent.stopCancellation()
		}
		delete(m.prepared, intent)
		m.mu.Unlock()
	}
	return err
}
func (m *WebControlManager) retireOwnedAuthority(ctx context.Context, p auth.Principal, authority WebControlAuthority, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	cleanup, cleanupErr := m.retire(cleanupCtx, p, authority)
	cleanupErr = errors.Join(cleanupErr, cleanupCtx.Err())
	cancel()
	if cleanupErr == nil && cleanup.AuthorityRetired && (cleanup.ExecutorsQuiesced || cleanup.RetiredAuthorityQuiesced) && !cleanup.UnknownExecutors {
		return cause
	}
	m.mu.Lock()
	m.inhibited[webChannelKey(authority)] = true
	m.mu.Unlock()
	recordCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer stop()
	recordErr := m.options.RecordCleanupUnknown(recordCtx, p, authority)
	return errors.Join(cause, cleanupErr, recordErr, recordCtx.Err(), ErrWebControlCleanupUnknown)
}
func (m *WebControlManager) cancelPrepared(intent *webControlIntent) {
	m.mu.Lock()
	if m.closed || intent.executing || intent.dispatched || intent.consumed {
		m.mu.Unlock()
		return
	}
	intent.executing = true
	m.active.Add(1)
	m.mu.Unlock()
	defer m.active.Done()
	_ = m.abandonIntent(intent.ownerContext, intent.principal, intent, context.Canceled)
	m.mu.Lock()
	intent.executing = false
	m.mu.Unlock()
}

func (m *WebControlManager) beginWork() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.active.Add(1)
	return true
}

// A broken provider cannot turn a bounded retirement timeout into cleanup proof.
func (m *WebControlManager) retire(ctx context.Context, p auth.Principal, authority WebControlAuthority) (WebControlCleanup, error) {
	type outcome struct {
		cleanup WebControlCleanup
		err     error
	}
	completed := make(chan outcome, 1)
	go func() { cleanup, err := m.options.Retire(ctx, p, authority); completed <- outcome{cleanup, err} }()
	select {
	case result := <-completed:
		return result.cleanup, result.err
	case <-ctx.Done():
		return WebControlCleanup{UnknownExecutors: true}, ctx.Err()
	}
}

func (m *WebControlManager) Capabilities(ctx context.Context, p auth.Principal) map[string]bool {
	result := map[string]bool{}
	if !m.beginWork() {
		return result
	}
	defer m.active.Done()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ctx = bounded
	actual, err := webControlActor(ctx, p)
	if err != nil || m == nil {
		return result
	}
	scope, err := m.options.Enrolled(ctx, actual)
	if err != nil {
		return result
	}
	if m.options.CapabilityProbe != nil {
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed || m.options.Owner.Err() != nil || len(scope.Profiles) == 0 {
			return result
		}
		probed, err := m.options.CapabilityProbe(ctx, actual)
		if err != nil {
			return result
		}
		return probed
	}
	for _, profile := range scope.Profiles {
		candidates := profile.Origins
		if profile.AllWebsites && len(profile.Origins) == 0 {
			candidates = profile.ObservedOrigins
		}
		for _, origin := range candidates {
			if ctx.Err() != nil {
				return result
			}
			// Qualification must select one unique root document; policy never
			// guesses a tab or borrows a native fence.
			ready, err := m.qualify(ctx, actual, model.Surface{Kind: "web", Origin: origin})
			if err != nil {
				continue
			}
			if ready.NewlyAcquired {
				if m.retireOwnedAuthority(ctx, actual, ready.Authority, nil) != nil {
					continue
				}
			}
			if !supportsWebAction(ready, "element.press") && !supportsWebAction(ready, "element.fill") {
				continue
			}
			locatorReady := false
			for strategy, name := range map[string]string{"role": "roleLocator", "id": "idLocator", "testId": "testIdLocator", "label": "labelRelationships"} {
				if supportsWebLocator(ready, strategy) {
					result["web:"+name] = true
					locatorReady = true
				}
			}
			if !locatorReady {
				continue
			}
			for _, action := range []string{"browser.navigate", "browser.activate"} {
				if supportsWebAction(ready, action) {
					result["web:"+action] = true
				}
			}
			if supportsWebAction(ready, "element.press") {
				result["web:semanticPress"] = true
				result["web:element.press"] = true
			}
			if supportsWebAction(ready, "element.fill") {
				result["web:replaceValue"] = true
				result["web:element.fill"] = true
			}
		}
	}
	return result
}
func (m *WebControlManager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.closed = true
	if m.drained == nil {
		m.drained = make(chan struct{})
		go func() { m.active.Wait(); close(m.drained) }()
	}
	drained := m.drained
	m.mu.Unlock()
	select {
	case <-drained:
	case <-ctx.Done():
		return errors.Join(ErrWebControlCleanupUnknown, ctx.Err())
	}
	select {
	case m.closeLane <- struct{}{}:
		defer func() { <-m.closeLane }()
	case <-ctx.Done():
		return ctx.Err()
	}
	m.mu.Lock()
	if m.providerClosed {
		m.mu.Unlock()
		return nil
	}
	pending := make([]*webControlIntent, 0, len(m.prepared))
	for intent := range m.prepared {
		pending = append(pending, intent)
	}
	m.mu.Unlock()
	var failures []error
	for _, intent := range pending {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		// Close owns only drained, manager-tracked preparations. It never guesses
		// authority from the current tab or tears down transport during dispatch.
		proofCtx, cancel := context.WithTimeout(intent.ownerContext, 2*time.Second)
		stop := context.AfterFunc(ctx, cancel)
		cleanup, e := m.retire(proofCtx, intent.principal, intent.authority)
		stop()
		cancel()
		if e != nil || !cleanup.AuthorityRetired || !(cleanup.ExecutorsQuiesced || cleanup.RetiredAuthorityQuiesced) || cleanup.UnknownExecutors {
			m.mu.Lock()
			m.inhibited[webChannelKey(intent.authority)] = true
			m.mu.Unlock()
			failures = append(failures, errors.Join(e, ErrWebControlCleanupUnknown))
			continue
		}
		m.mu.Lock()
		intent.consumed = true
		if intent.stopCancellation != nil {
			intent.stopCancellation()
		}
		delete(m.prepared, intent)
		m.mu.Unlock()
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if e := m.options.Close(ctx); e != nil {
		return e
	}
	m.mu.Lock()
	m.providerClosed = true
	m.mu.Unlock()
	return nil
}

// Provider implementations may use the existing Chrome root-document gateway,
// but FixtureEnrollment and client hello claims never satisfy VerifyChannel.
// The gateway lease callback must represent this renderer authority ID/generation,
// not a native desktop fence. Its current production enrollment remains disabled.
func (a WebControlAuthority) RendererLease() chrome.Lease {
	return chrome.Lease{ID: a.ID, Generation: a.Generation}
}
