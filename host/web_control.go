package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
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
	authorizeRead func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error)
	Owner         context.Context
	Enrolled      func(context.Context, auth.Principal) (WebControlScope, error)
	// Qualify must select exactly one live enrolled root document and return fresh
	// operator evidence. VerifyChannel independently rechecks the actual connected
	// kernel peer/signature, Chrome parent and exact channel/document identity.
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
	options   WebControlOptions
	mu        sync.Mutex
	closed    bool
	inhibited map[string]bool
}
type webControlIntent struct {
	postconditionRead *webPostconditionRead
	readReady         bool
	manager           *WebControlManager
	principal         auth.Principal
	binding           auth.ConsentBinding
	metadata          automation.ExecutionMetadata
	stepHash          string
	authority         WebControlAuthority
	dispatched        bool
}
type webControlIntentKey struct{}

func NewWebControlManager(options WebControlOptions) (*WebControlManager, error) {
	if options.Owner == nil || options.Enrolled == nil || options.Qualify == nil || options.VerifyChannel == nil || options.Authorize == nil || options.ExecutePinned == nil || options.Retire == nil || options.RecordCleanupUnknown == nil || options.Close == nil {
		return nil, ErrWebControlUnqualified
	}
	return &WebControlManager{options: options, inhibited: map[string]bool{}}, nil
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
	if step.Target.Surface.Kind != "web" || step.Effect.Class == model.ReadOnly || (step.Action != "element.press" && step.Action != "element.fill") {
		return ErrWebControlUnqualified
	}
	if step.Target.Surface.Origin == "" || step.Target.Surface.BundleID != "" || len(step.Target.Scope.Frame) > 0 || len(step.Target.Scope.Window) > 0 || step.Target.Ancestor != nil {
		return ErrWebControlUnqualified
	}
	if step.Target.Locator == nil || !step.Target.Locator.Exact || step.Target.Cardinality != "one" {
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
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host != "" && parsed.User == nil && parsed.Scheme+"://"+parsed.Host == origin && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
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
func (m *WebControlManager) qualify(ctx context.Context, p auth.Principal, surface model.Surface) (WebControlReadiness, error) {
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
	a, d := ready.Authority, ready.Authority.Document
	now := time.Now()
	if !ready.NativeHostSignatureQualified || !ready.KernelPeerQualified || !ready.ChromeParentQualified || !webScopeQualified(ready) || !ready.ExtensionQualified || !ready.DocumentQualified || !ready.ExecutorQualified || ready.UnresolvedExecutors || !ready.ValidUntil.After(now) || ready.ValidUntil.After(now.Add(5*time.Second)) || a.Owner != p.Namespace || a.ID == "" || a.Generation == 0 || a.Generation > uint64(math.MaxInt) || a.BrokerEpoch == "" || a.ChannelEpoch == "" || a.ScopeHash == "" || d.FrameID != 0 || d.TabID <= 0 || d.DocumentID == "" || d.Generation == 0 || d.Origin != surface.Origin || a.NativeHost.PID <= 0 || a.NativeHost.StartToken == "" || !filepath.IsAbs(a.NativeHost.Executable) || a.NativeHost.UID != uint32(os.Getuid()) || a.BrowserParent.PID <= 0 || a.BrowserParent.StartToken == "" || !filepath.IsAbs(a.BrowserParent.Executable) || a.BrowserParent.UID != uint32(os.Getuid()) {
		return WebControlReadiness{}, ErrWebControlUnqualified
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
			for _, origin := range profile.Origins {
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
func (m *WebControlManager) Prepare(ctx context.Context, p auth.Principal, step model.Step) (context.Context, int, error) {
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
	if !supportsWebAction(ready, step.Action) || !supportsWebLocator(ready, step.Target.Locator.Strategy) {
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
	intent := &webControlIntent{manager: m, principal: actual, binding: binding, metadata: meta, stepHash: hash, authority: ready.Authority, postconditionRead: ready.postconditionRead}
	return context.WithValue(ctx, webControlIntentKey{}, intent), int(ready.Authority.Generation), nil
}

// Execute is called ONLY by the durable dispatcher after intent commit. The
// private permit cannot be lent across manager, owner/client, run/step or grant.
func (m *WebControlManager) Execute(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
	result := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
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
	unavailable := m.closed || intent.dispatched || m.inhibited[webChannelKey(intent.authority)]
	m.mu.Unlock()
	if unavailable {
		return result, ErrWebControlIntent
	}
	ready, err := m.qualify(ctx, actual, step.Target.Surface)
	if err != nil {
		return result, err
	}
	if ready.Authority != intent.authority || !supportsWebAction(ready, step.Action) || !supportsWebLocator(ready, step.Target.Locator.Strategy) {
		return result, ErrWebControlIntent
	}
	lease, err := m.options.Authorize(ctx, actual, step.Target.Surface)
	if err != nil {
		return result, err
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
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
	intent.dispatched = true
	m.mu.Unlock()
	dispatchCtx, cancel := context.WithCancel(lease.Context)
	stopOwner := context.AfterFunc(m.options.Owner, cancel)
	defer func() { stopOwner(); cancel() }()
	if err = dispatchCtx.Err(); err != nil {
		lease.Release()
		return result, err
	}
	result, dispatchErr := m.options.ExecutePinned(dispatchCtx, actual, step, values, intent.authority)
	// Renderer receipts do not establish a business postcondition.
	result.VerificationState = "unknown"
	result.Postcondition = nil
	if result.DispatchState == "" || dispatchCtx.Err() != nil {
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
	for _, profile := range scope.Profiles {
		for _, origin := range profile.Origins {
			if ctx.Err() != nil {
				return result
			}
			// Qualification must select one unique root document; policy never
			// guesses a tab or borrows a native fence.
			ready, err := m.qualify(ctx, actual, model.Surface{Kind: "web", Origin: origin})
			if err != nil {
				continue
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
	m.mu.Unlock()
	return m.options.Close(ctx)
}

// Provider implementations may use the existing Chrome root-document gateway,
// but FixtureEnrollment and client hello claims never satisfy VerifyChannel.
// The gateway lease callback must represent this renderer authority ID/generation,
// not a native desktop fence. Its current production enrollment remains disabled.
func (a WebControlAuthority) RendererLease() chrome.Lease {
	return chrome.Lease{ID: a.ID, Generation: a.Generation}
}
