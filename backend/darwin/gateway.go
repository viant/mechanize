package darwin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

type Caller interface {
	Call(context.Context, Request) (Reply, error)
	Close() error
}
type GatewayOptions struct {
	AllApplications bool
	AllowedBundles  []string
	// Lease must return an externally held desktop-wide fence, never a per-app lock.
	Lease func(context.Context, auth.Principal) (Lease, error)
	// Explicit bundle/AX identifier read policy. Snapshot values stay withheld.
	AllowedValueIdentifiers map[string][]string
	// Exact app opt-in for bounded, noneditable AXStaticText reads only.
	AllowedStaticTextBundles []string
}
type Gateway struct {
	caller                       Caller
	options                      GatewayOptions
	bundles                      map[string]bool
	values                       map[string]map[string]bool
	staticText                   map[string]bool
	mu                           sync.Mutex
	epoch                        string
	readGeneration               uint64
	installed                    Lease
	sequence                     uint64
	axTrusted                    bool
	mutationEnabled              bool
	semanticEnabled              bool
	targetedKeyboardEnabled      bool
	sessionKeyboardEnabled       bool
	launchEnabled                bool
	nativeRootScopes             map[string]bool
	windowTitleScopeEnabled      bool
	windowPositionEnabled        bool
	windowSessionKeyboardEnabled bool
	windowFrameClickEnabled      bool
	framePermit                  *WindowFramePermit
	textReplaceEnabled           bool
	valueMatchesEnabled          bool
}

func NewGateway(caller Caller, options GatewayOptions) (*Gateway, error) {
	if caller == nil {
		return nil, errors.New("native caller required")
	}
	scope, err := (session.Scope{AllApplications: options.AllApplications, AllowedBundles: options.AllowedBundles}).Normalize()
	if err != nil {
		return nil, err
	}
	options.AllowedBundles = scope.AllowedBundles
	g := &Gateway{caller: caller, options: options, bundles: map[string]bool{}, values: map[string]map[string]bool{}, staticText: map[string]bool{}}
	for _, bundle := range options.AllowedBundles {
		if strings.TrimSpace(bundle) == "" {
			return nil, errors.New("empty allowed bundle")
		}
		g.bundles[bundle] = true
	}
	for bundle, ids := range options.AllowedValueIdentifiers {
		g.values[bundle] = map[string]bool{}
		for _, id := range ids {
			if id != "" {
				g.values[bundle][id] = true
			}
		}
	}
	if len(options.AllowedStaticTextBundles) > 64 {
		return nil, errors.New("static text policy exceeds 64 exact bundles")
	}
	for _, bundle := range options.AllowedStaticTextBundles {
		if (session.Scope{AllowedBundles: []string{bundle}}).Validate() != nil || !scope.AllowsBundle(bundle) || g.staticText[bundle] {
			return nil, errors.New("static text policy requires an exact bundle within desktop scope")
		}
		g.staticText[bundle] = true
	}
	return g, nil
}
func (g *Gateway) Close() error { return g.caller.Close() }
func (g *Gateway) Capabilities() []model.Capability {
	g.mu.Lock()
	defer g.mu.Unlock()
	caps := []model.Capability{{Name: "sessionKeyboard", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && g.sessionKeyboardEnabled, Reason: "Explicit login-session keyboard route; foreground and sheet qualification required"}, {Name: "element.focus", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && g.semanticEnabled, Reason: "Explicit settable AXFocused, exact foreground identity required"}, {Name: "targetedKeyboard", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && g.targetedKeyboardEnabled, Reason: "Explicit scoped focus-bound one-key chord; not pointer/text authority"}, {Name: "observe", Surface: "native", Supported: g.axTrusted, Reason: "Scoped AX; permission-granted fixture qualification pending"}, {Name: "element.read", Surface: "native", Supported: g.axTrusted, Reason: "Metadata and explicitly permitted nonsecure value reads"}, {Name: "element.press", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled), Reason: "External fence, helper mutation opt-in and AX permission required; receipt is not success"}, {Name: "element.fill", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled), Reason: "External fence, helper mutation opt-in and AX permission required; receipt is not success"}, {Name: "element.submit", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled), Reason: "Only an advertised AXConfirm action; no keyboard reinterpretation"}, {Name: "app.activate", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled), Reason: "Explicit scoped activation with independent active identity verification"}, {Name: "app.open", Surface: "native", Supported: g.options.Lease != nil && g.launchEnabled, Reason: "Exact enrolled bundle, external fence and signed lifecycle opt-in; receipt is not business completion"}, {Name: "windowScope", Surface: "native", Supported: g.axTrusted && g.windowTitleScopeEnabled, Reason: "Exact unique window title and optional window role; complete closed AX tree required"}, {Name: "ancestorScope", Surface: "native", Supported: g.axTrusted, Reason: "Exact unique same-surface ancestor and strict descendants in a complete closed AX graph"}, {Name: "frameScope", Surface: "native", Supported: false}}
	caps = append(caps, model.Capability{Name: "windowPosition", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled) && g.windowPositionEnabled, Reason: "Explicit AXWindow position setter, external fence and exact readback required"})
	caps = append(caps, model.Capability{Name: "windowSessionKeyboard", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.semanticEnabled || g.mutationEnabled) && g.sessionKeyboardEnabled && g.windowSessionKeyboardEnabled, Reason: "Explicit captured CGWindow login-session chord; no AX lookup or automatic success"})
	caps = append(caps, model.Capability{Name: "windowFrameClick", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && g.semanticEnabled && g.windowFrameClickEnabled, Reason: "One-use exact captured-window frame pixels under retained qualified control; receipt is not outcome proof"})
	caps = append(caps, model.Capability{Name: "replaceText", Surface: "native", Supported: g.options.Lease != nil && g.axTrusted && (g.mutationEnabled || g.semanticEnabled) && g.textReplaceEnabled, Reason: "Explicit selected-text replacement, full range and readback; no AXValue fallback"}, model.Capability{Name: "valueMatches", Surface: "native", Supported: g.axTrusted && g.valueMatchesEnabled, Reason: "Private bounded literal equality proof; no plaintext value export"})
	return append(caps, model.Capability{Name: "menuBarScope", Surface: "native", Supported: g.axTrusted && g.nativeRootScopes["menuBar"], Reason: "Complete exact app-owned menu bar subtree"}, model.Capability{Name: "focusedElementScope", Surface: "native", Supported: g.axTrusted && g.nativeRootScopes["focusedElement"], Reason: "Complete exact app-owned focused element subtree, rechecked before input"})
}

func authorized(ctx context.Context, p auth.Principal, control bool) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace {
		return auth.ErrUnauthorized
	}
	scope := "desktop:observe"
	if control {
		scope = "desktop:control"
	}
	if !actual.HasScope(scope) && !(scope == "desktop:observe" && actual.HasScope("desktop:control")) {
		return auth.ErrUnauthorized
	}
	return nil
}
func (g *Gateway) surface(surface model.Surface) error {
	if err := surface.ValidateProcessIdentity(); err != nil {
		return nativeError("scopeDenied", err.Error())
	}
	if surface.Kind != "native" || surface.BundleID == "" || !(session.Scope{AllApplications: g.options.AllApplications, AllowedBundles: g.options.AllowedBundles}).AllowsBundle(surface.BundleID) || surface.Origin != "" || surface.Title != "" || surface.TabID != "" {
		return nativeError("scopeDenied", "Exact native bundle target within the verified desktop scope is required")
	}
	return nil
}
func nativeError(code, message string) error {
	return &model.MechanizeError{Code: code, Message: message, Stage: "native", DispatchState: "notDispatched", EffectState: "none"}
}
func requestID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data[:])
}
func (g *Gateway) call(ctx context.Context, method string, params any, lease *Lease) (Reply, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return Reply{}, err
	}
	reply, err := g.caller.Call(ctx, Request{ProtocolVersion: 1, RequestID: requestID(), Method: method, HelperEpoch: g.epoch, DeadlineRemainingMS: 30000, Lease: lease, Params: data})
	if reply.HelperEpoch != "" {
		if g.epoch != "" && g.epoch != reply.HelperEpoch {
			return reply, nativeError("staleEpoch", "Helper restarted; reobserve and reconcile")
		}
		g.epoch = reply.HelperEpoch
	}
	return reply, err
}
func (g *Gateway) ready(ctx context.Context) error {
	if prepared, ok := g.caller.(interface {
		PrepareRead(context.Context) (uint64, error)
	}); ok {
		generation, err := prepared.PrepareRead(ctx)
		if err != nil {
			return err
		}
		if generation == 0 {
			return nativeError("staleEpoch", "Observation helper generation unavailable")
		}
		if g.readGeneration != generation {
			g.readGeneration = generation
			g.epoch = ""
			g.installed = Lease{}
			g.sequence = 0
			g.axTrusted = false
			g.mutationEnabled = false
			g.semanticEnabled = false
			g.targetedKeyboardEnabled = false
			g.sessionKeyboardEnabled = false
			g.launchEnabled = false
			g.nativeRootScopes = nil
			g.windowTitleScopeEnabled = false
			g.windowPositionEnabled = false
			g.windowSessionKeyboardEnabled = false
			g.windowFrameClickEnabled = false
			g.framePermit = nil
			g.textReplaceEnabled = false
			g.valueMatchesEnabled = false
		}
	}
	if g.epoch != "" {
		return nil
	}
	reply, err := g.call(ctx, "doctor", map[string]any{}, nil)
	if err == nil {
		var doctor struct {
			AXTrusted               bool     `json:"axTrusted"`
			MutationEnabled         bool     `json:"mutationEnabled"`
			SemanticEnabled         bool     `json:"semanticEnabled"`
			TargetedKeyboardEnabled bool     `json:"targetedKeyboardEnabled"`
			SessionKeyboardEnabled  bool     `json:"sessionKeyboardEnabled"`
			WindowFrameClickEnabled bool     `json:"windowFrameClickEnabled"`
			CaptureGranted          bool     `json:"captureGranted"`
			LaunchEnabled           bool     `json:"launchEnabled"`
			NativeRootScopes        []string `json:"nativeRootScopes"`
			NativeWindowScopes      []string `json:"nativeWindowScopes"`
			NativeWindowActions     []string `json:"nativeWindowActions"`
			NativeTextActions       []string `json:"nativeTextActions"`
			NativeTextReads         []string `json:"nativeTextReads"`
		}
		err = json.Unmarshal(reply.Result, &doctor)
		g.axTrusted = doctor.AXTrusted
		g.mutationEnabled = doctor.MutationEnabled
		g.semanticEnabled = doctor.SemanticEnabled
		g.targetedKeyboardEnabled = doctor.TargetedKeyboardEnabled
		g.sessionKeyboardEnabled = doctor.SessionKeyboardEnabled
		g.windowFrameClickEnabled = doctor.WindowFrameClickEnabled && doctor.CaptureGranted
		g.launchEnabled = doctor.LaunchEnabled
		g.windowTitleScopeEnabled = false
		for _, scope := range doctor.NativeWindowScopes {
			if scope == "exactTitle" {
				g.windowTitleScopeEnabled = true
			}
		}
		g.windowPositionEnabled = false
		g.windowSessionKeyboardEnabled = false
		for _, action := range doctor.NativeWindowActions {
			if action == "pressSessionKey" {
				g.windowSessionKeyboardEnabled = true
			}
			if action == "setPosition" {
				g.windowPositionEnabled = true
			}
		}
		g.textReplaceEnabled = false
		g.valueMatchesEnabled = false
		for _, action := range doctor.NativeTextActions {
			if action == "replaceText" {
				g.textReplaceEnabled = true
			}
		}
		for _, read := range doctor.NativeTextReads {
			if read == "valueMatches" {
				g.valueMatchesEnabled = true
			}
		}
		g.nativeRootScopes = map[string]bool{}
		for _, scope := range doctor.NativeRootScopes {
			if scope == "menuBar" || scope == "focusedElement" {
				g.nativeRootScopes[scope] = true
			}
		}
	}
	return err
}
func (g *Gateway) LeaseEpoch(ctx context.Context, p auth.Principal) (int, error) {
	if err := authorized(ctx, p, false); err != nil {
		return 0, err
	}
	if g.options.Lease == nil {
		return 0, nativeError("leaseUnavailable", "External desktop fence provider is required")
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return 0, err
	}
	if lease.ID == "" || lease.Generation == 0 || lease.Generation > uint64(math.MaxInt) {
		return 0, nativeError("invalidLease", "Held fence requires ID and positive generation")
	}
	return int(lease.Generation), nil
}

type nativeNode struct {
	NativeOwnerProcessID      int      `json:"nativeOwnerProcessId"`
	NativeOwnerStartToken     string   `json:"nativeOwnerStartToken"`
	NativeOwnerBundleID       string   `json:"nativeOwnerBundleId"`
	NativeOwnerUID            *uint32  `json:"nativeOwnerUid"`
	NativeOwnerMatchesRoot    *bool    `json:"nativeOwnerMatchesRoot"`
	Focused                   *bool    `json:"focused"`
	FocusSettable             *bool    `json:"focusSettable"`
	Actions                   []string `json:"actions"`
	SelectedTextSettable      *bool    `json:"selectedTextSettable"`
	SelectedTextRangeSettable *bool    `json:"selectedTextRangeSettable"`
	ValueSettable             *bool    `json:"valueSettable"`
	Ref                       string   `json:"ref"`
	Parent                    string   `json:"parentRef"`
	Role                      string   `json:"nativeRole"`
	Name                      string   `json:"name"`
	Identifier                string   `json:"identifier"`
	Enabled                   *bool    `json:"enabled"`
	Unavailable               []string `json:"unavailable"`
	Truncated                 []string `json:"truncatedAttributes"`
}
type snapshot struct {
	WindowScope     map[string]string `json:"windowScope"`
	WindowRootsOnly bool              `json:"windowRootsOnly"`
	RootScope       string            `json:"rootScope"`
	ID              string            `json:"observationId"`
	Generation      uint64            `json:"generation"`
	Started         time.Time         `json:"startedAt"`
	Ended           time.Time         `json:"returnedAt"`
	Complete        bool              `json:"complete"`
	Truncated       bool              `json:"truncated"`
	Nodes           []nativeNode      `json:"nodes"`
}

func (g *Gateway) observe(ctx context.Context, surface model.Surface) (model.Observation, error) {
	return g.observeScoped(ctx, surface, "")
}

func (g *Gateway) observeScoped(ctx context.Context, surface model.Surface, nativeRoot string) (model.Observation, error) {
	return g.observeSnapshot(ctx, surface, nativeRoot, false)
}
func (g *Gateway) observeSnapshot(ctx context.Context, surface model.Surface, nativeRoot string, windowOnly bool) (model.Observation, error) {
	return g.observeWindowSnapshot(ctx, surface, nativeRoot, windowOnly, nil)
}
func (g *Gateway) observeWindowSnapshot(ctx context.Context, surface model.Surface, nativeRoot string, windowOnly bool, windowScope map[string]string) (model.Observation, error) {
	if err := g.surface(surface); err != nil {
		return model.Observation{}, err
	}
	if err := g.ready(ctx); err != nil {
		return model.Observation{}, err
	}
	if len(windowScope) > 0 && (!g.windowTitleScopeEnabled || nativeRoot != "" || windowOnly) {
		return model.Observation{}, nativeError("unsupportedScope", "Exact window-root helper scope required")
	}
	if nativeRoot != "" && !g.nativeRootScopes[nativeRoot] {
		return model.Observation{}, nativeError("unsupportedScope", "Native helper does not advertise the requested root scope")
	}
	reply, err := g.call(ctx, "apps.list", map[string]any{"expectedApp": surface.BundleID}, nil)
	if err != nil {
		return model.Observation{}, err
	}
	var apps struct {
		Apps []struct {
			PID        int    `json:"pid"`
			Bundle     string `json:"bundleID"`
			Launch     string `json:"launchTime"`
			StartToken string `json:"startToken"`
		} `json:"apps"`
		Complete bool `json:"complete"`
	}
	if err = json.Unmarshal(reply.Result, &apps); err != nil {
		return model.Observation{}, err
	}
	if !apps.Complete {
		return model.Observation{}, nativeError("incompleteObservation", "App enumeration is incomplete")
	}
	pid := 0
	launch := ""
	matches := 0
	for _, app := range apps.Apps {
		if app.Bundle == surface.BundleID && (surface.ProcessID == 0 || (app.PID == surface.ProcessID && app.StartToken == surface.ProcessStartToken)) {
			pid = app.PID
			launch = app.Launch
			matches++
		}
	}
	if matches != 1 {
		code := "ambiguousTarget"
		if surface.ProcessID != 0 {
			code = "staleReference"
		} else if matches == 0 {
			code = "targetNotFound"
		}
		return model.Observation{}, nativeError(code, fmt.Sprintf("Expected one app instance, found %d", matches))
	}
	if pid <= 0 || launch == "" {
		return model.Observation{}, nativeError("appIdentityUnavailable", "Stable process launch identity is unavailable")
	}
	params := map[string]any{"pid": pid, "bundleID": surface.BundleID, "maxNodes": 1000, "maxDepth": 20}
	if len(windowScope) > 0 {
		params["windowScope"] = windowScope
	}
	if nativeRoot != "" {
		params["rootScope"] = nativeRoot
	}
	if surface.ProcessID != 0 {
		params["processStartToken"] = surface.ProcessStartToken
	}
	method := "elements.snapshot"
	if windowOnly {
		method = "windows.list"
		params["maxDepth"] = 0
	}
	reply, err = g.call(ctx, method, params, nil)
	if err != nil {
		return model.Observation{}, err
	}
	var tree snapshot
	if err = json.Unmarshal(reply.Result, &tree); err != nil {
		return model.Observation{}, err
	}
	if !reflect.DeepEqual(tree.WindowScope, windowScope) {
		return model.Observation{}, nativeError("unsupportedScope", "Native snapshot did not confirm exact window scope")
	}
	if tree.WindowRootsOnly != windowOnly {
		return model.Observation{}, nativeError("unsupportedScope", "Native snapshot did not confirm the exact requested window-root scope")
	}
	if windowOnly {
		if !tree.Complete || tree.Truncated || len(tree.Nodes) > 1000 {
			return model.Observation{}, nativeError("incompleteObservation", "Complete bounded window enumeration required")
		}
		seen := map[string]bool{}
		for _, node := range tree.Nodes {
			if node.Role != "AXWindow" || node.Parent != "" || node.Ref == "" || seen[node.Ref] {
				return model.Observation{}, nativeError("incompleteObservation", "Window enumeration contains invalid or duplicate roots")
			}
			seen[node.Ref] = true
		}
	}
	if tree.RootScope != nativeRoot {
		return model.Observation{}, nativeError("unsupportedScope", "Native snapshot did not confirm the exact requested root scope")
	}
	g.sequence++
	observation := model.Observation{WindowScope: tree.WindowScope, WindowRootsOnly: windowOnly, NativeRoot: nativeRoot, ID: tree.ID, Epoch: g.epoch, Sequence: g.sequence, Started: tree.Started, Ended: tree.Ended, Surface: surface, Truncated: tree.Truncated || !tree.Complete}
	for _, node := range tree.Nodes {
		unavailable := append([]string(nil), node.Unavailable...)
		for _, field := range node.Truncated {
			unavailable = append(unavailable, "truncated:"+field)
		}
		// These are bounded advertised semantics, not permission/qualification.
		// Values remain withheld; secure-target checks still run at dispatch.
		actions := make([]string, 0, min(len(node.Actions), 32))
		truncatedActions := len(node.Actions) > 32
		for _, action := range node.Actions[:min(len(node.Actions), 32)] {
			if len(action) > 128 {
				truncatedActions = true
				continue
			}
			actions = append(actions, action)
		}
		if truncatedActions {
			unavailable = append(unavailable, "truncated:actions")
		}
		observation.Nodes = append(observation.Nodes, model.Node{Ref: model.ElementRef{ID: node.Ref, Epoch: g.epoch, AppLaunchID: fmt.Sprintf("%d:%s", pid, launch), Generation: tree.Generation}, ParentID: node.Parent, Role: role(node.Role), NativeRole: node.Role, Name: node.Name, Identifier: node.Identifier, Enabled: node.Enabled, Unavailable: unavailable, Actions: actions, SelectedTextSettable: node.SelectedTextSettable, SelectedTextRangeSettable: node.SelectedTextRangeSettable, ValueSettable: node.ValueSettable, Focused: node.Focused, FocusSettable: node.FocusSettable, NativeOwnerProcessID: node.NativeOwnerProcessID, NativeOwnerStartToken: node.NativeOwnerStartToken, NativeOwnerBundleID: node.NativeOwnerBundleID, NativeOwnerUID: node.NativeOwnerUID, NativeOwnerMatchesRoot: node.NativeOwnerMatchesRoot})
	}
	return observation, nil
}
func (g *Gateway) Observe(ctx context.Context, p auth.Principal, surface model.Surface) (model.Observation, error) {
	if err := authorized(ctx, p, false); err != nil {
		return model.Observation{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.observe(ctx, surface)
}

// ObserveNativeRoot reads only the explicitly selected app-owned semantic subtree.
// Unsupported helper capabilities and missing scope echoes fail without broadening.
func (g *Gateway) ObserveNativeRoot(ctx context.Context, p auth.Principal, surface model.Surface, nativeRoot string) (model.Observation, error) {
	if surface.Kind != "native" || (nativeRoot != "menuBar" && nativeRoot != "focusedElement") {
		return model.Observation{}, fmt.Errorf("supported native observation root required")
	}
	if err := authorized(ctx, p, false); err != nil {
		return model.Observation{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.observeScoped(ctx, surface, nativeRoot)
}

// ValidateNativeWindowRequest describes the exact process/window-only read
// contract. It adds no AX queries or input/value-read authority.
func ValidateNativeWindowRequest(surface model.Surface, title, role string) error {
	if surface.Kind != "native" || surface.BundleID == "" || surface.ProcessID <= 0 || surface.ProcessStartToken == "" || surface.Origin != "" || surface.Title != "" || surface.TabID != "" || surface.ValidateProcessIdentity() != nil {
		return nativeError("invalidScope", "Exact native process and window title required")
	}
	scope := map[string]model.Value{"title": {Kind: model.StringValue, String: title}}
	if role != "" {
		scope["role"] = model.Value{Kind: model.StringValue, String: role}
	}
	_, _, err := windowScopeValues(scope, nil)
	return err
}

// ValidateNativeWindowObservation checks an untrusted returned metadata graph
// against the exact requested process and scope; it does not query Accessibility.
func ValidateNativeWindowObservation(observed model.Observation, surface model.Surface, title, role string) error {
	if err := ValidateNativeWindowRequest(surface, title, role); err != nil {
		return err
	}
	wanted := map[string]string{"title": title}
	if role != "" {
		wanted["role"] = role
	}
	if observed.Surface != surface || observed.NativeRoot != "" || observed.WindowRootsOnly || !reflect.DeepEqual(observed.WindowScope, wanted) || len(observed.Unavailable) != 0 {
		return nativeError("unsupportedScope", "Exact native window observation identity/scope required")
	}
	if observed.ID == "" || observed.Epoch == "" || observed.Sequence == 0 || observed.Started.IsZero() || observed.Ended.IsZero() || observed.Ended.Before(observed.Started) {
		return nativeError("incompleteObservation", "Fresh native snapshot identity required")
	}
	graph, err := validatedParentGraph(observed)
	if err != nil {
		return err
	}
	root := ""
	var uid *uint32
	for _, node := range observed.Nodes {
		if node.Ref.Epoch != observed.Epoch || node.Ref.Generation == 0 || node.Ref.AppLaunchID == "" {
			return nativeError("incompleteObservation", "Fresh generation-bound node references required")
		}
		if node.NativeOwnerMatchesRoot == nil || !*node.NativeOwnerMatchesRoot || node.NativeOwnerUID == nil || node.NativeOwnerProcessID != surface.ProcessID || node.NativeOwnerStartToken != surface.ProcessStartToken || node.NativeOwnerBundleID != surface.BundleID || len(node.Values) != 0 {
			return nativeError("rootOwnerMismatch", "Exact owned nonvalue metadata required for every node")
		}
		if uid == nil {
			uid = node.NativeOwnerUID
		} else if *uid != *node.NativeOwnerUID {
			return nativeError("rootOwnerMismatch", "Window tree owner UID differs")
		}
		if node.ParentID == "" {
			if root != "" || node.NativeRole != "AXWindow" || node.Role != "window" || node.Name != title || unavailableAttribute(node, "name") || unavailableAttribute(node, "role") {
				return nativeError("incompleteObservation", "One exact selected AXWindow root required")
			}
			root = node.Ref.ID
		}
	}
	if root == "" {
		return nativeError("incompleteObservation", "Selected window root unavailable")
	}
	for _, node := range observed.Nodes {
		if node.Ref.ID == root {
			continue
		}
		parent := node.ParentID
		for parent != "" && parent != root {
			parent = graph[parent].ParentID
		}
		if parent != root {
			return nativeError("incompleteObservation", "Node lies outside selected window root")
		}
	}
	return nil
}

// ObserveNativeWindow exposes the already-qualified exact-title helper route as
// a metadata-only read. Unsupported scope or incomplete evidence never broadens.
func (g *Gateway) ObserveNativeWindow(ctx context.Context, p auth.Principal, surface model.Surface, title, role string) (model.Observation, error) {
	if err := ValidateNativeWindowRequest(surface, title, role); err != nil {
		return model.Observation{}, err
	}
	if err := authorized(ctx, p, false); err != nil {
		return model.Observation{}, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID {
		return model.Observation{}, auth.ErrUnauthorized
	}
	scope := map[string]string{"title": title}
	if role != "" {
		scope["role"] = role
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	observed, err := g.observeWindowSnapshot(ctx, surface, "", false, scope)
	if err != nil {
		return model.Observation{}, err
	}
	if err = ValidateNativeWindowObservation(observed, surface, title, role); err != nil {
		return model.Observation{}, err
	}
	return observed, nil
}

func role(native string) string {
	switch native {
	case "AXButton":
		return "button"
	case "AXTextField", "AXTextArea":
		return "textbox"
	case "AXCheckBox":
		return "checkbox"
	case "AXRadioButton":
		return "radio"
	case "AXStaticText":
		return "text"
	case "AXWindow":
		return "window"
	case "AXComboBox":
		return "combobox"
	case "AXMenuItem":
		return "menuitem"
	}
	return native
}
func resolve(observation model.Observation, target model.Selector, values map[string]model.Value) (model.Node, error) {
	if observation.Truncated {
		return model.Node{}, nativeError("incompleteObservation", "Complete lookup required to prove uniqueness")
	}
	nodes, err := windowScopedNodes(observation, target.Scope.Window, values)
	if err != nil {
		return model.Node{}, err
	}
	var graph map[string]model.Node
	if target.Ancestor != nil {
		graph, err = validatedParentGraph(observation)
		if err != nil {
			return model.Node{}, err
		}
	}
	return resolveScopedNodes(nodes, target, values, graph, target.Scope.Window, 0)
}

func resolveScopedNodes(nodes []model.Node, target model.Selector, values map[string]model.Value, graph map[string]model.Node, window map[string]model.Value, depth int) (model.Node, error) {
	if depth > 4 {
		return model.Node{}, nativeError("unsupportedScope", "Ancestor scope exceeds four levels")
	}
	if len(target.Scope.Frame) > 0 {
		return model.Node{}, nativeError("unsupportedScope", "Frame scope is not qualified")
	}
	if target.Cardinality != "one" || target.Locator == nil || !target.Locator.Exact {
		return model.Node{}, nativeError("unsupportedLocator", "Exact strict cardinality-one locator required")
	}
	value, err := model.ResolveValue(target.Locator.Value, values)
	if err != nil || value.Kind != model.StringValue {
		return model.Node{}, nativeError("invalidLocator", "Locator must resolve to string")
	}
	var name *string
	if target.Locator.Name != nil {
		v, e := model.ResolveValue(*target.Locator.Name, values)
		if e != nil || v.Kind != model.StringValue {
			return model.Node{}, nativeError("invalidLocator", "Role name must resolve to string")
		}
		name = &v.String
	}
	strategy := target.Locator.Strategy
	if strategy != "role" && strategy != "id" && strategy != "name" {
		return model.Node{}, nativeError("unsupportedLocator", "Native supports exact role/id/name only")
	}
	if target.Ancestor != nil {
		ancestor := *target.Ancestor
		if ancestor.Surface != target.Surface {
			return model.Node{}, nativeError("unsupportedScope", "Ancestor cannot cross native surfaces")
		}
		if len(ancestor.Scope.Window) > 0 {
			title, _, err := windowScopeValues(ancestor.Scope.Window, values)
			wanted, _, outerErr := windowScopeValues(window, values)
			if err != nil || outerErr != nil || title != wanted || len(window) == 0 {
				return model.Node{}, nativeError("unsupportedScope", "Ancestor must use the same explicit window boundary")
			}
		}
		parent, err := resolveScopedNodes(nodes, ancestor, values, graph, window, depth+1)
		if err != nil {
			return model.Node{}, err
		}
		var descendants []model.Node
		for _, node := range nodes {
			for parentID := node.ParentID; parentID != ""; parentID = graph[parentID].ParentID {
				if parentID == parent.Ref.ID {
					descendants = append(descendants, node)
					break
				}
			}
		}
		nodes = descendants
	}
	var matches []model.Node
	for _, node := range nodes {
		if strategy == "role" && node.Role != value.String && node.NativeRole != value.String {
			// An unrelated known role cannot satisfy a role/name conjunction. Missing
			// names on that node do not weaken uniqueness of the candidate role set.
			if node.Role == "" && node.NativeRole == "" {
				return model.Node{}, nativeError("incompleteObservation", "Required role attribute unavailable")
			}
			for _, missing := range node.Unavailable {
				if missing == "role" || missing == "truncated:role" {
					return model.Node{}, nativeError("incompleteObservation", "Required role attribute unavailable")
				}
			}
			continue
		}
		field := strategy
		if field == "id" {
			field = "identifier"
		}
		for _, missing := range node.Unavailable {
			if missing == field || missing == "truncated:"+field || (name != nil && (missing == "name" || missing == "truncated:name")) {
				return model.Node{}, nativeError("incompleteObservation", "Required locator attribute unavailable")
			}
		}
		match := strategy == "role" && (node.Role == value.String || node.NativeRole == value.String) || strategy == "id" && node.Identifier == value.String || strategy == "name" && node.Name == value.String
		if match && (name == nil || node.Name == *name) {
			matches = append(matches, node)
		}
	}
	if len(matches) != 1 {
		code := "ambiguousTarget"
		if len(matches) == 0 {
			code = "targetNotFound"
		}
		return model.Node{}, nativeError(code, fmt.Sprintf("Expected exactly one element, found %d", len(matches)))
	}
	return matches[0], nil
}
func (g *Gateway) Execute(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	mutation := step.Action == "window.pressSessionKey" || step.Action == "element.replaceText" || step.Action == "window.moveTo" || step.Action == "element.focus" || (step.Action == "element.pressKey" || step.Action == "element.pressSessionKey") || step.Action == "element.press" || step.Action == "element.fill" || step.Action == "element.submit" || step.Action == "app.open" || step.Action == "app.activate"
	if err := authorized(ctx, p, mutation); err != nil {
		return result, err
	}
	if err := step.Validate(); err != nil {
		return result, err
	}
	if (step.Action == "element.focus" || (step.Action == "element.pressKey" || step.Action == "element.pressSessionKey")) && (step.Target.Surface.ProcessID <= 0 || step.Target.Surface.ProcessStartToken == "") {
		return result, nativeError("processIdentityRequired", "Explicit PID and kernel birth required for focus/keyboard")
	}

	var positionX, positionY int64
	if step.Action == "window.moveTo" {
		arguments, err := step.ResolveArguments(values)
		if err != nil {
			return result, err
		}
		positionX, positionY, err = model.WindowPosition(arguments["position"])
		if err != nil {
			return result, err
		}
	}
	if err := g.surface(step.Target.Surface); err != nil {
		return result, err
	}
	if len(step.Target.Scope.Frame) > 0 {
		return result, nativeError("unsupportedScope", "Frame scope not qualified")
	}
	if _, _, err := windowScopeValues(step.Target.Scope.Window, values); err != nil {
		return result, err
	}
	timeout := time.Duration(step.TimeoutMs) * time.Millisecond
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if step.Action == "window.pressSessionKey" {
		return g.pressWindowKey(ctx, p, step, values)
	}
	if step.Action == "window.clickFrame" {
		return g.clickWindowFrame(ctx, p, step, values)
	}
	if step.Action == "app.open" {
		return g.openApp(ctx, p, step)
	}
	if step.Action == "app.activate" {
		return g.activateApp(ctx, p, step)
	}
	windowScope, err := resolvedWindowScope(step.Target.Scope.Window, values)
	if err != nil {
		return result, err
	}
	observation, err := g.observeWindowSnapshot(ctx, step.Target.Surface, step.Target.Scope.NativeRoot, step.Action == "window.moveTo", windowScope)
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	node, err := resolve(observation, step.Target, values)
	if err != nil {
		return result, err
	}
	if step.Action == "window.moveTo" && (!g.windowPositionEnabled || node.NativeRole != "AXWindow" || node.Role != "window") {
		return result, nativeError("windowPositionUnsupported", "Advertised position action and exact AXWindow target required")
	}
	if step.Action == "element.replaceText" && (!g.textReplaceEnabled || node.SelectedTextSettable == nil || !*node.SelectedTextSettable || node.SelectedTextRangeSettable == nil || !*node.SelectedTextRangeSettable) {
		return result, nativeError("replaceTextUnsupported", "Explicit selected-text and full-range setters required")
	}
	params := map[string]any{"elementRef": node.Ref.ID, "generation": node.Ref.Generation, "expectedApp": step.Target.Surface.BundleID}
	if mutation {
		if !g.axTrusted || !(g.mutationEnabled || g.semanticEnabled) {
			return result, nativeError("mutationDisabled", "Helper mutation opt-in and AX trust required")
		}
		if step.Action != "window.moveTo" && (node.Enabled == nil || !*node.Enabled) {
			return result, nativeError("targetNotActionable", "Enabled state must be positively known")
		}
		if g.options.Lease == nil {
			return result, nativeError("leaseUnavailable", "External desktop fence required")
		}
		lease, err := g.options.Lease(ctx, p)
		if err != nil {
			return result, err
		}
		if lease.ID == "" || lease.Generation == 0 {
			return result, nativeError("invalidLease", "Held external fence absent")
		}
		if lease != g.installed {
			if _, err = g.call(ctx, "lease.install", lease, nil); err != nil {
				return result, err
			}
			g.installed = lease
		}
		if step.Action == "element.focus" && (node.FocusSettable == nil || !*node.FocusSettable) {
			return result, nativeError("focusUnsupported", "Target does not advertise settable AXFocused; inspect current focused target")
		}
		if (step.Action == "element.pressKey" || step.Action == "element.pressSessionKey") && (node.Focused == nil || !*node.Focused) {
			return result, nativeError("staleFocus", "Target must already be focused; use explicit focus only when independently supported")
		}
		method := "elements.press"
		if step.Action == "window.moveTo" {
			method = "windows.setPosition"
			params["position"] = map[string]int64{"x": positionX, "y": positionY}
		}
		if step.Action == "element.focus" {
			method = "elements.focus"
		}
		if step.Action == "element.pressKey" || step.Action == "element.pressSessionKey" {
			if (step.Action == "element.pressKey" && !g.targetedKeyboardEnabled || step.Action == "element.pressSessionKey" && !g.sessionKeyboardEnabled) || step.Target.Surface.ProcessID <= 0 || step.Target.Surface.ProcessStartToken == "" {
				return result, nativeError("keyboardUnqualified", "Explicit process identity and selected keyboard route enrollment required")
			}
			value, e := model.ResolveValue(step.Arguments["key"], values)
			if e != nil || value.Kind != model.StringValue || validateKeyboardChord(value.String) != nil {
				return result, nativeError("invalidKey", "Closed named key/chord required")
			}
			method = "elements.pressKey"
			if step.Action == "element.pressSessionKey" {
				method = "elements.pressSessionKey"
			}
			params["key"] = value.String
		}
		if step.Action == "element.submit" {
			method = "elements.submit"
		}
		if step.Action == "element.fill" || step.Action == "element.replaceText" {
			method = "elements.setValue"
			if step.Action == "element.replaceText" {
				method = "elements.replaceText"
			}
			value, e := model.ResolveValue(step.Arguments["value"], values)
			if e != nil || value.Kind != model.StringValue {
				return result, nativeError("invalidValue", "Fill must resolve to string")
			}
			if step.Action == "element.replaceText" {
				if e = model.ValidateLiteralText(value.String); e != nil {
					return result, e
				}
			}
			params["value"] = value.String
			// Only explicit plaintext literals qualify this post-write proof.
			// Bound/Vault/sensitive references and protected selectors retain
			// ordinary dispatched-unverified behavior, with no value read API.
			protectedTarget := step.Target
			protectedTarget.Surface = model.Surface{}
			targetBody, _ := json.Marshal(protectedTarget)
			protected := false
			for _, marker := range []string{"password", "credential", "secret", "token", "securetextfield"} {
				protected = protected || strings.Contains(strings.ToLower(string(targetBody)), marker)
			}
			if step.Arguments["value"].Kind == model.StringValue && !protected && step.Target.Surface.ProcessID > 0 && step.Target.Surface.ProcessStartToken != "" {
				params["verifyReplacement"] = true
			}
		}
		reply, callErr := g.call(ctx, method, params, &lease)
		if reply.Receipt != nil {
			result.DispatchState = reply.Receipt.DispatchState
		} else {
			var transport *TransportError
			if errors.As(callErr, &transport) {
				result.DispatchState = transport.DispatchState
			}
		}
		if step.Action == "element.focus" && callErr == nil && ctx.Err() == nil && reply.Receipt != nil && reply.Receipt.DispatchState == "dispatched" {
			var proof struct {
				Focused    bool   `json:"focused"`
				PID        int    `json:"pid"`
				StartToken string `json:"startToken"`
				Bundle     string `json:"bundleID"`
				Ref        string `json:"targetRef"`
				Generation uint64 `json:"generation"`
			}
			if json.Unmarshal(reply.Result, &proof) == nil && proof.Focused && proof.PID == step.Target.Surface.ProcessID && proof.StartToken == step.Target.Surface.ProcessStartToken && proof.Bundle == step.Target.Surface.BundleID && proof.Ref == node.Ref.ID && proof.Generation == node.Ref.Generation && reply.Receipt.TargetRef == node.Ref.ID {
				result.VerificationState = "verified"
			}
		}
		if (step.Action == "element.fill" || step.Action == "element.replaceText") && params["verifyReplacement"] == true && callErr == nil && ctx.Err() == nil && reply.Receipt != nil && reply.Receipt.DispatchState == "dispatched" {
			var proof struct {
				Matches    bool      `json:"replacementMatches"`
				PID        int       `json:"pid"`
				Birth      string    `json:"startToken"`
				Bundle     string    `json:"bundleID"`
				Ref        string    `json:"targetRef"`
				Generation uint64    `json:"generation"`
				RequestID  string    `json:"requestId"`
				ObservedAt time.Time `json:"observedAt"`
			}
			if json.Unmarshal(reply.Result, &proof) == nil && proof.Matches && proof.PID == step.Target.Surface.ProcessID && proof.Birth == step.Target.Surface.ProcessStartToken && proof.Bundle == step.Target.Surface.BundleID && proof.Ref == node.Ref.ID && proof.Generation == node.Ref.Generation && proof.RequestID == reply.RequestID && proof.RequestID != "" && reply.Receipt.TargetRef == node.Ref.ID && !proof.ObservedAt.Before(observation.Started) && !proof.ObservedAt.After(time.Now()) && time.Since(proof.ObservedAt) <= 3*time.Second {
				result.VerificationState = "verified"
			}
		}
		if step.Action == "window.moveTo" && callErr == nil && ctx.Err() == nil && reply.Receipt != nil && reply.Receipt.DispatchState == "dispatched" {
			var proof struct {
				PositionVerified bool `json:"positionVerified"`
				Position         struct {
					X *int64 `json:"x"`
					Y *int64 `json:"y"`
				} `json:"position"`
				PID        int       `json:"pid"`
				Birth      string    `json:"startToken"`
				Bundle     string    `json:"bundleID"`
				Ref        string    `json:"targetRef"`
				Generation uint64    `json:"generation"`
				RequestID  string    `json:"requestId"`
				ObservedAt time.Time `json:"observedAt"`
			}
			if json.Unmarshal(reply.Result, &proof) == nil && proof.PositionVerified && proof.Position.X != nil && proof.Position.Y != nil && *proof.Position.X == positionX && *proof.Position.Y == positionY && proof.PID == step.Target.Surface.ProcessID && proof.Birth == step.Target.Surface.ProcessStartToken && proof.Bundle == step.Target.Surface.BundleID && proof.Ref == node.Ref.ID && proof.Generation == node.Ref.Generation && proof.RequestID != "" && proof.RequestID == reply.RequestID && reply.Receipt.TargetRef == node.Ref.ID && !proof.ObservedAt.Before(observation.Started) && !proof.ObservedAt.After(time.Now()) && time.Since(proof.ObservedAt) <= 3*time.Second {
				result.VerificationState = "verified"
			} else {
				result.DispatchState = "unknown"
				callErr = &model.MechanizeError{Code: "windowPositionUnconfirmed", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Window position readback is unconfirmed; reconcile before replay"}
			}
		}
		if step.Action == "window.moveTo" && callErr == nil && result.VerificationState != "verified" {
			result.DispatchState = "unknown"
			callErr = &model.MechanizeError{Code: "windowPositionUnconfirmed", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Window position readback is unconfirmed; reconcile before replay"}
		}
		if step.Action == "element.replaceText" && reply.Receipt == nil {
			var nativeFailure *NativeError
			if errors.As(callErr, &nativeFailure) && nativeFailure.DispatchState != "" {
				result.DispatchState = nativeFailure.DispatchState
			}
			if callErr == nil {
				result.DispatchState = "unknown"
				callErr = &model.MechanizeError{Code: "replacementUnconfirmed", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Selected-text write receipt is unconfirmed; reconcile before replay"}
			}
		}
		// A successful AX return cannot verify a business effect. Durable builder
		// records unknown and blocks replay until an outcome adapter reconciles it.
		return result, callErr
	}
	attribute := ""
	if step.Action == "element.read" {
		attribute = step.Arguments["attribute"].String
	} else if step.Action == "expect" {
		switch step.Assertion.Matcher {
		case "toBeEnabled":
			attribute = "enabled"
		case "toHaveText":
			attribute = "name"
		case "toHaveValue":
			attribute = "value"
		default:
			return result, nativeError("unsupportedAssertion", "Visibility is not inferred from AX presence")
		}
	}
	if attribute == "text" {
		attribute = "name"
	}
	if attribute == "checked" {
		return result, nativeError("unsupportedAttribute", "Checked state codec not qualified")
	}
	if attribute == "value" {
		if !g.values[step.Target.Surface.BundleID][node.Identifier] {
			return result, nativeError("valueReadDenied", "Value read identifier is not explicitly permitted")
		}
		params["allowValueRead"] = true
		params["expectedIdentifier"] = node.Identifier
	}
	if attribute == "staticText" {
		if !g.staticText[step.Target.Surface.BundleID] || node.NativeRole != "AXStaticText" {
			return result, nativeError("staticTextReadDenied", "Static text requires explicit app policy and AXStaticText target")
		}
		params["allowStaticTextRead"] = true
	}
	params["attributes"] = []string{attribute}
	reply, err := g.call(ctx, "elements.read", params, nil)
	if err != nil {
		return result, err
	}
	var read struct {
		Values      map[string]json.RawMessage `json:"values"`
		Unavailable []string                   `json:"unavailable"`
	}
	if err = json.Unmarshal(reply.Result, &read); err != nil {
		return result, err
	}
	raw, ok := read.Values[attribute]
	if !ok {
		return result, nativeError("attributeUnavailable", "Requested attribute unavailable")
	}
	var value model.Value
	if attribute == "enabled" || attribute == "focused" {
		value.Kind = model.BoolValue
		err = json.Unmarshal(raw, &value.Bool)
	} else {
		value.Kind = model.StringValue
		err = json.Unmarshal(raw, &value.String)
	}
	if err != nil {
		return result, err
	}
	if attribute == "staticText" && (len(value.String) > 4096 || strings.ContainsRune(value.String, 0)) {
		return result, nativeError("invalidReadEvidence", "Static text exceeds the bounded string policy")
	}
	if step.Action == "expect" {
		holds := value.Bool
		if step.Assertion.Expected != nil {
			expected, e := model.ResolveValue(*step.Assertion.Expected, values)
			if e != nil {
				return result, e
			}
			holds = expected.Kind == value.Kind && expected.String == value.String
		}
		if step.Assertion.Not {
			holds = !holds
		}
		if !holds {
			return result, nativeError("assertionFailed", "Native assertion failed")
		}
	} else {
		result.Value = &value
	}
	// Evidence belongs to the separately completed read, not an action receipt.
	result.Observation = &model.Observation{ID: observation.ID, Epoch: g.epoch, Started: observation.Started, Ended: time.Now(), Surface: step.Target.Surface, Nodes: []model.Node{{Ref: node.Ref}}}
	result.VerificationState = "verified"
	return result, nil
}

// openApp uses the public lifecycle route before any AX lookup. It never accepts
// an executable path, document URL, command line or action replay request.
func (g *Gateway) openApp(ctx context.Context, p auth.Principal, step model.Step) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if err := g.ready(ctx); err != nil {
		return result, err
	}
	if !g.launchEnabled {
		return result, nativeError("launchDisabled", "Signed helper lifecycle opt-in is required")
	}
	if g.options.Lease == nil {
		return result, nativeError("leaseUnavailable", "External desktop fence required for application launch")
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return result, err
	}
	if lease.ID == "" || lease.Generation == 0 {
		return result, nativeError("invalidLease", "Held external fence absent")
	}
	if lease != g.installed {
		if _, err = g.call(ctx, "lease.install", lease, nil); err != nil {
			return result, err
		}
		g.installed = lease
	}
	reply, callErr := g.call(ctx, "app.launch", map[string]any{"expectedApp": step.Target.Surface.BundleID}, &lease)
	if reply.Receipt != nil {
		result.DispatchState = reply.Receipt.DispatchState
	} else {
		var transport *TransportError
		if errors.As(callErr, &transport) {
			result.DispatchState = transport.DispatchState
		} else if callErr == nil {
			result.DispatchState = "unknown"
		}
	}
	if callErr != nil {
		return result, callErr
	}
	if reply.Error != nil {
		return result, reply.Error
	}
	var identity struct {
		BundleID   string `json:"bundleID"`
		PID        int    `json:"pid"`
		LaunchTime string `json:"launchTime"`
		StartToken string `json:"startToken"`
		Active     bool   `json:"active"`
	}
	if json.Unmarshal(reply.Result, &identity) != nil || identity.BundleID != step.Target.Surface.BundleID || identity.PID <= 0 || identity.LaunchTime == "" || identity.StartToken == "" || result.DispatchState != "dispatched" {
		result.DispatchState = "unknown"
		return result, &model.MechanizeError{Code: "launchIdentityUnknown", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: "Application launch receipt lacks the exact postlaunch process identity; reconcile before replay"}
	}
	// Verify the action's narrow app-running effect through a separate public
	// process enumeration after the receipt, never the receipt's own echo.
	observed, observeErr := g.call(ctx, "apps.list", map[string]any{"expectedApp": step.Target.Surface.BundleID}, nil)
	var current struct {
		Complete bool `json:"complete"`
		Apps     []struct {
			BundleID   string `json:"bundleID"`
			PID        int    `json:"pid"`
			LaunchTime string `json:"launchTime"`
			StartToken string `json:"startToken"`
		} `json:"apps"`
	}
	if observed.Error != nil {
		observeErr = errors.Join(observeErr, observed.Error)
	}
	if observeErr != nil || json.Unmarshal(observed.Result, &current) != nil || !current.Complete {
		result.DispatchState = "unknown"
		return result, errors.Join(observeErr, &model.MechanizeError{Code: "launchPostconditionUnknown", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Independent application identity observation is unavailable after launch; reconcile before replay"})
	}
	matches := 0
	targetInstances := 0
	for _, app := range current.Apps {
		if app.BundleID == identity.BundleID {
			targetInstances++
		}
		if app.BundleID == identity.BundleID && app.PID == identity.PID && app.LaunchTime == identity.LaunchTime && app.StartToken == identity.StartToken {
			matches++
		}
	}
	if matches != 1 || targetInstances != 1 {
		result.DispatchState = "unknown"
		return result, &model.MechanizeError{Code: "launchPostconditionUnknown", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Independent application observation differs from the launched process identity; reconcile before replay"}
	}
	result.Value = &model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{
		"bundleID":   {Kind: model.StringValue, String: identity.BundleID},
		"pid":        {Kind: model.NumberValue, Number: int64(identity.PID)},
		"launchTime": {Kind: model.StringValue, String: identity.LaunchTime},
		"startToken": {Kind: model.StringValue, String: identity.StartToken},
		"active":     {Kind: model.BoolValue, Bool: identity.Active},
	}}
	// Only the app-running lifecycle effect is verified independently. Mail
	// content and the caller's business objective still require their own proof.
	result.VerificationState = "verified"
	return result, nil
}
