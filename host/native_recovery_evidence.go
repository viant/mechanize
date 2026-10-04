package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

// NativeRecoveryEvidencePolicy is trusted host enrollment. Display metadata is
// withheld unless it occurs in these explicit allowlists; observed data cannot
// enroll a route or redefine this policy.
type NativeRecoveryEvidencePolicy struct {
	Contracts       []core.Contract
	PolicyHash      string
	SafeIdentifiers []string
	SafeNames       []string
}

type NativeRecoveryEvidenceOptions struct {
	Observe func(context.Context, auth.Principal, model.Surface) (model.Observation, error)
	Resolve func(context.Context, auth.Principal, repairs.Snapshot) (NativeRecoveryEvidencePolicy, error)
}

type NativeRecoveryEvidenceProvider struct{ options NativeRecoveryEvidenceOptions }

func NewNativeRecoveryEvidence(options NativeRecoveryEvidenceOptions) (*NativeRecoveryEvidenceProvider, error) {
	if options.Observe == nil || options.Resolve == nil {
		return nil, errors.New("native recovery requires trusted observation and explicit policy enrollment")
	}
	return &NativeRecoveryEvidenceProvider{options: options}, nil
}

func recoveryEvidenceString(value string, maximum int, empty bool) bool {
	if (!empty && strings.TrimSpace(value) == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func recoveryEvidenceIdentity(ctx context.Context, p auth.Principal, snapshot repairs.Snapshot) (model.Surface, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:observe") && !actual.HasScope("desktop:control") {
		return model.Surface{}, auth.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return model.Surface{}, err
	}
	if !recoveryEvidenceString(p.ClientID, 256, true) || !recoveryEvidenceString(snapshot.Reference.RunID, 256, false) || !recoveryEvidenceString(snapshot.Reference.PlanID, 256, false) || snapshot.Reference.Revision < 1 || snapshot.Unknown || (snapshot.Reference.Status != "paused" && snapshot.Reference.Status != "new") || snapshot.CompletedSteps < 0 || snapshot.CompletedSteps >= len(snapshot.Plan.Steps) {
		return model.Surface{}, errors.New("exact stopped known native recovery revision required")
	}
	surface := snapshot.Plan.Steps[snapshot.CompletedSteps].Target.Surface
	if surface.Kind != "native" || surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil || !recoveryEvidenceString(surface.ProcessStartToken, 256, false) || !recoveryEvidenceString(surface.BundleID, 256, false) || surface.Title != "" || surface.Origin != "" || surface.TabID != "" {
		return model.Surface{}, errors.New("exact native process and birth scope required")
	}
	return surface, nil
}

func recoveryEvidenceSelectorPolicy(target model.Selector, surface model.Surface, ids, names map[string]bool, depth int) error {
	if depth > 16 || target.Validate() != nil || target.Surface != surface || target.Scope.NativeRoot != "" || len(target.Scope.Frame) != 0 || target.Locator == nil || !target.Locator.Exact || target.Locator.Value.Kind != model.StringValue || !recoveryEvidenceString(target.Locator.Value.String, 512, false) {
		return errors.New("literal exact enrolled native selector required")
	}
	for key, value := range target.Scope.Window {
		if value.Kind != model.StringValue {
			return errors.New("literal native recovery window scope required")
		}
		switch key {
		case "title":
			if !names[value.String] {
				return errors.New("native recovery window title must be explicitly safe")
			}
		case "role":
			if value.String != "window" && value.String != "AXWindow" {
				return errors.New("unsupported native recovery window role")
			}
		default:
			return errors.New("unsupported native recovery window scope")
		}
	}
	if len(target.Scope.Window) != 0 {
		if _, ok := target.Scope.Window["title"]; !ok {
			return errors.New("native recovery window title required")
		}
	}
	switch target.Locator.Strategy {
	case "id":
		if !ids[target.Locator.Value.String] {
			return errors.New("native recovery identifier must be explicitly safe")
		}
	case "name":
		if !names[target.Locator.Value.String] {
			return errors.New("native recovery name must be explicitly safe")
		}
	case "role":
		if recoveryEvidenceRole(target.Locator.Value.String) == "unknown" {
			return errors.New("unsupported native recovery locator role")
		}
	default:
		return errors.New("unsupported native recovery locator")
	}
	if target.Locator.Name != nil && (target.Locator.Name.Kind != model.StringValue || !names[target.Locator.Name.String]) {
		return errors.New("native recovery locator name must be explicitly safe")
	}
	if target.Ancestor != nil {
		return recoveryEvidenceSelectorPolicy(*target.Ancestor, surface, ids, names, depth+1)
	}
	return nil
}

func recoveryEvidenceAllowlist(values []string) (map[string]bool, []string, error) {
	if len(values) > 256 {
		return nil, nil, errors.New("bounded native recovery display policy required")
	}
	set := make(map[string]bool, len(values))
	ordered := append([]string(nil), values...)
	for _, value := range values {
		if !recoveryEvidenceString(value, 512, false) || set[value] {
			return nil, nil, errors.New("unique bounded native recovery display policy required")
		}
		set[value] = true
	}
	sort.Strings(ordered)
	return set, ordered, nil
}

func normalizeRecoveryEvidencePolicy(p auth.Principal, snapshot repairs.Snapshot, surface model.Surface, policy NativeRecoveryEvidencePolicy) (NativeRecoveryEvidencePolicy, map[string]bool, map[string]bool, error) {
	if !recoveryEvidenceString(policy.PolicyHash, 128, false) || len(policy.Contracts) < 1 || len(policy.Contracts) > 100 {
		return policy, nil, nil, errors.New("explicit bounded native recovery contracts required")
	}
	ids, sortedIDs, err := recoveryEvidenceAllowlist(policy.SafeIdentifiers)
	if err != nil {
		return policy, nil, nil, err
	}
	names, sortedNames, err := recoveryEvidenceAllowlist(policy.SafeNames)
	if err != nil {
		return policy, nil, nil, err
	}
	policy.SafeIdentifiers, policy.SafeNames = sortedIDs, sortedNames
	// Detach trusted callback objects before sorting or returning them.
	encoded, err := json.Marshal(policy.Contracts)
	if err != nil || len(encoded) > 262144 {
		return policy, nil, nil, errors.New("bounded native recovery contract payload required")
	}
	if err = json.Unmarshal(encoded, &policy.Contracts); err != nil {
		return policy, nil, nil, err
	}
	seen := map[string]bool{}
	for i := range policy.Contracts {
		contract := &policy.Contracts[i]
		if !contract.Qualified || contract.Surface != surface || !recoveryEvidenceString(contract.Profile, 128, false) || !recoveryEvidenceString(contract.Action, 128, false) || contract.TargetScope == nil || contract.TargetScope.Validate() != nil || len(contract.Permissions) < 1 || len(contract.Permissions) > 32 {
			return policy, nil, nil, errors.New("exact qualified native target contract required")
		}
		permissions := map[string]bool{}
		for _, permission := range contract.Permissions {
			if !recoveryEvidenceString(permission, 128, false) || permissions[permission] || !p.HasScope(permission) {
				return policy, nil, nil, auth.ErrUnauthorized
			}
			permissions[permission] = true
		}
		sort.Strings(contract.Permissions)
		matched := false
		for _, step := range snapshot.Plan.Steps[snapshot.CompletedSteps:] {
			if step.Target.Surface == surface && step.SemanticsProfile == contract.Profile && step.Action == contract.Action && reflect.DeepEqual(step.Target, *contract.TargetScope) && reflect.DeepEqual(step.Postcondition, contract.Postcondition) && reflect.DeepEqual(step.Effect.Reconcile, contract.Reconcile) {
				matched = true
				break
			}
		}
		if !matched {
			return policy, nil, nil, errors.New("native recovery contract does not enroll an original remaining target")
		}
		if err := recoveryEvidenceSelectorPolicy(*contract.TargetScope, surface, ids, names, 0); err != nil {
			return policy, nil, nil, err
		}
		payload, _ := json.Marshal(contract)
		key := string(payload)
		if seen[key] {
			return policy, nil, nil, errors.New("duplicate native recovery contract")
		}
		seen[key] = true
	}
	sort.Slice(policy.Contracts, func(i, j int) bool {
		left, _ := json.Marshal(policy.Contracts[i])
		right, _ := json.Marshal(policy.Contracts[j])
		return string(left) < string(right)
	})
	return policy, ids, names, nil
}

func recoveryEvidenceRole(role string) string {
	switch role {
	case "button", "textbox", "checkbox", "radio", "text", "window", "combobox", "menuitem", "application", "menu", "menubar", "tabgroup", "table", "row", "cell", "outline", "group", "scrollarea", "slider", "toolbar", "link", "unknown":
		return role
	case "AXApplication":
		return "application"
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
	case "AXComboBox", "AXPopUpButton":
		return "combobox"
	case "AXMenuItem":
		return "menuitem"
	case "AXMenu":
		return "menu"
	case "AXMenuBar":
		return "menubar"
	case "AXTabGroup":
		return "tabgroup"
	case "AXTable":
		return "table"
	case "AXRow":
		return "row"
	case "AXCell":
		return "cell"
	case "AXOutline":
		return "outline"
	case "AXGroup":
		return "group"
	case "AXScrollArea":
		return "scrollarea"
	case "AXSlider":
		return "slider"
	case "AXToolbar":
		return "toolbar"
	case "AXLink":
		return "link"
	default:
		return "unknown"
	}
}

func recoveryEvidenceBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func redactNativeRecoveryObservation(raw model.Observation, surface model.Surface, ids, names map[string]bool, now time.Time) (model.Observation, string, error) {
	if raw.Surface != surface || raw.NativeRoot != "" || len(raw.WindowScope) != 0 || raw.WindowRootsOnly || raw.Truncated || len(raw.Unavailable) != 0 || len(raw.Nodes) < 1 || len(raw.Nodes) > 256 || raw.Started.IsZero() || raw.Ended.IsZero() || raw.Started.After(raw.Ended) || raw.Ended.After(now) || now.Sub(raw.Ended) >= 5*time.Second || raw.Ended.Sub(raw.Started) > 5*time.Second {
		return model.Observation{}, "", errors.New("complete fresh exact native recovery observation required")
	}
	redacted := model.Observation{Surface: surface, Started: raw.Started, Ended: raw.Ended, Nodes: make([]model.Node, 0, len(raw.Nodes))}
	seenRefs := map[string]bool{}
	for _, node := range raw.Nodes {
		if node.NativeOwnerProcessID != 0 && node.NativeOwnerProcessID != surface.ProcessID || node.NativeOwnerStartToken != "" && node.NativeOwnerStartToken != surface.ProcessStartToken || node.NativeOwnerBundleID != "" && node.NativeOwnerBundleID != surface.BundleID || node.NativeOwnerMatchesRoot != nil && !*node.NativeOwnerMatchesRoot {
			return model.Observation{}, "", errors.New("native recovery node belongs to a foreign process")
		}
		if !recoveryEvidenceString(node.Ref.ID, 256, false) || !recoveryEvidenceString(node.ParentID, 256, true) || seenRefs[node.Ref.ID] {
			return model.Observation{}, "", errors.New("unique bounded native recovery topology references required")
		}
		seenRefs[node.Ref.ID] = true
		safe := model.Node{Role: recoveryEvidenceRole(node.Role), Enabled: recoveryEvidenceBool(node.Enabled), Visible: recoveryEvidenceBool(node.Visible), Focused: recoveryEvidenceBool(node.Focused)}
		if ids[node.Identifier] {
			safe.Identifier = node.Identifier
		}
		if names[node.Name] {
			safe.Name = node.Name
		}
		redacted.Nodes = append(redacted.Nodes, safe)
	}
	topologyHash, err := nativeRecoveryTopologyHash(raw, redacted.Nodes)
	if err != nil {
		return model.Observation{}, "", err
	}
	sort.Slice(redacted.Nodes, func(i, j int) bool {
		left, _ := json.Marshal(redacted.Nodes[i])
		right, _ := json.Marshal(redacted.Nodes[j])
		return string(left) < string(right)
	})
	return redacted, topologyHash, nil
}

func nativeRecoveryEvidenceRef(p auth.Principal, snapshot repairs.Snapshot, policy NativeRecoveryEvidencePolicy, observation model.Observation, topology string) string {
	observation.Started, observation.Ended = time.Time{}, time.Time{}
	proof := struct {
		Version             string
		Namespace, ClientID string
		Reference           repairs.RunReference
		Policy              NativeRecoveryEvidencePolicy
		Observation         model.Observation
		Topology            string
	}{"native-recovery-evidence-v1", p.Namespace, p.ClientID, snapshot.Reference, policy, observation, topology}
	body, _ := json.Marshal(proof)
	digest := sha256.Sum256(body)
	return "native-recovery:" + hex.EncodeToString(digest[:])
}

// Prepare observes metadata through the host's ordinary read authorization. It
// supplies no dispatch handles, raw values, or automatic route qualification.
func (provider *NativeRecoveryEvidenceProvider) Prepare(ctx context.Context, p auth.Principal, snapshot repairs.Snapshot) (repairs.Evidence, error) {
	if provider == nil {
		return repairs.Evidence{}, errors.New("native recovery evidence provider unavailable")
	}
	surface, err := recoveryEvidenceIdentity(ctx, p, snapshot)
	if err != nil {
		return repairs.Evidence{}, err
	}
	// Context identity supplies scopes; the caller cannot expand its grants by
	// retaining the same namespace and client in a larger Principal value.
	p, _ = auth.FromContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	detachedJSON, err := json.Marshal(snapshot)
	if err != nil {
		return repairs.Evidence{}, err
	}
	var detached repairs.Snapshot
	if err := json.Unmarshal(detachedJSON, &detached); err != nil {
		return repairs.Evidence{}, err
	}
	policy, err := provider.options.Resolve(ctx, p, detached)
	if err != nil {
		return repairs.Evidence{}, err
	}
	if err = ctx.Err(); err != nil {
		return repairs.Evidence{}, err
	}
	policy, ids, names, err := normalizeRecoveryEvidencePolicy(p, snapshot, surface, policy)
	if err != nil {
		return repairs.Evidence{}, err
	}
	raw, err := provider.options.Observe(ctx, p, surface)
	if err != nil {
		return repairs.Evidence{}, err
	}
	if err = ctx.Err(); err != nil {
		return repairs.Evidence{}, err
	}
	observation, topology, err := redactNativeRecoveryObservation(raw, surface, ids, names, time.Now())
	if err != nil {
		return repairs.Evidence{}, err
	}
	return repairs.Evidence{Verified: true, Redacted: true, Observation: observation, EvidenceRefs: []string{nativeRecoveryEvidenceRef(p, snapshot, policy, observation, topology)}, PolicyHash: policy.PolicyHash, Contracts: policy.Contracts, ValidUntil: observation.Ended.Add(5 * time.Second)}, nil
}

// Verify independently refreshes trusted policy and semantic observation. A
// stable redacted UI can refresh; a changed actor, route, process or UI cannot.
func (provider *NativeRecoveryEvidenceProvider) Verify(ctx context.Context, p auth.Principal, snapshot repairs.Snapshot, evidence repairs.Evidence) error {
	now := time.Now()
	if !evidence.Verified || !evidence.Redacted || len(evidence.EvidenceRefs) != 1 || evidence.ValidUntil.IsZero() || !now.Before(evidence.ValidUntil) || evidence.Observation.Started.IsZero() || evidence.Observation.Ended.IsZero() || evidence.Observation.Started.After(evidence.Observation.Ended) || evidence.Observation.Ended.After(now) || now.Sub(evidence.Observation.Ended) >= 5*time.Second || evidence.Observation.Ended.Sub(evidence.Observation.Started) > 5*time.Second || evidence.ValidUntil.After(evidence.Observation.Ended.Add(5*time.Second)) {
		return errors.New("fresh native recovery proof required")
	}
	fresh, err := provider.Prepare(ctx, p, snapshot)
	if err != nil {
		return err
	}
	if !time.Now().Before(evidence.ValidUntil) || evidence.PolicyHash != fresh.PolicyHash || evidence.EvidenceRefs[0] != fresh.EvidenceRefs[0] || !reflect.DeepEqual(evidence.Contracts, fresh.Contracts) {
		return errors.New("native recovery evidence identity, policy, scope or UI changed")
	}
	// Reconstruct the proof's semantic observation to reject inserted raw fields
	// and semantic tampering, even when a caller retains its old reference.
	semantic := evidence.Observation
	semantic.Started, semantic.Ended = fresh.Observation.Started, fresh.Observation.Ended
	if !reflect.DeepEqual(semantic, fresh.Observation) {
		return errors.New("native recovery redacted observation changed")
	}
	return ctx.Err()
}
