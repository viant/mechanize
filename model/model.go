// Package model defines the shared, serializable desktop and browser contracts.
package model

import "time"

type ValueKind string

const (
	StringValue    ValueKind = "string"
	NumberValue    ValueKind = "number"
	BoolValue      ValueKind = "boolean"
	ReferenceValue ValueKind = "reference"
	DurationValue  ValueKind = "duration"
	ArrayValue     ValueKind = "array"
	ObjectValue    ValueKind = "object"
)

// Value is a tagged scalar or runtime reference; references are never interpolated.
type Value struct {
	Expected ValueKind        `json:"expected,omitempty"`
	Kind     ValueKind        `json:"kind"`
	String   string           `json:"string,omitempty"`
	Number   int64            `json:"number,omitempty"`
	Bool     bool             `json:"boolean,omitempty"`
	Ref      string           `json:"ref,omitempty"`
	Array    []Value          `json:"array,omitempty"`
	Object   map[string]Value `json:"object,omitempty"`
}
type Surface struct {
	Kind              string `json:"kind"`
	ProcessID         int    `json:"processId,omitempty"`
	ProcessStartToken string `json:"processStartToken,omitempty"`
	BundleID          string `json:"bundleId,omitempty"`
	Origin            string `json:"origin,omitempty"`
	Title             string `json:"title,omitempty"`
	TabID             string `json:"tabId,omitempty"`
}
type Scope struct {
	NativeRoot string           `json:"nativeRoot,omitempty"`
	Window     map[string]Value `json:"window,omitempty"`
	Frame      map[string]Value `json:"frame,omitempty"`
}
type Locator struct {
	Strategy string `json:"strategy"`
	Value    Value  `json:"value"`
	Name     *Value `json:"name,omitempty"`
	Exact    bool   `json:"exact"`
}
type Selector struct {
	Surface     Surface   `json:"surface"`
	Scope       Scope     `json:"scope"`
	Locator     *Locator  `json:"locator,omitempty"`
	Ancestor    *Selector `json:"ancestor,omitempty"`
	Cardinality string    `json:"cardinality"`
	Limit       int       `json:"limit,omitempty"`
	Index       *int      `json:"index,omitempty"`
	Order       string    `json:"order,omitempty"`
}
type EffectClass string

const (
	ReadOnly              EffectClass = "readOnly"
	IdempotentMutation    EffectClass = "idempotentMutation"
	ReversibleMutation    EffectClass = "reversibleMutation"
	ExternalNonIdempotent EffectClass = "externalNonIdempotent"
)

type Effect struct {
	Class       EffectClass      `json:"class"`
	BusinessKey map[string]Value `json:"businessKey,omitempty"`
	Reconcile   *Predicate       `json:"reconcile,omitempty"`
}
type Assertion struct {
	Matcher  string `json:"matcher"`
	Not      bool   `json:"not"`
	Expected *Value `json:"expected,omitempty"`
}
type SourceSpan struct {
	Offset int `json:"offset"`
	Line   int `json:"line"`
	Column int `json:"column"`
}
type Step struct {
	Command          string            `json:"command,omitempty"`
	SemanticsProfile string            `json:"semanticsProfile,omitempty"`
	Precondition     *Predicate        `json:"precondition,omitempty"`
	Postcondition    *Predicate        `json:"postcondition,omitempty"`
	Checkpoint       *CheckpointPolicy `json:"checkpoint,omitempty"`
	ResultType       ValueKind         `json:"resultType,omitempty"`
	ID               string            `json:"id"`
	Action           string            `json:"action"`
	Target           Selector          `json:"target"`
	Arguments        map[string]Value  `json:"arguments"`
	TimeoutMs        int64             `json:"timeoutMs"`
	Effect           Effect            `json:"effect"`
	Assertion        *Assertion        `json:"assertion,omitempty"`
	Bind             string            `json:"bind,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	Source           SourceSpan        `json:"source"`
}
type Binding struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Selector *Selector `json:"selector,omitempty"`
	Value    *Value    `json:"value,omitempty"`
}
type Plan struct {
	Name          string                        `json:"name,omitempty"`
	Inputs        map[string]InputDefinition    `json:"inputs,omitempty"`
	Surfaces      map[string]Surface            `json:"surfaces,omitempty"`
	Artifacts     map[string]ArtifactDefinition `json:"artifacts,omitempty"`
	Objective     *Predicate                    `json:"objective,omitempty"`
	Goal          *WorkflowGoal                 `json:"goal,omitempty"`
	Constraints   *Constraints                  `json:"constraints,omitempty"`
	Recovery      *RecoveryPolicy               `json:"recovery,omitempty"`
	Requires      *Requirements                 `json:"requires,omitempty"`
	Checkpoints   []CheckpointPolicy            `json:"checkpoints,omitempty"`
	SchemaVersion int                           `json:"schemaVersion"`
	Steps         []Step                        `json:"steps"`
	Bindings      []Binding                     `json:"bindings"`
}

// ElementRef identifies a generation-scoped opaque element, never a native pointer.
type ElementRef struct {
	ID          string `json:"id"`
	Epoch       string `json:"epoch"`
	AppLaunchID string `json:"appLaunchId"`
	Generation  uint64 `json:"generation"`
}
type Node struct {
	// Diagnostic actual AX-element ownership; no delegated input authority.
	NativeOwnerProcessID   int     `json:"nativeOwnerProcessId,omitempty"`
	NativeOwnerStartToken  string  `json:"nativeOwnerStartToken,omitempty"`
	NativeOwnerBundleID    string  `json:"nativeOwnerBundleId,omitempty"`
	NativeOwnerUID         *uint32 `json:"nativeOwnerUid,omitempty"`
	NativeOwnerMatchesRoot *bool   `json:"nativeOwnerMatchesRoot,omitempty"`
	Focused                *bool   `json:"focused,omitempty"`
	FocusSettable          *bool   `json:"focusSettable,omitempty"`
	// Advertised AX metadata guides target choice; it grants no input authority.
	Actions                   []string         `json:"actions,omitempty"`
	SelectedTextSettable      *bool            `json:"selectedTextSettable,omitempty"`
	SelectedTextRangeSettable *bool            `json:"selectedTextRangeSettable,omitempty"`
	ValueSettable             *bool            `json:"valueSettable,omitempty"`
	Ref                       ElementRef       `json:"ref"`
	ParentID                  string           `json:"parentId,omitempty"`
	Role                      string           `json:"role"`
	NativeRole                string           `json:"nativeRole,omitempty"`
	Name                      string           `json:"name,omitempty"`
	Identifier                string           `json:"identifier,omitempty"`
	Values                    map[string]Value `json:"values,omitempty"`
	Unavailable               []string         `json:"unavailable,omitempty"`
	Enabled                   *bool            `json:"enabled,omitempty"`
	Visible                   *bool            `json:"visible,omitempty"`
}
type Observation struct {
	// WindowScope identifies an exact bounded window subtree, never whole-app coverage.
	WindowScope     map[string]string `json:"windowScope,omitempty"`
	WindowRootsOnly bool              `json:"windowRootsOnly,omitempty"`
	NativeRoot      string            `json:"nativeRoot,omitempty"`
	ID              string            `json:"id"`
	Sequence        uint64            `json:"sequence"`
	Epoch           string            `json:"epoch"`
	Started         time.Time         `json:"started"`
	Ended           time.Time         `json:"ended"`
	Surface         Surface           `json:"surface"`
	Nodes           []Node            `json:"nodes"`
	Truncated       bool              `json:"truncated"`
	Unavailable     []string          `json:"unavailable,omitempty"`
}
type MatchSet struct {
	Elements  []ElementRef `json:"elements"`
	Complete  bool         `json:"complete"`
	Truncated bool         `json:"truncated"`
}
type Capability struct {
	Name      string `json:"name"`
	Surface   string `json:"surface"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}
type MechanizeError struct {
	Code          string   `json:"code"`
	Message       string   `json:"message"`
	Stage         string   `json:"stage"`
	RetryableRead bool     `json:"retryableRead"`
	DispatchState string   `json:"dispatchState,omitempty"`
	EffectState   string   `json:"effectState,omitempty"`
	EvidenceRefs  []string `json:"evidenceRefs,omitempty"`
}

func (e *MechanizeError) Error() string { return e.Code + ": " + e.Message }
