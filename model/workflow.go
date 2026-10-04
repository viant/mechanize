package model

// WorkflowGoal records descriptive business intent for recovery context.
// It is never an executable condition or evidence that the workflow succeeded.
type WorkflowGoal struct {
	Description     string   `json:"description"`
	SuccessCriteria []string `json:"successCriteria,omitempty"`
}

// Workflow metadata belongs to the same immutable IR; Endly owns composition.
type InputDefinition struct {
	Type      ValueKind `json:"type"`
	Required  bool      `json:"required"`
	Sensitive bool      `json:"sensitive,omitempty"`
	Default   *Value    `json:"default,omitempty"`
}
type Requirements struct {
	SemanticsProfiles []string `json:"semanticsProfiles,omitempty"`
	Adapters          []string `json:"adapters,omitempty"`
}
type ArtifactDefinition struct {
	FromPath Value    `json:"fromPath"`
	Require  []string `json:"require"`
}
type PredicateScope struct {
	SurfaceRef string    `json:"surfaceRef,omitempty"`
	Target     *Selector `json:"target,omitempty"`
}
type Predicate struct {
	Kind              string           `json:"kind"`
	Adapter           string           `json:"adapter,omitempty"`
	Name              string           `json:"name,omitempty"`
	Inputs            map[string]Value `json:"inputs,omitempty"`
	Matcher           *Assertion       `json:"matcher,omitempty"`
	Scope             PredicateScope   `json:"scope"`
	TimeoutMs         int64            `json:"timeoutMs"`
	FreshnessMs       int64            `json:"freshnessMs"`
	RequiredAuthority string           `json:"requiredAuthority"`
}
type Constraints struct {
	AllowedOrigins           []string `json:"allowedOrigins,omitempty"`
	AllowedApps              []string `json:"allowedApps,omitempty"`
	FileRoots                []string `json:"fileRoots,omitempty"`
	AllowDuplicateAttachment bool     `json:"allowDuplicateAttachment"`
}
type RecoveryPolicy struct {
	MaxRepairs      int    `json:"maxRepairs"`
	MaxElapsedMs    int64  `json:"maxElapsedMs"`
	OnUnknownEffect string `json:"onUnknownEffect"`
}
type CheckpointPolicy struct {
	Name   string   `json:"name"`
	Levels []string `json:"levels"`
}
