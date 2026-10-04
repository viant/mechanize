package endly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// ResumeSnapshot contains only verified, serializable durable state. Completed
// IDs are original plan IDs; filtering never renumbers execution metadata.
type ResumeSnapshot struct {
	RunID, PlanID, ObjectiveID, Status string
	Revision                           int
	Plan                               model.Plan
	Inputs, Values                     map[string]model.Value
	Completed                          map[string]StepResult
}
type ResumeResult struct {
	RunID     string             `json:"runId"`
	SessionID string             `json:"sessionId"`
	Operation *manager.Operation `json:"operation"`
}

// Resume opens a context for trusted no-grant callers. Consent-bearing callers
// must first open and authorize a session, then use ResumeInSession; grants are
// never moved from their original session to an internally-created session.
func (r *Runtime) Resume(ctx context.Context, actor auth.Principal, runID string, expectedRevision int, expectedPlanID, expectedObjectiveID string) (result *ResumeResult, err error) {
	binding, _ := auth.ConsentBindingFromContext(ctx)
	if binding.GrantID != "" {
		return nil, errors.New("consent-bearing resume requires an existing authorized session")
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != actor.Namespace || actual.ClientID != actor.ClientID {
		return nil, auth.ErrUnauthorized
	}
	session, err := r.Open(ctx, "resume "+runID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = r.Close(context.WithoutCancel(ctx), session.SessionID)
		}
	}()
	return r.ResumeInSession(ctx, actual, session.SessionID, runID, expectedRevision, expectedPlanID, expectedObjectiveID)
}

// ResumeInSession admits durable work into a caller-owned authenticated session.
// The caller may grant consent for this session before dispatch. The trusted
// loader reconciles durable uncertainty, and the commit gate inhibits execution
// until the new run/operation correlation is confirmed. Endly schedules actions.
func (r *Runtime) ResumeInSession(ctx context.Context, actor auth.Principal, sessionID, runID string, expectedRevision int, expectedPlanID, expectedObjectiveID string) (*ResumeResult, error) {
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != actor.Namespace || actual.ClientID != actor.ClientID {
		return nil, auth.ErrUnauthorized
	}
	if _, err = r.authorize(ctx, sessionID); err != nil {
		return nil, err
	}
	// Capture only the verified request principal, never caller-supplied scopes.
	actor = actual
	binding, _ := auth.ConsentBindingFromContext(ctx)
	if binding.GrantID != "" && binding.SessionID != sessionID {
		return nil, errors.New("resume consent must name the owned session")
	}
	if runID == "" || expectedRevision <= 0 || expectedPlanID == "" || expectedObjectiveID == "" {
		return nil, errors.New("run, expected revision, plan and objective identity required")
	}
	if r.loadResume == nil || r.attachOperation == nil {
		return nil, errors.New("durable resume integration unavailable")
	}
	r.admission.Lock()
	defer r.admission.Unlock()
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	r.mu.RLock()
	previous := r.programs[runID]
	var previousOwner auth.Principal
	if previous != nil {
		previousOwner = r.principals[previous.owner]
	}
	r.mu.RUnlock()
	if previous != nil {
		if previousOwner.Namespace != actor.Namespace {
			return nil, auth.ErrUnauthorized
		}
		if previous.operationID == "" {
			return nil, errors.New("prior operation admission is unresolved")
		}
		operation, e := r.manager.GetOperation(previous.owner, previous.operationID)
		if e != nil {
			return nil, e
		}
		switch operation.Status {
		case manager.OperationFailed, manager.OperationCancelled, manager.OperationSucceeded:
		default:
			return nil, errors.New("live operation must reach a stopped boundary before resume")
		}
	}
	snapshot, err := r.loadResume(ctx, actor, runID, expectedRevision, expectedPlanID, expectedObjectiveID)
	if err != nil {
		return nil, err
	}
	if snapshot.RunID != runID || snapshot.Revision != expectedRevision || snapshot.PlanID != expectedPlanID || snapshot.ObjectiveID != expectedObjectiveID {
		return nil, errors.New("resume snapshot identity mismatch")
	}
	if err = snapshot.Plan.Validate(); err != nil {
		return nil, err
	}
	switch snapshot.Status {
	case "running", "paused", "new":
	default:
		return nil, errors.New("durable terminal run cannot be resumed")
	}
	// Validate durable tagged unions before JSON cloning: omitempty can erase
	// malformed empty fields. A resume must preserve the persisted input set;
	// defaults are resolved at initial admission, never added during recovery.
	for name, value := range snapshot.Inputs {
		if err = value.Validate(); err != nil {
			return nil, fmt.Errorf("resume input %s: %w", name, err)
		}
	}
	for name, definition := range snapshot.Plan.Inputs {
		value, present := snapshot.Inputs[name]
		if !present {
			if definition.Required {
				return nil, fmt.Errorf("required persisted input %s is missing", name)
			}
			continue
		}
		kind := value.Kind
		if kind == model.ReferenceValue {
			kind = value.Expected
			if kind == "" {
				kind = definition.Type
			}
		}
		if kind != definition.Type {
			return nil, fmt.Errorf("persisted input %s has incompatible type", name)
		}
	}
	for name, value := range snapshot.Values {
		if err = value.Validate(); err != nil {
			return nil, fmt.Errorf("resume value %s: %w", name, err)
		}
	}
	for stepID, completed := range snapshot.Completed {
		if completed.Value != nil {
			if err = completed.Value.Validate(); err != nil {
				return nil, fmt.Errorf("completed step %s value: %w", stepID, err)
			}
		}
	}
	// Detach all typed payloads from the loader's cache. Execution never changes
	// the immutable plan or aliases caller-owned business-key maps.
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(encoded, &snapshot); err != nil {
		return nil, err
	}
	stepIDs := make(map[string]bool, len(snapshot.Plan.Steps))
	for _, step := range snapshot.Plan.Steps {
		stepIDs[step.ID] = true
	}
	for stepID, completed := range snapshot.Completed {
		if !stepIDs[stepID] || completed.VerificationState != "verified" {
			return nil, errors.New("completed step absent from plan or unverified")
		}
	}
	values := map[string]model.Value{}
	for name, value := range snapshot.Inputs {
		// Older persisted references may omit Expected. Constrain the detached
		// execution value without changing the immutable loader snapshot.
		if definition, declared := snapshot.Plan.Inputs[name]; declared && value.Kind == model.ReferenceValue && value.Expected == "" {
			value.Expected = definition.Type
		}
		values["input."+name] = value
	}
	for _, binding := range snapshot.Plan.Bindings {
		if binding.Value != nil {
			values["binding."+binding.Name] = *binding.Value
		}
	}
	for name, value := range snapshot.Values {
		values["binding."+name] = value
	}
	pipeline := []map[string]any{}
	for index, step := range snapshot.Plan.Steps {
		if completed, ok := snapshot.Completed[step.ID]; ok {
			if completed.VerificationState != "verified" {
				return nil, errors.New("unverified completed step")
			}
			if step.Bind != "" {
				if completed.Value == nil {
					return nil, errors.New("completed step binding lacks durable typed evidence")
				}
				values["binding."+step.Bind] = *completed.Value
			}
			continue
		}
		pipeline = append(pipeline, map[string]any{"Key": fmt.Sprintf("step_%08d", index), "Value": map[string]any{"action": "mechanize:step", "request": map[string]any{"programId": runID, "stepId": step.ID}}})
	}
	if len(pipeline) == 0 {
		pipeline = append(pipeline, map[string]any{"Key": "complete", "Value": map[string]any{"action": "workflow:nop"}})
	}
	source, err := json.Marshal(map[string]any{"pipeline": pipeline})
	if err != nil {
		return nil, err
	}
	program := &program{resumed: true, requestPrincipal: actor, consentBinding: binding, planID: snapshot.PlanID, owner: sessionID, plan: snapshot.Plan, values: values, ready: make(chan struct{})}
	r.mu.Lock()
	r.programs[runID] = program
	r.mu.Unlock()
	// Failure releases this admission without closing the caller's session.
	// Keep a prior stopped mapping available for inspection or another resume.
	discardProgram := func() {
		r.mu.Lock()
		if previous == nil {
			delete(r.programs, runID)
		} else {
			r.programs[runID] = previous
		}
		r.mu.Unlock()
	}
	_, err = r.manager.LoadWorkflow(ctx, &manager.LoadWorkflowRequest{SessionID: sessionID, URL: runID + ".json", Name: runID, Alias: runID, Replace: true, Content: string(source), Format: "json"})
	if err != nil {
		discardProgram()
		return nil, err
	}
	operation, err := r.manager.StartWorkflow(&manager.RunWorkflowRequest{SessionID: sessionID, Workflow: runID, Tasks: "*"})
	if err != nil {
		discardProgram()
		return nil, err
	}
	r.mu.Lock()
	program.operationID = operation.ID
	r.mu.Unlock()
	err = r.attachOperation(ctx, actor, runID, snapshot.Revision, sessionID, operation.ID)
	program.admissionErr = err
	close(program.ready)
	if err != nil {
		// Stop is asynchronous. Retain the inhibited program so an action that
		// has not yet entered the service cannot resolve a prior ungated plan.
		// Its operation must reach a stopped boundary before another admission.
		r.manager.StopOperation(sessionID, operation.ID)
		return nil, err
	}
	r.observeCompletion(ctx, runID, program)
	return &ResumeResult{RunID: runID, SessionID: sessionID, Operation: operation}, nil
}

// RefreshVariables runs while StateMutationGuard holds admission. Values are
// runtime bindings; immutable plan inputs cannot be replaced by state patches.
func (r *Runtime) RefreshVariables(ctx context.Context, actor auth.Principal, runID string, variables map[string]model.Value) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != actor.Namespace {
		return auth.ErrUnauthorized
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.programs[runID]
	if !ok {
		return nil
	} // Process-death state is loaded on explicit resume.
	if r.principals[p.owner].Namespace != actor.Namespace {
		return auth.ErrUnauthorized
	}
	for name, value := range variables {
		found := false
		for _, binding := range p.plan.Bindings {
			if binding.Name == name {
				found = true
				break
			}
		}
		if !found {
			return errors.New("state variable does not name a plan binding")
		}
		if err = value.Validate(); err != nil {
			return err
		}
	}
	for name, value := range variables {
		p.values["binding."+name] = value
	}
	return nil
}
