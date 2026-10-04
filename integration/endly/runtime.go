// Package endly integrates the shared DSL with Endly's task and operation runtime.
// It does not implement another workflow scheduler.
package endly

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	endlylib "github.com/viant/endly"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

type StepResult struct {
	Value             *model.Value       `json:"value,omitempty"`
	Observation       *model.Observation `json:"observation,omitempty"`
	DispatchState     string             `json:"dispatchState"`
	VerificationState string             `json:"verificationState"`
	Postcondition     *objective.Result  `json:"postcondition,omitempty"`
}

// Execute handles a single action. Durable data operations belong in generated
// Datly components called by this implementation, not Endly lifecycle hooks.
type Execute func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error)
type program struct {
	requestPrincipal auth.Principal
	consentBinding   auth.ConsentBinding
	fingerprint      string
	operationID      string
	resumed          bool
	planID           string
	owner            string
	plan             model.Plan
	values           map[string]model.Value
	outputs          map[string]runtimeOutput
	ready            chan struct{}
	admissionErr     error
	objectiveReady   chan struct{}
	objectiveCancel  context.CancelFunc
	businessResult   BusinessResult
}
type PreparePlan func(context.Context, auth.Principal, string, string, model.Plan, map[string]model.Value) (string, error)
type LoadResume func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error)
type AttachOperation func(context.Context, auth.Principal, string, int, string, string) error
type Options struct {
	// OnSessionClose inhibits owner-bound capabilities before Endly closes the
	// session. It runs only after ownership is verified and admission is closed.
	OnSessionClose  func(context.Context, auth.Principal, string) error
	PreparePlan     PreparePlan
	LoadResume      LoadResume
	AttachOperation AttachOperation
	// AttachInitialOperation commits newly prepared run correlation before its
	// first step is released. The freshly prepared run has revision 1.
	AttachInitialOperation AttachOperation
	EvaluatePostcondition  EvaluatePostcondition
	CompleteObjective      CompleteObjective
}
type ExecutionMetadata struct {
	// Resumed and OperationID are supplied by the admitted Runtime program,
	// never workflow variables. Durable retry admission verifies correlation.
	Resumed     bool
	OperationID string
	RunID       string
	PlanID      string
	SessionID   string
	StepIndex   int
}
type executionKey struct{}

func ExecutionFromContext(ctx context.Context) (ExecutionMetadata, bool) {
	value, ok := ctx.Value(executionKey{}).(ExecutionMetadata)
	return value, ok
}

type requestKey struct{}

// StartPlanWithRequest makes repeated live requests return the same operation;
// the deterministic run identity also fences duplicates through Datly after restart.
func (r *Runtime) StartPlanWithRequest(ctx context.Context, session, requestID string, plan model.Plan, inputs map[string]model.Value) (*manager.Operation, error) {
	if requestID == "" || len(requestID) > 128 {
		return nil, errors.New("bounded clientRequestId required")
	}
	p, err := r.authorize(ctx, session)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal([]string{p.Namespace, session, requestID})
	sum := sha256.Sum256(raw)
	return r.StartPlan(context.WithValue(ctx, requestKey{}, hex.EncodeToString(sum[:])), session, plan, inputs)
}

type Runtime struct {
	onSessionClose         func(context.Context, auth.Principal, string) error
	closingSessions        map[string]bool
	admission              sync.Mutex
	prepare                PreparePlan
	loadResume             LoadResume
	attachOperation        AttachOperation
	attachInitialOperation AttachOperation
	evaluatePostcondition  EvaluatePostcondition
	completeObjective      CompleteObjective
	manager                *manager.Service
	execute                Execute
	mu                     sync.RWMutex
	principals             map[string]auth.Principal
	programs               map[string]*program
	stopping               bool
	shutdownOnce           sync.Once
	shutdownDone           chan struct{}
	shutdownErr            error
	completionWorkers      map[*completionWorker]bool
}

func New(execute Execute) (*Runtime, error) { return NewWithOptions(execute, Options{}) }
func NewWithOptions(execute Execute, options Options) (*Runtime, error) {
	if options.AttachInitialOperation != nil && options.PreparePlan == nil {
		return nil, errors.New("initial operation correlation requires durable plan preparation")
	}
	if execute == nil {
		return nil, errors.New("action executor required")
	}
	r := &Runtime{execute: execute, prepare: options.PreparePlan, loadResume: options.LoadResume, attachOperation: options.AttachOperation, attachInitialOperation: options.AttachInitialOperation, onSessionClose: options.OnSessionClose, closingSessions: map[string]bool{}, principals: map[string]auth.Principal{}, programs: map[string]*program{}, completionWorkers: map[*completionWorker]bool{}}
	r.execute = func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
		if r.isStopping() {
			return StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, ErrShutdownPending
		}
		return execute(ctx, p, step, values)
	}
	r.evaluatePostcondition = options.EvaluatePostcondition
	if options.CompleteObjective != nil {
		r.completeObjective = func(ctx context.Context, p auth.Principal, request CompletionRequest) (BusinessResult, error) {
			return r.completeOwned(ctx, p, request, options.CompleteObjective)
		}
	}
	r.manager = manager.New(func() endlylib.Manager {
		m := endlylib.New()
		m.Register(newService(r))
		return m
	}, manager.WithAllowedActions("mechanize:step", "workflow:run", "workflow:nop", "workflow:fail", "workflow:exit", "workflow:switch", "workflow:goto", "nop:*"))
	return r, nil
}
func (r *Runtime) Open(ctx context.Context, name string) (*manager.SessionInfo, error) {
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	r.admission.Lock()
	defer r.admission.Unlock()
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	p, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := r.manager.Open(ctx, &manager.OpenRequest{Name: name, Subject: p.Namespace})
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.principals[session.SessionID] = p
	r.mu.Unlock()
	return session, nil
}
func (r *Runtime) authorize(ctx context.Context, session string) (auth.Principal, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return auth.Principal{}, err
	}
	r.mu.RLock()
	owner, ok := r.principals[session]
	closing := r.closingSessions[session]
	r.mu.RUnlock()
	if !ok || closing || owner.Namespace != p.Namespace || (owner.ClientID != "" && owner.ClientID != p.ClientID) {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return owner, nil
}
func (r *Runtime) Close(ctx context.Context, session string) error {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	owner, ok := r.principals[session]
	if !ok || owner.Namespace != p.Namespace || owner.ClientID != "" && owner.ClientID != p.ClientID {
		r.mu.Unlock()
		return auth.ErrUnauthorized
	}
	r.closingSessions[session] = true
	r.mu.Unlock()
	if r.onSessionClose != nil {
		if err := r.onSessionClose(ctx, p, session); err != nil {
			return err
		}
	}
	if err := r.manager.Close(ctx, session); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.principals, session)
	delete(r.closingSessions, session)
	for id, p := range r.programs {
		if p.owner == session {
			if p.objectiveCancel != nil {
				p.objectiveCancel()
			}
			delete(r.programs, id)
		}
	}
	r.mu.Unlock()
	return nil
}

// StartPlan accepts validated immutable input. Persistence must commit before
// a production caller invokes this function; the runtime map is a live cache.
func (r *Runtime) StartPlan(ctx context.Context, session string, plan model.Plan, inputs map[string]model.Value) (*manager.Operation, error) {
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	r.admission.Lock()
	defer r.admission.Unlock()
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	principal, err := r.authorize(ctx, session)
	if err != nil {
		return nil, err
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if len(plan.Steps) == 0 || len(plan.Steps) > 2000 {
		return nil, errors.New("plan must contain 1...2000 steps")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	var copied model.Plan
	if err = json.Unmarshal(encoded, &copied); err != nil {
		return nil, err
	}
	// Validate declared inputs before plan preparation or Endly dispatch. Keep
	// legacy extra bindings, but never let them satisfy missing declared inputs.
	effectiveInputs := make(map[string]model.Value, len(inputs)+len(copied.Inputs))
	for name, value := range inputs {
		effectiveInputs[name] = value
	}
	for name, definition := range copied.Inputs {
		value, present := effectiveInputs[name]
		if !present && definition.Default != nil {
			value = *definition.Default
			effectiveInputs[name] = value
			present = true
		}
		if !present {
			if definition.Required {
				return nil, fmt.Errorf("required input %s is missing", name)
			}
			continue
		}
		kind := value.Kind
		if kind == model.ReferenceValue {
			if value.Expected == "" {
				value.Expected = definition.Type
				effectiveInputs[name] = value
			}
			kind = value.Expected
		}
		if kind != definition.Type {
			return nil, fmt.Errorf("input %s has incompatible type", name)
		}
	}
	// Validate before JSON cloning: omitempty must not erase invalid tagged
	// union fields (for example an empty object on a string value).
	for _, value := range effectiveInputs {
		if err := value.Validate(); err != nil {
			return nil, err
		}
	}
	// Detach nested caller input values before asynchronous execution and persist
	// the same resolved defaults used for dispatch and request deduplication.
	inputJSON, err := json.Marshal(effectiveInputs)
	if err != nil {
		return nil, err
	}
	effectiveInputs = nil
	if err = json.Unmarshal(inputJSON, &effectiveInputs); err != nil {
		return nil, err
	}
	values := make(map[string]model.Value, len(effectiveInputs))
	for name, v := range effectiveInputs {
		if err := v.Validate(); err != nil {
			return nil, err
		}
		values["input."+name] = v
	}
	for _, b := range copied.Bindings {
		if b.Value != nil {
			values["binding."+b.Name] = *b.Value
		}
	}
	body, _ := json.Marshal(struct {
		Plan   model.Plan
		Inputs map[string]model.Value
	}{copied, effectiveInputs})
	fingerprintSum := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(fingerprintSum[:])
	id, _ := ctx.Value(requestKey{}).(string)
	if id == "" {
		id = newID()
	}
	r.mu.RLock()
	previous := r.programs[id]
	r.mu.RUnlock()
	if previous != nil {
		if previous.owner != session || previous.fingerprint != fingerprint {
			return nil, errors.New("clientRequestId conflicts with a different request")
		}
		if previous.operationID == "" {
			return nil, errors.New("request has durable intent but operation admission is unresolved")
		}
		return r.manager.GetOperation(session, previous.operationID)
	}
	planID := id
	if r.prepare != nil {
		var err error
		planID, err = r.prepare(ctx, principal, id, session, copied, effectiveInputs)
		if err != nil {
			return nil, err
		}
	}
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	r.mu.Lock()
	binding, _ := auth.ConsentBindingFromContext(ctx)
	r.programs[id] = &program{requestPrincipal: principal, consentBinding: binding, fingerprint: fingerprint, planID: planID, owner: session, plan: copied, values: values}
	if r.attachInitialOperation != nil {
		r.programs[id].ready = make(chan struct{})
	}
	r.mu.Unlock()
	pipeline := []map[string]any{}
	for i, step := range copied.Steps {
		pipeline = append(pipeline, map[string]any{"Key": fmt.Sprintf("step_%08d", i), "Value": map[string]any{"action": "mechanize:step", "request": map[string]any{"programId": id, "stepId": step.ID}}})
	}
	source, err := json.Marshal(map[string]any{"pipeline": pipeline})
	if err != nil {
		return nil, err
	}
	_, err = r.manager.LoadWorkflow(ctx, &manager.LoadWorkflowRequest{SessionID: session, URL: id + ".json", Name: id, Alias: id, Content: string(source), Format: "json"})
	if err != nil {
		r.mu.Lock()
		delete(r.programs, id)
		r.mu.Unlock()
		return nil, err
	}
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	operation, err := r.manager.StartWorkflow(&manager.RunWorkflowRequest{SessionID: session, Workflow: id, Tasks: "*"})
	if err == nil {
		r.mu.Lock()
		r.programs[id].operationID = operation.ID
		r.mu.Unlock()
	}
	if err == nil {
		r.mu.RLock()
		p := r.programs[id]
		r.mu.RUnlock()
		if r.attachInitialOperation != nil {
			err = r.attachInitialOperation(ctx, principal, id, 1, session, operation.ID)
			if err == nil {
				err = ctx.Err()
			}
			p.admissionErr = err
			close(p.ready)
			if err != nil {
				// Retain the inhibited mapping: an ambiguous commit must never
				// admit a duplicate input or fall back to an ungated program.
				_, _ = r.manager.StopOperation(session, operation.ID)
				return nil, err
			}
		}
		r.observeCompletion(ctx, id, p)
	}
	return operation, err
}
func (r *Runtime) Status(ctx context.Context, session, operation string) (*manager.Operation, error) {
	if _, err := r.authorize(ctx, session); err != nil {
		return nil, err
	}
	return r.manager.GetOperation(session, operation)
}
func (r *Runtime) Wait(ctx context.Context, session, operation string) (*manager.Operation, error) {
	if _, err := r.authorize(ctx, session); err != nil {
		return nil, err
	}
	finished, err := r.manager.WaitOperation(ctx, session, operation)
	if err == nil {
		err = r.waitObjective(ctx, session, operation)
	}
	return finished, err
}
func (r *Runtime) Cancel(ctx context.Context, session, operation string) (*manager.Operation, error) {
	if _, err := r.authorize(ctx, session); err != nil {
		return nil, err
	}
	return r.manager.StopOperation(session, operation)
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system entropy unavailable")
	}
	return hex.EncodeToString(b[:])
}

// RunReference returns the stable durable run key for an owned live operation.
func (r *Runtime) RunReference(ctx context.Context, session, operation string) (string, error) {
	if _, err := r.authorize(ctx, session); err != nil {
		return "", err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, p := range r.programs {
		if p.owner == session && p.operationID == operation {
			return id, nil
		}
	}
	return "", errors.New("operation has no live run mapping; inspect durable state for recovery")
}

// StateMutationGuard inhibits new admissions while a terminal/new run's durable
// variables or checkpoint metadata are changed. It never clears in-flight effects.
func (r *Runtime) StateMutationGuard(ctx context.Context, actor auth.Principal, runID string) (func(), error) {
	if r.isStopping() {
		return nil, ErrShutdownPending
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != actor.Namespace {
		return nil, auth.ErrUnauthorized
	}
	r.admission.Lock()
	release := func() { r.admission.Unlock() }
	if r.isStopping() {
		release()
		return nil, ErrShutdownPending
	}
	r.mu.RLock()
	p, ok := r.programs[runID]
	var principal auth.Principal
	if ok {
		principal = r.principals[p.owner]
	}
	r.mu.RUnlock()
	if !ok {
		// A restarted runtime has no live context to inhibit. The generated
		// state component still authorizes the namespace and persisted run.
		return release, nil
	}
	if principal.Namespace != actor.Namespace {
		release()
		return nil, auth.ErrUnauthorized
	}
	if p.operationID != "" {
		operation, err := r.manager.GetOperation(p.owner, p.operationID)
		if err != nil {
			release()
			return nil, err
		}
		switch operation.Status {
		case manager.OperationCancelled, manager.OperationFailed, manager.OperationSucceeded:
		default:
			release()
			return nil, errors.New("run has not reached a safe stopped boundary")
		}
	}
	return release, nil
}

// QuiesceRun stops the live Endly operation and waits for its action/lifecycle
// completion. Durable pause publication is a separate guarded Datly operation.
func (r *Runtime) QuiesceRun(ctx context.Context, actor auth.Principal, runID string) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != actor.Namespace {
		return auth.ErrUnauthorized
	}
	r.mu.RLock()
	p, ok := r.programs[runID]
	var principal auth.Principal
	if ok {
		principal = r.principals[p.owner]
	}
	r.mu.RUnlock()
	if !ok || principal.Namespace != actor.Namespace {
		return auth.ErrUnauthorized
	}
	if p.operationID == "" {
		return nil
	}
	operation, err := r.manager.GetOperation(p.owner, p.operationID)
	if err != nil {
		return err
	}
	if operation.Status == manager.OperationQueued || operation.Status == manager.OperationRunning || operation.Status == manager.OperationCancelling {
		if _, err = r.manager.StopOperation(p.owner, p.operationID); err != nil {
			return err
		}
	}
	_, err = r.manager.WaitOperation(ctx, p.owner, p.operationID)
	return err
}

// CheckSession binds an enrolled client to the current live automation session.
func (r *Runtime) CheckSession(ctx context.Context, p auth.Principal, id string) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	_, err = r.authorize(ctx, id)
	return err
}

var ErrShutdownPending = errors.New("Endly owner shutdown is pending; execution cleanup requires attention")

type completionWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *Runtime) isStopping() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.stopping }

// completeOwned binds objective writes to owner shutdown even when the observer
// supplied WithoutCancel context for durable finalization. Joining this callback
// is mandatory before the host may close its Datly storage.
func (r *Runtime) completeOwned(ctx context.Context, p auth.Principal, request CompletionRequest, complete CompleteObjective) (BusinessResult, error) {
	owned, cancel := context.WithCancel(ctx)
	worker := &completionWorker{cancel: cancel, done: make(chan struct{})}
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		cancel()
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown", Reason: "owner shutdown inhibited objective completion"}, ErrShutdownPending
	}
	r.completionWorkers[worker] = true
	r.mu.Unlock()
	defer func() { cancel(); r.mu.Lock(); delete(r.completionWorkers, worker); close(worker.done); r.mu.Unlock() }()
	return complete(owned, p, request)
}

// Shutdown is lifecycle ownership, not a scheduler. Endly cancels and joins its
// operations. A noncooperative action retains session/program state and keeps
// this owner cleanup pending; a later call can observe its eventual completion.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		r.stopping = true
		r.shutdownDone = make(chan struct{})
		r.mu.Unlock()
		r.inhibitOwnedWork()
		go r.finishOwnedShutdown()
	})
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	r.mu.RLock()
	done := r.shutdownDone
	r.mu.RUnlock()
	select {
	case <-done:
		r.mu.RLock()
		err := r.shutdownErr
		r.mu.RUnlock()
		return err
	case <-ctx.Done():
		return errors.Join(ErrShutdownPending, ctx.Err(), &model.MechanizeError{Code: "shutdownPending", Stage: "shutdown", EffectState: "unknown", Message: "Owned Endly actions or objective writes have not stopped. Keep durable storage open and reconcile before declaring cleanup complete."})
	}
}

func (r *Runtime) inhibitOwnedWork() {
	r.mu.RLock()
	cancels := []context.CancelFunc{}
	owners := make([]string, 0, len(r.principals))
	for owner := range r.principals {
		owners = append(owners, owner)
	}
	for _, program := range r.programs {
		if program.objectiveCancel != nil {
			cancels = append(cancels, program.objectiveCancel)
		}
	}
	for worker := range r.completionWorkers {
		cancels = append(cancels, worker.cancel)
	}
	r.mu.RUnlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, owner := range owners {
		operations, err := r.manager.ListOperations(owner)
		if err != nil {
			continue
		}
		for _, operation := range operations.Operations {
			if operation.Status == manager.OperationQueued || operation.Status == manager.OperationRunning || operation.Status == manager.OperationCancelling {
				_, _ = r.manager.StopOperation(owner, operation.ID)
			}
		}
	}
}

func (r *Runtime) finishOwnedShutdown() {
	// Any admission that began before inhibition must finish its durable mapping
	// before the final owner snapshot. New Open/Start/Resume calls are inhibited.
	r.admission.Lock()
	r.inhibitOwnedWork()
	r.mu.RLock()
	owners := make([]string, 0, len(r.principals))
	for owner := range r.principals {
		owners = append(owners, owner)
	}
	objectives := []chan struct{}{}
	for _, program := range r.programs {
		if program.objectiveReady != nil {
			objectives = append(objectives, program.objectiveReady)
		}
	}
	workers := []chan struct{}{}
	for worker := range r.completionWorkers {
		workers = append(workers, worker.done)
	}
	r.mu.RUnlock()
	r.admission.Unlock()
	var failures []error
	for _, owner := range owners {
		operations, err := r.manager.ListOperations(owner)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, operation := range operations.Operations {
			_, err = r.manager.WaitOperation(context.Background(), owner, operation.ID)
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	for _, ready := range objectives {
		<-ready
	}
	for _, done := range workers {
		<-done
	}
	// manager.Close can block on execMu without honoring ctx. It is invoked only
	// after every actual operation and objective callback has joined above.
	if len(failures) == 0 {
		for _, owner := range owners {
			if err := r.manager.Close(context.Background(), owner); err != nil {
				failures = append(failures, err)
				continue
			}
			r.mu.Lock()
			delete(r.principals, owner)
			for id, program := range r.programs {
				if program.owner == owner {
					delete(r.programs, id)
				}
			}
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	r.shutdownErr = errors.Join(failures...)
	close(r.shutdownDone)
	r.mu.Unlock()
}
