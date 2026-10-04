// Package durable composes generated Datly use cases with one external action.
// It owns no SQL, writer plumbing, workflow scheduler, or data repository.
package durable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/createrun"
	"github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/publishplan"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/xdatly/handler"
)

var ErrNeedsReconciliation = errors.New("durable effect is unresolved; reconciliation required before dispatch")

type Options struct {
	ObjectiveEvaluator      *objective.Evaluator
	SourceRoot, StorageRoot string
	MaxUsers                int
	// LeaseEpoch must return the currently held broker fence for this principal.
	LeaseEpoch func(context.Context, auth.Principal) (int, error)
	// PrepareStepAuthority pins the executor for the exact immutable step before
	// its intent is committed. Native physical fences and browser channel epochs
	// are separate authority sources. Nil retains the native lease callback.
	PrepareStepAuthority func(context.Context, auth.Principal, model.Step) (context.Context, int, error)
	// StateMutationGuard holds paused/new run admission through durable commit and runtime refresh.
	StateMutationGuard func(context.Context, auth.Principal, string) (func(), error)
	// RefreshVariables refreshes live Endly bindings after confirmed state commit,
	// while StateMutationGuard still inhibits admission. Nil supports durable-only contexts.
	RefreshVariables func(context.Context, auth.Principal, string, map[string]model.Value) error
	// VerifyArtifact verifies immutable bytes in the principal-owned artifact root.
	VerifyArtifact func(context.Context, auth.Principal, data.ArtifactReference) error
	// ReconciliationGuard inhibits overlapping execution through late evidence
	// evaluation and commit. It must independently prove the executor stopped.
	ReconciliationGuard func(context.Context, auth.Principal, string) (func() error, error)
	// ResolveReconciliation is trusted host enrollment, never a caller predicate.
	ResolveReconciliation func(context.Context, auth.Principal, ReconciliationContext) (ReconciliationContract, error)
}
type userHost struct {
	server *standalone.Server
	mu     sync.Mutex
}
type Builder struct {
	options  Options
	dispatch integration.Execute
	mu       sync.Mutex
	users    map[string]*userHost
	closed   bool
}

func New(options Options, dispatch integration.Execute) (*Builder, error) {
	if options.SourceRoot == "" || options.StorageRoot == "" || options.LeaseEpoch == nil || dispatch == nil {
		return nil, errors.New("source/storage roots, trusted lease callback and action executor required")
	}
	if options.MaxUsers <= 0 {
		options.MaxUsers = 16
	}
	return &Builder{options: options, dispatch: dispatch, users: map[string]*userHost{}}, nil
}
func (b *Builder) bound(ctx context.Context, p auth.Principal, epoch int) (context.Context, *userHost, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace {
		return nil, nil, auth.ErrUnauthorized
	}
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
	if err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil, errors.New("durable host closed")
	}
	if user := b.users[p.Namespace]; user != nil {
		return ctx, user, nil
	}
	if len(b.users) >= b.options.MaxUsers {
		return nil, nil, errors.New("per-user Datly host capacity reached")
	}
	server, err := host.Open(ctx, b.options.SourceRoot, b.options.StorageRoot, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
	if err != nil {
		return nil, nil, err
	}
	user := &userHost{server: server}
	b.users[p.Namespace] = user
	return ctx, user, nil
}
func (b *Builder) Close(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	users := b.users
	b.users = nil
	b.mu.Unlock()
	var failures []error
	for _, user := range users {
		user.mu.Lock()
		failures = append(failures, user.server.Shutdown(ctx))
		user.mu.Unlock()
	}
	return errors.Join(failures...)
}
func pointer[T any](value T) *T { return &value }
func key(parts ...string) string {
	raw, _ := json.Marshal(parts)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func invoke(ctx context.Context, s *standalone.Server, pkg, name, method string, input any, requireCommit bool) (any, error) {
	var outcome handler.Outcome
	result, err := s.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(v handler.Outcome) { outcome = v }})
	if err != nil {
		return nil, err
	}
	if requireCommit && !outcome.CommitConfirmed() {
		return nil, errors.New("Datly transaction commit is not confirmed")
	}
	return result, nil
}

// PreparePlan is directly installed as Endly's preparation callback. Typed
// input values are JSON data, never interpolated workflow or executable text.
func (b *Builder) PreparePlan(ctx context.Context, p auth.Principal, runID, sessionID string, plan model.Plan, inputs map[string]model.Value) (string, error) {
	if err := plan.Validate(); err != nil {
		return "", err
	}
	if runID == "" || sessionID == "" {
		return "", errors.New("run and session identity required")
	}
	for _, v := range inputs {
		if err := v.Validate(); err != nil {
			return "", err
		}
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return "", err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	content, err := json.Marshal(struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}{plan, inputs})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	planID := key("plan", runID, hash)
	revision := &publishplan.PlanRevision{}
	revision.SetNamespace(pointer(p.Namespace))
	revision.SetId(pointer(planID))
	revision.SetObjectiveId(pointer(runID))
	revision.SetContentHash(pointer(hash))
	revision.SetContentJson(pointer(string(content)))
	revision.SetCreatedAt(pointer(now()))
	publish := &publishplan.PublishPlanRevisionInput{}
	publish.SetNamespace(p.Namespace)
	publish.SetPublishPlanRevision([]*publishplan.PlanRevision{revision})
	if _, err = invoke(ctx, user.server, "publishplan", "PublishPlanRevision", "POST", publish, true); err != nil {
		return "", err
	}
	run := &createrun.Run{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer(runID))
	run.SetPlanId(pointer(planID))
	run.SetStatus(pointer("running"))
	run.SetRevision(pointer(1))
	run.SetEndlySessionId(pointer(sessionID))
	run.SetCreatedAt(pointer(now()))
	run.SetUpdatedAt(pointer(now()))
	create := &createrun.CreateRunInput{}
	create.SetNamespace(p.Namespace)
	create.SetCreateRun([]*createrun.Run{run})
	if _, err = invoke(ctx, user.server, "createrun", "CreateRun", "POST", create, true); err != nil {
		return "", err
	}
	return planID, nil
}
func load(ctx context.Context, s *standalone.Server, p auth.Principal, id string) (*loadrun.Run, error) {
	input := &loadrun.LoadRunInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(id)
	result, err := invoke(ctx, s, "loadrun", "LoadRun", "GET", input, false)
	if err != nil {
		return nil, err
	}
	output, ok := result.(*loadrun.LoadRunOutput)
	if !ok || len(output.Data) != 1 {
		return nil, errors.New("authorized durable run not found")
	}
	return output.Data[0], nil
}
