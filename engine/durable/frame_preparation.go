package durable

import (
	"context"
	"errors"
	"time"

	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
)

// PrepareWindowFrameDispatch materializes only fixed generated contracts before
// collecting a thirty-second frame permit. It creates no plan, run or intent and
// accepts no caller-selected component. Cold metadata never spends permit TTL.
func (b *Builder) PrepareWindowFrameDispatch(ctx context.Context, p auth.Principal) error {
	actual, err := auth.FromContext(ctx)
	if b == nil || err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || actual.ClientID == "" || !actual.HasScope("desktop:control") || !actual.HasScope("desktop:observe") {
		return auth.ErrUnauthorized
	}
	if _, held := ctx.Value(heldUserLockKey{}).(*heldUserLock); held {
		return errors.New("frame metadata preparation cannot nest inside durable dispatch")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, user, err := b.bound(ctx, actual, 0)
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	for _, target := range []struct{ pkg, name string }{
		{"publishplan", "PublishPlanRevision"}, {"createrun", "CreateRun"}, {"loadrun", "LoadRun"}, {"attachoperation", "AttachOperation"}, {"beginattempt", "BeginAttempt"}, {"commitoutcome", "CommitOutcome"}, {"publishartifact", "PublishArtifact"}, {"transitionrun", "TransitionRun"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		bounded, stop := context.WithTimeout(ctx, 30*time.Second)
		err = user.server.PrepareComponent(bounded, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + target.pkg, Name: target.name})
		stop()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}
