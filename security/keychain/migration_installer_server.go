//go:build darwin || linux

package keychain

import (
	"context"
	"github.com/viant/mechanize/session"
	"io"
	"os"
	"time"

	"github.com/viant/mechanize/auth"
)

type migrationInstallerRequest struct {
	Version                  int                           `json:"version"`
	ID                       string                        `json:"id"`
	Session                  string                        `json:"session"`
	Operation                string                        `json:"op"`
	Preparation              *migrationPreparationEvidence `json:"preparation,omitempty"`
	Identity                 []byte                        `json:"identity,omitempty"`
	DeadlineUnixMilliseconds int64                         `json:"deadlineUnixMilliseconds,omitempty"`
}
type migrationInstallerRuntimeReceipt struct {
	BrokerPID        int    `json:"brokerPID"`
	BrokerStartToken string `json:"brokerStartToken"`
}
type migrationInstallerResponse struct {
	Version      int                               `json:"version"`
	ID           string                            `json:"id"`
	Session      string                            `json:"session"`
	Status       string                            `json:"status"`
	TransitionID string                            `json:"transitionId,omitempty"`
	Scope        string                            `json:"scope,omitempty"`
	Runtime      *migrationInstallerRuntimeReceipt `json:"runtime,omitempty"`
}
type migrationInstallerSession struct {
	composition         *migrationComposition
	expectedPreparation migrationPreparationPlan
	frozen              func(context.Context) error
	finalize            func(context.Context, migrationCompositionReceipt) (session.ProcessIdentity, error)
}

// Factory is a trusted signed-entry dependency, never a field in the request.
type migrationInstallerSessionFactory func(context.Context) (*migrationInstallerSession, error)

// Closed installer mode admits one execute/adopt, optional inspect-only reconcile,
// one terminal console finalization and close. Raw worker mutation verbs cannot
// skip configuration/artifact staging or manufacture approval/journal receipts.
func serveMigrationInstaller(ctx context.Context, channel io.ReadWriteCloser, config migrationWorkerConfig, authority migrationWorkerAuthority, factory migrationInstallerSessionFactory) error {
	if ctx == nil || channel == nil || authority == nil || factory == nil || !validMigrationBootstrap(config, migrationOptionsDigest(config.options)) || config.expectedIdentity != nil {
		if channel != nil {
			channel.Close()
		}
		return errMigrationUnavailable
	}
	defer channel.Close()
	current, err := authority(ctx)
	if err != nil || migrationContext(current) != nil {
		return errMigrationUnavailable
	}
	outer, ok := ctx.Deadline()
	limit, bounded := current.Deadline()
	owner, err := auth.FromContext(current)
	if err != nil || !ok || !bounded || limit.After(outer) {
		return errMigrationUnavailable
	}
	stop := context.AfterFunc(current, func() { channel.Close() })
	defer stop()
	var active *migrationInstallerSession
	var outcome migrationCompositionReceipt
	executed, finalized := false, false
	seen := map[string]bool{}
	for count := 0; count < 4; count++ {
		var request migrationInstallerRequest
		if readMigrationWorkerFrame(channel, &request) != nil || request.Version != 1 || !validMigrationID(request.ID) || request.Session != config.session || seen[request.ID] {
			return errMigrationUnavailable
		}
		seen[request.ID] = true
		fresh, e := authority(current)
		if e != nil || migrationContext(fresh) != nil {
			return errMigrationUnavailable
		}
		principal, e := auth.FromContext(fresh)
		deadline, bounded := fresh.Deadline()
		if e != nil || principal.Namespace != owner.Namespace || principal.ClientID != owner.ClientID || !bounded || deadline.After(limit) {
			return errMigrationUnavailable
		}
		current = fresh
		limit = deadline
		response := migrationInstallerResponse{Version: 1, ID: request.ID, Session: config.session, Status: "unavailable"}
		switch request.Operation {
		case "execute":
			if executed || request.Preparation == nil || !validMasterIdentity(request.Identity) || request.DeadlineUnixMilliseconds <= 0 {
				return errMigrationUnavailable
			}
			executed = true
			requested := time.UnixMilli(request.DeadlineUnixMilliseconds)
			if !requested.After(time.Now()) {
				return errMigrationUnavailable
			}
			if requested.After(limit) {
				requested = limit
			}
			active, e = factory(current)
			if e != nil || active == nil || active.composition == nil || active.frozen == nil || active.finalize == nil || request.Preparation.RuntimeManifestSHA256 != active.expectedPreparation.RuntimeManifestSHA256 {
				return errMigrationUnavailable
			}
			adopted, cancel, e := bindMigrationPreparation(current, active.composition, active.expectedPreparation, *request.Preparation, request.Identity, requested, active.frozen)
			if e != nil {
				return errMigrationUnavailable
			}
			defer cancel()
			current = adopted
			limit = requested
			stopped := context.AfterFunc(current, func() { channel.Close() })
			defer stopped()
			outcome, e = active.composition.execute(current)
			response.Status = string(outcome.State)
			response.TransitionID = outcome.TransitionID
			response.Scope = outcome.Scope
			if e == nil && outcome.State != migrationVerified {
				return errMigrationUnavailable
			}
		case "reconcile":
			if !executed || active == nil || request.Preparation != nil || request.Identity != nil || request.DeadlineUnixMilliseconds != 0 {
				return errMigrationUnavailable
			}
			outcome, e = active.composition.reconcile(current)
			response.Status = string(outcome.State)
			response.TransitionID = outcome.TransitionID
			response.Scope = outcome.Scope
		case "finalize":
			if !executed || finalized || active == nil || outcome.State != migrationVerified || request.Preparation != nil || request.Identity != nil || request.DeadlineUnixMilliseconds != 0 {
				return errMigrationUnavailable
			}
			finalized = true
			identity, finalErr := active.finalize(current, outcome)
			if finalErr != nil || identity.PID <= 0 || identity.StartToken == "" || identity.UID != uint32(os.Getuid()) || identity.Executable != config.options.destinationExecutable() {
				response.Status = "unknown"
			} else {
				response.Status = "verified"
				response.Runtime = &migrationInstallerRuntimeReceipt{BrokerPID: identity.PID, BrokerStartToken: identity.StartToken}
			}
			response.TransitionID = outcome.TransitionID
			response.Scope = "runtime-artifacts"
		case "close":
			if request.Preparation != nil || request.Identity != nil || request.DeadlineUnixMilliseconds != 0 {
				return errMigrationUnavailable
			}
			response.Status = "closed"
			return writeMigrationWorkerFrame(channel, response)
		default:
			return errMigrationUnavailable
		}
		if writeMigrationWorkerFrame(channel, response) != nil {
			return errMigrationUnknown
		}
	}
	return errMigrationUnavailable
}
