package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/viant/mechanize/auth"
)

// Immutable signed enrollment, never a request-selected mode. The preparation
// executable has the same code role, but this branch exposes no commit path.
type migrationPreparationPlan struct {
	MutationExecutable    string `json:"mutationExecutable"`
	MutationRequirement   string `json:"mutationRequirement"`
	MutationSHA256        string `json:"mutationSHA256"`
	RuntimeManifestSHA256 string `json:"runtimeManifestSHA256"`
}

func (p *migrationPreparationPlan) valid() bool {
	return p != nil && migrationPackagedPath(p.MutationExecutable) && migrationWorkerExecutorPin.MatchString(p.MutationRequirement) && validMigrationID(p.MutationSHA256) && validMigrationID(p.RuntimeManifestSHA256)
}
func migrationPreparationIntent(config migrationWorkerConfig, digest string, plan migrationPreparationPlan) string {
	values := []string{"mechanize-main-window-upgrade-v1", plan.MutationExecutable, plan.MutationRequirement, plan.MutationSHA256, config.session, digest, plan.RuntimeManifestSHA256, migrationOptionsDigest(config.options)}
	raw, _ := json.Marshal(values)
	return migrationDigest(raw)
}

// Confined to the authenticated native pipe. Identity/policy metadata is not a
// general RPC response, a human approval, a key-read result, or a write permit.
type migrationPreparationEvidence struct {
	IntentSHA256          string              `json:"intentSHA256"`
	ConfigSHA256          string              `json:"configSHA256"`
	OptionsSHA256         string              `json:"optionsSHA256"`
	RuntimeManifestSHA256 string              `json:"runtimeManifestSHA256"`
	MutationRequirement   string              `json:"mutationRequirement"`
	Transition            migrationTransition `json:"transition"`
}
type migrationPreparationResponse struct {
	Version  int                           `json:"version"`
	ID       string                        `json:"id"`
	Session  string                        `json:"session"`
	Status   string                        `json:"status"`
	Identity []byte                        `json:"identity,omitempty"`
	Evidence *migrationPreparationEvidence `json:"evidence,omitempty"`
}
type migrationPreparationRuntime struct {
	authority migrationWorkerAuthority
	metadata  func(context.Context, migrationOptions) (*migrationPrepared, error)
	frozen    func(context.Context) error
	acquire   migrationInstallAcquire
}

// Uses only metadata reads and the existing placement lease. No journal/staging,
// native write executor or approval transport is reachable from this server.
func serveMigrationPreparation(ctx context.Context, channel io.ReadWriteCloser, config migrationWorkerConfig, digest string, plan migrationPreparationPlan, runtime migrationPreparationRuntime) error {
	if ctx == nil || channel == nil || !validMigrationBootstrap(config, digest) || config.expectedIdentity != nil || !plan.valid() || runtime.authority == nil || runtime.metadata == nil || runtime.frozen == nil || runtime.acquire == nil {
		if channel != nil {
			channel.Close()
		}
		return errMigrationUnavailable
	}
	defer channel.Close()
	authorized, err := runtime.authority(ctx)
	if err != nil || migrationContext(authorized) != nil {
		return errMigrationUnavailable
	}
	owner, err := auth.FromContext(authorized)
	if err != nil {
		return errMigrationUnavailable
	}
	deadline, ok := ctx.Deadline()
	actualDeadline, bounded := authorized.Deadline()
	if !ok || !bounded || actualDeadline.After(deadline) {
		return errMigrationUnavailable
	}
	stop := context.AfterFunc(authorized, func() { channel.Close() })
	defer stop()
	var check func() error
	var release func()
	defer func() {
		if release != nil {
			release()
		}
	}()
	preparedOnce := false
	seen := map[string]bool{}
	for count := 0; count < 2; count++ {
		request, e := readMigrationWorkerRequest(channel)
		if e != nil || request.Session != config.session || seen[request.ID] {
			return errMigrationUnavailable
		}
		seen[request.ID] = true
		// Reject mutation/verification/inspection verbs before any preparation IO.
		if request.Operation != "prepare" && request.Operation != "close" {
			return errMigrationUnavailable
		}
		current, e := runtime.authority(authorized)
		if e != nil || migrationContext(current) != nil {
			return errMigrationUnavailable
		}
		currentDeadline, bounded := current.Deadline()
		if !bounded || currentDeadline.After(actualDeadline) {
			return errMigrationUnavailable
		}
		principal, e := auth.FromContext(current)
		if e != nil || principal.Namespace != owner.Namespace || principal.ClientID != owner.ClientID {
			return errMigrationUnavailable
		}
		response := migrationPreparationResponse{Version: 1, ID: request.ID, Session: config.session, Status: "closed"}
		if request.Operation == "close" {
			if check != nil && check() != nil {
				return errMigrationUnavailable
			}
			return writeMigrationWorkerFrame(channel, response)
		}
		if preparedOnce {
			return errMigrationUnavailable
		}
		preparedOnce = true
		check, release, e = runtime.acquire(current)
		if e != nil || check == nil || release == nil || check() != nil || runtime.frozen(current) != nil {
			return errMigrationUnavailable
		}
		evidence, identity, e := prepareMigrationEvidence(current, config, digest, plan, runtime, check)
		if e != nil || check() != nil || migrationContext(current) != nil {
			return errMigrationUnavailable
		}
		fresh, e := runtime.authority(current)
		if e != nil || migrationContext(fresh) != nil {
			return errMigrationUnavailable
		}
		confirmed, e := auth.FromContext(fresh)
		freshDeadline, bounded := fresh.Deadline()
		if e != nil || confirmed.Namespace != owner.Namespace || confirmed.ClientID != owner.ClientID || !bounded || freshDeadline.After(currentDeadline) || check() != nil {
			return errMigrationUnavailable
		}
		response.Status = "prepared"
		response.Identity = identity
		response.Evidence = &evidence
		if writeMigrationWorkerFrame(channel, response) != nil {
			return errMigrationUnavailable
		}
	}
	return errMigrationUnavailable
}
func prepareMigrationEvidence(ctx context.Context, config migrationWorkerConfig, digest string, plan migrationPreparationPlan, runtime migrationPreparationRuntime, check func() error) (migrationPreparationEvidence, []byte, error) {
	fail := func() (migrationPreparationEvidence, []byte, error) {
		return migrationPreparationEvidence{}, nil, errMigrationUnavailable
	}
	if migrationContext(ctx) != nil || check() != nil || runtime.frozen(ctx) != nil {
		return fail()
	}
	first, err := runtime.metadata(ctx, config.options)
	if first != nil && first.dispose != nil {
		defer first.dispose()
	}
	if err != nil || first == nil || first.handle == nil || !validMasterIdentity(first.identity) || check() != nil || migrationContext(ctx) != nil {
		return fail()
	}
	// Both reads enforce the exact full old policy independently, and must refer
	// to the same persistent item. Neither asks Security.framework for key data.
	second, err := runtime.metadata(ctx, config.options)
	if second != nil && second.dispose != nil {
		defer second.dispose()
	}
	if err != nil || second == nil || second.handle == nil || !bytes.Equal(first.identity, second.identity) || check() != nil || runtime.frozen(ctx) != nil || migrationContext(ctx) != nil {
		return fail()
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail()
	}
	record := &migrationJournalRecord{state: migrationUnknown, transitionID: hex.EncodeToString(nonce[:]), optionsSHA256: migrationOptionsDigest(config.options), identity: bytes.Clone(first.identity)}
	// Reuse the existing generated transition binding format; no journal write.
	coordinator := migrationCoordinator{options: config.options, record: record}
	evidence := migrationPreparationEvidence{IntentSHA256: migrationPreparationIntent(config, digest, plan), ConfigSHA256: digest, OptionsSHA256: record.optionsSHA256, RuntimeManifestSHA256: plan.RuntimeManifestSHA256, MutationRequirement: plan.MutationRequirement, Transition: coordinator.transition()}
	return evidence, bytes.Clone(first.identity), nil
}
