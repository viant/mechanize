package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"sync"
	"unicode/utf8"

	"github.com/viant/mechanize/auth"
)

// This is a syntax restriction on a trusted enrollment input, not proof of peer
// identity. The exact role and hash must already be pinned by the installer.
// Neither a claimed PID/UID nor this string alone authenticates the parent.
var migrationBootstrapParentPin = regexp.MustCompile(`^identifier "com\.viant\.mechanize\.[a-z][a-z0-9-]{0,63}" and cdhash H"[a-f0-9]{40}"$`)

type migrationBootstrapFrame struct {
	Version                int    `json:"version"`
	Operation              string `json:"op"`
	Session                string `json:"session"`
	ConfigSHA256           string `json:"configSHA256"`
	CanonicalExecutable    string `json:"canonicalExecutable"`
	OldRequirement         string `json:"oldRequirement"`
	NewRequirement         string `json:"newRequirement"`
	Alias                  string `json:"alias"`
	Service                string `json:"service"`
	Account                string `json:"account"`
	WorkerRequirement      string `json:"workerRequirement"`
	ExpectedIdentity       []byte `json:"expectedIdentity,omitempty"`
	NewCanonicalExecutable string `json:"newCanonicalExecutable,omitempty"`
}

func migrationBootstrapWire(config migrationWorkerConfig, digest string) migrationBootstrapFrame {
	version := 1
	if config.options.newCanonicalExecutable != "" {
		version = 2
	}
	return migrationBootstrapFrame{Version: version, NewCanonicalExecutable: config.options.newCanonicalExecutable, Operation: "bootstrap", Session: config.session, ConfigSHA256: digest,
		CanonicalExecutable: config.options.canonicalExecutable, OldRequirement: config.options.oldRequirement, NewRequirement: config.options.newRequirement,
		Alias: config.options.alias, Service: config.options.item.Service, Account: config.options.item.Account, WorkerRequirement: config.executorRequirement,
		ExpectedIdentity: bytes.Clone(config.expectedIdentity)}
}
func validMigrationBootstrap(config migrationWorkerConfig, digest string) bool {
	return validMigrationOptions(config.options) && utf8.ValidString(config.options.canonicalExecutable) && utf8.ValidString(config.options.item.Account) && migrationWorkerExecutorPin.MatchString(config.executorRequirement) && validMigrationID(config.session) &&
		validMigrationID(digest) && (config.expectedIdentity == nil || validMasterIdentity(config.expectedIdentity))
}

// Private parent serializer. It produces public custody metadata only, never
// Scy credentials, native-human assertions, approval grants or policy handles.
func writeMigrationBootstrap(writer io.Writer, config migrationWorkerConfig, digest string) error {
	if !validMigrationBootstrap(config, digest) {
		return errMigrationUnavailable
	}
	return writeMigrationWorkerFrame(writer, migrationBootstrapWire(config, digest))
}

// Authenticate the ACTUAL already-enrolled parent/channel and its Scy admin
// authority against the exact trusted requirement before returning a context.
// Implementations must use qualified peer/admin verification; they must not
// construct NativeHuman authority from any bootstrap field or caller claim.
// The requirement argument comes solely from trusted constructor enrollment.
type migrationBootstrapAuthority func(context.Context, string) (context.Context, error)

type migrationBootstrapLoader struct {
	mu                sync.Mutex
	started           bool
	expected          migrationWorkerConfig
	configDigest      string
	parentRequirement string
	authority         migrationBootstrapAuthority
}

// No exported constructor, CLI, socket endpoint or live-file parser is provided.
// expected, digest, session and the parent pin must come from independently
// reviewed frozen enrollment OUTSIDE the wire decoder. Matching a wire-provided
// digest is never sufficient: every option is also compared to trusted expected.
func newMigrationBootstrapLoader(expected migrationWorkerConfig, digest, parentRequirement string, authority migrationBootstrapAuthority) (*migrationBootstrapLoader, error) {
	if !validMigrationBootstrap(expected, digest) || !migrationBootstrapParentPin.MatchString(parentRequirement) || authority == nil {
		return nil, errMigrationUnavailable
	}
	expected.expectedIdentity = bytes.Clone(expected.expectedIdentity)
	return &migrationBootstrapLoader{expected: expected, configDigest: digest, parentRequirement: parentRequirement, authority: authority}, nil
}
func (*migrationBootstrapLoader) String() string   { return "Keychain migration bootstrap" }
func (*migrationBootstrapLoader) GoString() string { return "Keychain migration bootstrap" }
func (*migrationBootstrapLoader) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}
func (b *migrationBootstrapLoader) authorize(parent context.Context) (context.Context, auth.Principal, func(), error) {
	if parent == nil || parent.Err() != nil {
		return nil, auth.Principal{}, nil, errMigrationUnavailable
	}
	deadline, bounded := parent.Deadline()
	if !bounded {
		return nil, auth.Principal{}, nil, errMigrationUnavailable
	}
	authorized, err := b.authority(parent, b.parentRequirement)
	if err != nil || parent.Err() != nil || migrationContext(authorized) != nil {
		return nil, auth.Principal{}, nil, errMigrationUnavailable
	}
	authorizedDeadline, _ := authorized.Deadline()
	if authorizedDeadline.After(deadline) {
		return nil, auth.Principal{}, nil, errMigrationUnavailable
	}
	principal, err := auth.FromContext(authorized)
	if err != nil {
		return nil, auth.Principal{}, nil, errMigrationUnavailable
	}
	ctx, cancel := context.WithCancel(authorized)
	stop := context.AfterFunc(parent, cancel)
	return ctx, principal, func() { stop(); cancel() }, nil
}

// Read exactly one bounded canonical frame. Successful loading leaves the
// private channel open for the worker; every refusal/cancellation closes it.
// Close must unblock the underlying transport's read. A configured process
// watchdog is still required for arbitrary native operations after bootstrap.
// The resulting config grants no authority: worker actions authenticate again.
func (b *migrationBootstrapLoader) load(parent context.Context, channel io.ReadWriteCloser) (migrationWorkerConfig, error) {
	if b == nil || channel == nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		_ = channel.Close()
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	b.started = true
	b.mu.Unlock()
	accepted := false
	defer func() {
		if !accepted {
			_ = channel.Close()
		}
	}()
	first, principal, releaseFirst, err := b.authorize(parent)
	if err != nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	defer releaseFirst()
	stopFirst := context.AfterFunc(first, func() { _ = channel.Close() })
	defer stopFirst()
	var frame migrationBootstrapFrame
	if readMigrationWorkerFrame(channel, &frame) != nil || migrationContext(first) != nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	// Authenticate again AFTER decoding, without forwarding any decoded field
	// into the authority callback. A different native administrator/client must
	// not complete another actor's bootstrap, even if both are authorized.
	second, current, releaseSecond, err := b.authorize(first)
	if err != nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	defer releaseSecond()
	stopSecond := context.AfterFunc(second, func() { _ = channel.Close() })
	defer stopSecond()
	if principal.Namespace != current.Namespace || principal.ClientID != current.ClientID || migrationContext(first) != nil || migrationContext(second) != nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	wanted := migrationBootstrapWire(b.expected, b.configDigest)
	decoded, _ := json.Marshal(frame)
	trusted, _ := json.Marshal(wanted)
	if !bytes.Equal(decoded, trusted) {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	// Return a copy of the TRUSTED configuration, rather than promoting fields
	// selected by the decoded object into installer or worker inputs.
	result := b.expected
	result.expectedIdentity = bytes.Clone(result.expectedIdentity)
	if migrationContext(second) != nil {
		return migrationWorkerConfig{}, errMigrationUnavailable
	}
	accepted = true
	return result, nil
}
