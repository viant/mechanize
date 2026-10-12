//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
char *mechanize_migration_own_requirement(void);
*/
import "C"

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	"golang.org/x/sys/unix"
)

// Descriptor-bound private reads: all ancestors reject symlinks; immediate
// directory is owned 0700, final file owned 0600/single-link. Data never leaves
// this process, and Scy receives pinned bytes rather than reopening a path.
func readMigrationPackagedResource(ref migrationPackagedResource) ([]byte, error) {
	if !migrationPackagedPath(ref.Path) || !validMigrationID(ref.SHA256) {
		return nil, errMigrationUnavailable
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	tree := &migrationDirectoryTree{root: root}
	defer tree.close()
	parent := root
	parts := strings.Split(strings.TrimPrefix(ref.Path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		fd, e := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, errMigrationUnavailable
		}
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || (info.Uid != 0 && info.Uid != uint32(os.Getuid())) {
			unix.Close(fd)
			return nil, errMigrationUnavailable
		}
		tree.links = append(tree.links, migrationDirectoryLink{parent: parent, name: part, descriptor: fd, original: info})
		parent = fd
	}
	if len(tree.links) == 0 {
		return nil, errMigrationUnavailable
	}
	directory := tree.links[len(tree.links)-1].original
	if directory.Uid != uint32(os.Getuid()) || directory.Mode&07777 != 0700 {
		return nil, errMigrationUnavailable
	}
	name := filepath.Base(ref.Path)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	file := os.NewFile(uintptr(fd), "private-migration-resource")
	defer file.Close()
	var before, after, entry unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Getuid()) || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Size <= 0 || before.Size > 1<<20 {
		return nil, errMigrationUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || tree.verify() != nil || unix.Fstat(fd, &after) != nil || unix.Fstatat(parent, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !migrationExecutableSame(before, after) || !migrationExecutableSame(before, entry) || migrationDigest(data) != ref.SHA256 {
		for i := range data {
			data[i] = 0
		}
		return nil, errMigrationUnavailable
	}
	return data, nil
}
func migrationPackagedVerifier(ctx context.Context, enrollment migrationPackagedEnrollment) (*auth.Verifier, error) {
	raw, err := readMigrationPackagedResource(enrollment.Config)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	// The complete existing broker configuration is digest-bound. Only these
	// fields are used; its unchanged identity policy and verifier scheme survive.
	var config struct {
		Keys           verifier.Config `json:"keys"`
		IdentityPolicy auth.Policy     `json:"identityPolicy"`
	}
	if json.Unmarshal(raw, &config) != nil || config.Keys.CertURL != "" {
		return nil, errMigrationUnavailable
	}
	pins := map[string]string{}
	for _, ref := range enrollment.Resources {
		pins[ref.Path] = ref.SHA256
	}
	resources := append([]*scy.Resource{}, config.Keys.RSA...)
	if config.Keys.HMAC != nil {
		resources = append(resources, config.Keys.HMAC)
	}
	for _, rule := range config.Keys.Rules {
		if rule == nil {
			return nil, errMigrationUnavailable
		}
		resources = append(resources, rule.RSA...)
		if rule.HMAC != nil {
			resources = append(resources, rule.HMAC)
		}
	}
	used := map[string]bool{}
	defer func() {
		for _, r := range resources {
			if r != nil {
				for i := range r.Data {
					r.Data[i] = 0
				}
				r.Data = nil
			}
		}
	}()
	for _, r := range resources {
		// Dynamic/encrypted/fallback resources need a separately reviewed custody
		// adapter; do not fetch secrets from environment, URLs or inline config.
		if r == nil || r.Key != "" || r.Fallback != nil || len(r.Data) != 0 || !migrationPackagedPath(r.URL) || pins[r.URL] == "" {
			return nil, errMigrationUnavailable
		}
		data, e := readMigrationPackagedResource(migrationPackagedResource{r.URL, pins[r.URL]})
		if e != nil {
			return nil, errMigrationUnavailable
		}
		r.Data = data
		used[r.URL] = true
	}
	if len(used) != len(pins) || ctx.Err() != nil {
		return nil, errMigrationUnavailable
	}
	result, err := auth.NewVerifier(ctx, &config.Keys, config.IdentityPolicy)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	return result, nil
}

// RunPackagedCustodyMigration is for the separately signed worker executable.
// Enrollment is linker-embedded, not argv/env/stdin. Runtime self-role checks and
// authenticated console peer/admin checks are mandatory even for direct calls.
func RunPackagedCustodyMigration(ctx context.Context, encoded string, channel io.ReadWriteCloser, descriptor *os.File) error {
	if ctx == nil || channel == nil || descriptor == nil {
		return errMigrationUnavailable
	}
	defer channel.Close()
	defer descriptor.Close()
	bounded, cancel := context.WithTimeout(ctx, 240*time.Second)
	defer cancel()
	// Also terminate blocked private IO; the parent owns the hard process watchdog.
	stop := context.AfterFunc(bounded, func() { channel.Close(); descriptor.Close() })
	defer stop()
	own := C.mechanize_migration_own_requirement()
	if own == nil {
		return errMigrationUnavailable
	}
	requirement := C.GoString(own)
	C.free(unsafe.Pointer(own))
	if !nativeMigrationExecutorMatches(requirement) {
		return errMigrationUnavailable
	}
	enrolled, err := decodeMigrationPackagedEnrollment(encoded)
	if err != nil || *enrolled.ExpectedUID != uint32(os.Getuid()) {
		return errMigrationUnavailable
	}
	if !migrationConsoleDescriptor(descriptor) {
		return errMigrationUnavailable
	}
	connection, err := net.FileConn(descriptor)
	if err != nil {
		return errMigrationUnavailable
	}
	console, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return errMigrationUnavailable
	}
	defer console.Close()
	deadline, _ := bounded.Deadline()
	if console.SetDeadline(deadline) != nil {
		return errMigrationUnavailable
	}
	peer, err := nativepeer.NewVerifier(nativepeer.Options{ExpectedUID: *enrolled.ExpectedUID, DesignatedRequirement: enrolled.ConsoleRequirement})
	if err == nil {
		peer = migrationApprovalConsolePeer(peer, enrolled.ApprovalConsole)
	}
	if err != nil || peer(console) != nil {
		return errMigrationUnavailable
	}
	configuration, err := readMigrationPackagedResource(enrolled.Config)
	if err != nil {
		return errMigrationUnavailable
	}
	matches := migrationEnrollmentMatchesConfiguration(enrolled, configuration)
	for i := range configuration {
		configuration[i] = 0
	}
	if !matches || peer(console) != nil || bounded.Err() != nil {
		return errMigrationUnavailable
	}
	// One non-consuming receive establishes this inherited endpoint's current
	// kernel peer/audit identity before the console authenticates the child.
	// No data may precede readiness; EOF, bytes, or any other error refuse it.
	if !migrationPrimeConsolePeer(console) {
		return errMigrationUnavailable
	}
	// Fixed progress marker on a separate pipe; credentials remain on fd3.
	ready := os.NewFile(4, "private-migration-ready")
	if ready == nil {
		return errMigrationUnavailable
	}
	info, readyErr := ready.Stat()
	if readyErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
		ready.Close()
		return errMigrationUnavailable
	}
	count, readyErr := ready.Write([]byte("MMREADY1"))
	ready.Close()
	if readyErr != nil || count != 8 {
		return errMigrationUnavailable
	}
	authorityVerifier, err := migrationPackagedVerifier(bounded, enrolled)
	if err != nil {
		return errMigrationUnavailable
	}
	options := migrationOptions{canonicalExecutable: enrolled.CanonicalExecutable, newCanonicalExecutable: enrolled.NewCanonicalExecutable, oldRequirement: enrolled.OldRequirement, newRequirement: enrolled.NewRequirement, alias: enrolled.Alias, item: Item{Service: enrolled.Service, Account: enrolled.Account}}
	entry := migrationEntryEnrollment{worker: migrationWorkerConfig{options: options, executorRequirement: requirement, session: enrolled.Session, expectedIdentity: enrolled.ExpectedIdentity}, configDigest: enrolled.Config.SHA256, parent: migrationNativeEnrollment{approvalConsole: enrolled.ApprovalConsole, parentRequirement: enrolled.ConsoleRequirement, expectedUID: *enrolled.ExpectedUID, namespace: enrolled.Namespace, clientID: enrolled.ClientID, deadline: deadline}, journalRoot: enrolled.JournalRoot}
	if enrolled.Preparation != nil {
		return serveMigrationPreparationEntry(bounded, channel, console, entry, enrolled, authorityVerifier)
	}
	if enrolled.InstallPlan != nil {
		return servePackagedInstallerEntry(bounded, channel, console, entry, enrolled, authorityVerifier)
	}
	if enrolled.ExpectedIdentity != nil {
		return serveMigrationEntry(bounded, channel, console, entry, authorityVerifier, nil)
	}
	// Mutation is exclusively the server-enforced installer mode. The historical
	// raw prepare/verify/commit worker remains private fixture infrastructure.
	return errMigrationUnavailable
}

// A single peek must find no data. It establishes inherited socket ownership
// without consuming a credential frame or transmitting any socket bytes.
func migrationPrimeConsolePeer(console *net.UnixConn) bool {
	if console == nil {
		return false
	}
	raw, err := console.SyscallConn()
	if err != nil {
		return false
	}
	noData := false
	err = raw.Control(func(fd uintptr) {
		buffer := make([]byte, 1)
		_, _, receiveErr := unix.Recvfrom(int(fd), buffer, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		noData = receiveErr == unix.EAGAIN || receiveErr == unix.EWOULDBLOCK
		buffer[0] = 0
	})
	return err == nil && noData
}
