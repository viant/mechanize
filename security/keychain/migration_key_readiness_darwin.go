//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>
static int readiness_static(const char *path,const char *rule) {
 CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),false);if(!url)return 0;
 SecStaticCodeRef code=NULL;OSStatus status=SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&code);CFRelease(url);if(status!=errSecSuccess)return 0;
 CFStringRef text=CFStringCreateWithCString(NULL,rule,kCFStringEncodingUTF8);SecRequirementRef requirement=NULL;
 status=text?SecRequirementCreateWithString(text,kSecCSDefaultFlags,&requirement):errSecParam;if(text)CFRelease(text);
 if(status==errSecSuccess)status=SecStaticCodeCheckValidity(code,kSecCSStrictValidate|kSecCSCheckAllArchitectures,requirement);
 if(requirement)CFRelease(requirement);CFRelease(code);return status==errSecSuccess;
}
static int readiness_pid(int pid,const char *rule) {
 CFNumberRef number=CFNumberCreate(NULL,kCFNumberIntType,&pid);if(!number)return 0;
 const void *keys[]={kSecGuestAttributePid};const void *values[]={number};CFDictionaryRef attributes=CFDictionaryCreate(NULL,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFRelease(number);if(!attributes)return 0;
 SecCodeRef code=NULL;OSStatus status=SecCodeCopyGuestWithAttributes(NULL,attributes,kSecCSDefaultFlags,&code);CFRelease(attributes);if(status!=errSecSuccess)return 0;
 CFStringRef text=CFStringCreateWithCString(NULL,rule,kCFStringEncodingUTF8);SecRequirementRef requirement=NULL;status=text?SecRequirementCreateWithString(text,kSecCSDefaultFlags,&requirement):errSecParam;if(text)CFRelease(text);
 if(status==errSecSuccess)status=SecCodeCheckValidity(code,kSecCSStrictValidate,requirement);if(requirement)CFRelease(requirement);CFRelease(code);return status==errSecSuccess;
}
*/
import "C"

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/viant/mechanize/session"
)

func nativeReadinessStatic(path, requirement string) bool {
	p, r := C.CString(path), C.CString(requirement)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(r))
	return C.readiness_static(p, r) == 1
}
func nativeReadinessPID(pid int, requirement string) bool {
	if pid <= 0 || int64(pid) > 1<<31-1 {
		return false
	}
	r := C.CString(requirement)
	defer C.free(unsafe.Pointer(r))
	return C.readiness_pid(C.int(pid), r) == 1
}

type readinessOutput struct {
	mu      sync.Mutex
	data    bytes.Buffer
	maximum int
}

func (w *readinessOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.data.Len()+len(p) > w.maximum {
		return 0, errors.New("bounded diagnostic output exceeded")
	}
	return w.data.Write(p)
}
func (w *readinessOutput) take() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := bytes.Clone(w.data.Bytes())
	raw := w.data.Bytes()
	for i := range raw {
		raw[i] = 0
	}
	w.data.Reset()
	return result
}

type nativeMigrationReadinessSystem struct{}

func readinessCommand(ctx context.Context, path string, args []string, limit int) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	command.Stdin = nil
	command.Stderr = io.Discard
	out := &readinessOutput{maximum: limit}
	command.Stdout = out
	if command.Run() != nil {
		data := out.take()
		for i := range data {
			data[i] = 0
		}
		return nil, errMigrationUnavailable
	}
	return out.take(), nil
}
func (nativeMigrationReadinessSystem) job(ctx context.Context, service string, job migrationLaunchdJob, definition string) (int, error) {
	raw, err := readinessCommand(ctx, "/bin/launchctl", []string{"print", service}, 65536)
	if err != nil {
		return 0, err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	return decodeMigrationLaunchdStatus(raw, service, job, definition)
}
func (nativeMigrationReadinessSystem) kickstart(ctx context.Context, service string) error {
	raw, err := readinessCommand(ctx, "/bin/launchctl", []string{"kickstart", service}, 4096)
	for i := range raw {
		raw[i] = 0
	}
	return err
}
func (nativeMigrationReadinessSystem) inspect(ctx context.Context, pid int, path string) (session.ProcessIdentity, error) {
	actual, alive, err := session.InspectProcess(pid)
	if err != nil || !alive || actual.PID != pid || actual.UID != uint32(os.Getuid()) || actual.Executable != path || actual.StartToken == "" || migrationContext(ctx) != nil {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	return actual, nil
}
func (s nativeMigrationReadinessSystem) verifyProcess(ctx context.Context, expected session.ProcessIdentity, requirement string) error {
	if !migrationRequirement.MatchString(requirement) && !runtimeRoleRequirement("console", requirement) {
		return errMigrationUnavailable
	}
	before, err := s.inspect(ctx, expected.PID, expected.Executable)
	if err != nil || before != expected || !nativeReadinessPID(expected.PID, requirement) {
		return errMigrationUnavailable
	}
	after, err := s.inspect(ctx, expected.PID, expected.Executable)
	if err != nil || after != expected {
		return errMigrationUnavailable
	}
	return nil
}
func (s nativeMigrationReadinessSystem) terminate(ctx context.Context, service string, owned session.ProcessIdentity, requirement string) error {
	if s.verifyProcess(ctx, owned, requirement) != nil {
		return errMigrationUnavailable
	}
	raw, err := readinessCommand(ctx, "/bin/launchctl", []string{"kill", "SIGTERM", service}, 4096)
	for i := range raw {
		raw[i] = 0
	}
	return err
}
func (s nativeMigrationReadinessSystem) diagnostic(ctx context.Context, bundle, requirement string, broker session.ProcessIdentity) ([]byte, error) {
	if !runtimeRoleRequirement("console", requirement) || !nativeReadinessStatic(bundle, requirement) {
		return nil, errMigrationUnavailable
	}
	executable := filepath.Join(bundle, "Contents/MacOS/MechanizeConsent")
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "--check-vault", "--broker-pid", strconv.Itoa(broker.PID), "--broker-start", broker.StartToken)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if home, err := migrationUserHomeDir(); err == nil {
		command.Env = append(command.Env, "HOME="+home)
	}
	out := &readinessOutput{maximum: 4096}
	command.Stdout = out
	command.Stderr = io.Discard
	command.Stdin = nil
	if command.Start() != nil {
		return nil, errMigrationUnavailable
	}
	identity, err := s.inspect(ctx, command.Process.Pid, executable)
	if err != nil || s.verifyProcess(ctx, identity, requirement) != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		raw := out.take()
		for i := range raw {
			raw[i] = 0
		}
		return nil, errMigrationUnavailable
	}
	if command.Wait() != nil || !nativeReadinessStatic(bundle, requirement) {
		raw := out.take()
		for i := range raw {
			raw[i] = 0
		}
		return nil, errMigrationUnavailable
	}
	return out.take(), nil
}
func newNativeMigrationKeyReadiness(plan migrationKeyReadinessPlan, acl migrationJournal, manifest migrationPackagedResource) (*migrationKeyReadiness, error) {
	if acl == nil || !migrationPackagedPath(manifest.Path) || !validMigrationID(manifest.SHA256) || !migrationPackagedPath(plan.Launchd.Path) || !validMigrationID(plan.Launchd.SHA256) || !migrationPackagedPath(plan.ConsoleCandidate) || !runtimeRoleRequirement("console", plan.ConsoleRequirement) || !runtimeValidInventory(plan.ConsoleInventory) {
		return nil, errMigrationUnavailable
	}
	return &migrationKeyReadiness{plan: plan, manifest: manifest, acl: acl, metadata: nativeMigrationMetadata{}, code: nativeRuntimeSignatureVerifier{}, system: nativeMigrationReadinessSystem{}, readResource: readMigrationPackagedResource}, nil
}

func (nativeMigrationReadinessSystem) gone(ctx context.Context, owned session.ProcessIdentity) error {
	if migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	_, alive, err := session.InspectProcess(owned.PID)
	if err != nil || alive {
		return errMigrationUnavailable
	}
	return nil
}
