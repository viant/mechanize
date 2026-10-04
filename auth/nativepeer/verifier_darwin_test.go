//go:build darwin && cgo

package nativepeer

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestRequirementParserAndNilPeer(t *testing.T) {
	if _, err := NewVerifier(Options{DesignatedRequirement: "this is not a requirement"}); err == nil {
		t.Fatal("invalid requirement accepted")
	}
	verify, err := NewVerifier(Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: `identifier "mechanize-fixture"`})
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(nil); err == nil {
		t.Fatal("nil peer accepted")
	}
}

// This explicit gate creates and ad hoc signs only a disposable Unix client.
// It does not touch the employee's desktop, Keychain, or installed applications.
func TestControlledSignedPeerFixture(t *testing.T) {
	if os.Getenv("MECHANIZE_SIGNED_PEER_FIXTURE") != "1" {
		t.Skip("set MECHANIZE_SIGNED_PEER_FIXTURE=1 for disposable signed-client integration")
	}
	for _, name := range []string{"clang", "codesign"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("fixture requires %s", name)
		}
	}
	dir, err := os.MkdirTemp("/tmp", "mpeer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "client.c")
	binary := filepath.Join(dir, "client")
	const code = `#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char **argv) {
 if (argc != 2) return 1;
 int fd = socket(AF_UNIX, SOCK_STREAM, 0);
 struct sockaddr_un address = {0}; address.sun_family = AF_UNIX;
 if (strlen(argv[1]) >= sizeof(address.sun_path)) return 2;
 strcpy(address.sun_path, argv[1]);
 if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 3;
 char byte = 'r'; if (write(fd, &byte, 1) != 1) return 4;
 read(fd, &byte, 1); close(fd); return 0;
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("clang", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("compile disposable fixture: %s: %v", output, err)
	}
	if output, err := exec.Command("codesign", "--force", "--sign", "-", "--identifier", "com.viant.mechanize.peer-fixture", binary).CombinedOutput(); err != nil {
		t.Fatalf("sign disposable fixture: %s: %v", output, err)
	}
	output, err := exec.Command("codesign", "-d", "--verbose=4", binary).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	hash := regexp.MustCompile(`CDHash=([0-9a-fA-F]{40})`).FindSubmatch(output)
	if len(hash) != 2 {
		t.Fatal("fixture CDHash unavailable")
	}
	executableOptions := Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: `cdhash H"` + string(hash[1]) + `"`}
	if err = VerifyExecutable(binary, executableOptions); err != nil {
		t.Fatalf("signed executable denied: %v", err)
	}
	wrongExecutable := executableOptions
	wrongExecutable.DesignatedRequirement = `identifier "com.viant.mechanize.other-fixture"`
	if VerifyExecutable(binary, wrongExecutable) == nil {
		t.Fatal("wrong executable requirement admitted")
	}
	link := filepath.Join(dir, "alias")
	if err = os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(link, executableOptions) == nil {
		t.Fatal("executable symlink admitted")
	}
	verify, err := NewVerifier(Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: `cdhash H"` + string(hash[1]) + `"`})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(10 * time.Second))
	client := exec.Command(binary, listener.Addr().String())
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Process.Kill(); _ = client.Wait() }()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ready [1]byte
	if _, err = conn.Read(ready[:]); err != nil {
		t.Fatal(err)
	}
	if err := verify(conn); err != nil {
		t.Fatalf("qualified signed fixture rejected: %v", err)
	}
	peerPID, err := AuditPID(conn)
	if err != nil || peerPID != client.Process.Pid {
		t.Fatalf("audit PID differs from child: %d %v", peerPID, err)
	}
	wrongUID, err := NewVerifier(Options{ExpectedUID: uint32(os.Getuid() + 1), DesignatedRequirement: `cdhash H"` + string(hash[1]) + `"`})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongUID(conn); err == nil {
		t.Fatal("wrong UID accepted")
	}
	wrongCode, err := NewVerifier(Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: `identifier "com.viant.mechanize.other-fixture"`})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongCode(conn); err == nil {
		t.Fatal("wrong signed identity accepted")
	}
}
