//go:build darwin && cgo

package nativepeer

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func executableHashRequirement(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("codesign", "-d", "--verbose=4", path).CombinedOutput()
	if err != nil {
		t.Fatalf("disposable image signature lookup: %v", err)
	}
	match := regexp.MustCompile(`CDHash=([a-fA-F0-9]{40})`).FindSubmatch(out)
	if len(match) != 2 {
		t.Fatal("disposable CDHash unavailable")
	}
	return `cdhash H"` + string(match[1]) + `"`
}

// This gate authenticates a signed inert Unix child and the signed test parent.
// It proves the actual kernel peer/libproc checks, not real Chrome/profile trust.
func TestControlledSignedChromeAncestryProcessLayer(t *testing.T) {
	if os.Getenv("MECHANIZE_SIGNED_PEER_FIXTURE") != "1" {
		t.Skip("set MECHANIZE_SIGNED_PEER_FIXTURE=1 for disposable signed process fixture")
	}
	for _, tool := range []string{"clang", "codesign"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	dir, err := os.MkdirTemp("/tmp", "mchrome-sign-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "child")
	source := filepath.Join(dir, "child.c")
	code := `#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
int main(int argc,char **argv){if(argc!=2)return 1;int fd=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a={0};a.sun_family=AF_UNIX;strncpy(a.sun_path,argv[1],sizeof(a.sun_path)-1);if(connect(fd,(struct sockaddr*)&a,sizeof(a)))return 2;char byte=1;if(write(fd,&byte,1)!=1)return 3;read(fd,&byte,1);return 0;}`
	if err = os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile inert child: %s %v", out, err)
	}
	if out, err := exec.Command("codesign", "--force", "--sign", "-", "--identifier", "mechanize.chrome-child-fixture", binary).CombinedOutput(); err != nil {
		t.Fatalf("sign inert child: %s %v", out, err)
	}
	parent, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	policy := ChromeProcessPolicy{ExpectedUID: uint32(os.Getuid()), NativeHostExecutable: binary, NativeHostRequirement: executableHashRequirement(t, binary), ChromeExecutable: parent, ChromeRequirement: executableHashRequirement(t, parent), MaximumAncestors: 1}
	verify, err := NewChromePeerVerifier(policy)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	child := exec.Command(binary, listener.Addr().String())
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var ready [1]byte
	if _, err = conn.Read(ready[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	evidence, err := verify.Verify(ctx, conn)
	if err != nil || evidence.NativeHost.PID != child.Process.Pid || evidence.ChromeParent.PID != os.Getpid() || !evidence.KernelPeerQualified || evidence.ProfileQualified || evidence.ExecutorQualified {
		t.Fatalf("kernel/ancestry fixture: %+v %v", evidence, err)
	}
	wrong := policy
	wrong.ChromeRequirement = `identifier "not.the.fixture.parent"`
	if _, err = VerifyChromeProcess(ctx, child.Process.Pid, wrong); err == nil {
		t.Fatal("wrong signed parent admitted")
	}
}
