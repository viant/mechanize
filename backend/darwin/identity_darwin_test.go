//go:build darwin && cgo

package darwin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A signed inert executable exercises the real kernel audit-token handshake,
// without initializing AX/TCC or dispatching desktop input.
func signedIdentityFixture(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"clang", "codesign"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "fixture.c")
	binary := filepath.Join(directory, "fixture")
	code := `#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
 const char *path=getenv("MECHANIZE_IDENTITY_SOCKET"), *nonce=getenv("MECHANIZE_IDENTITY_NONCE");
 if(!path||!nonce)return 2;
 if(getenv("MECHANIZE_TEST_FOREIGN_PID")) {
  int child=fork();if(child<0)return 6;
  if(child>0){waitpid(child,0,0);char input;while(read(0,&input,1)>0){}return 0;}
 }
 int fd=socket(AF_UNIX,SOCK_STREAM,0); struct sockaddr_un addr={0}; addr.sun_family=AF_UNIX;
 strncpy(addr.sun_path,path,sizeof(addr.sun_path)-1);
 if(connect(fd,(struct sockaddr*)&addr,sizeof(addr)))return 3;
 unsigned char frame[68]={0,0,0,64}; memcpy(frame+4,nonce,64);
 if(getenv("MECHANIZE_TEST_BAD_NONCE"))frame[4]^=1;
 if(write(fd,frame,sizeof(frame))!=sizeof(frame))return 4;
 unsigned char ack=0;if(read(fd,&ack,1)!=1||ack!=1)return 5;close(fd);
 char input;while(read(0,&input,1)>0){}return 0;
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("clang", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %s %v", output, err)
	}
	if output, err := exec.Command("codesign", "--force", "--sign", "-", "--identifier", "mechanize.identity.fixture", binary).CombinedOutput(); err != nil {
		t.Fatalf("sign: %s %v", output, err)
	}
	return binary
}
func TestSignedHelperAuthenticatesActualLaunchedProcess(t *testing.T) {
	binary := signedIdentityFixture(t)
	uid := uint32(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewClient(ctx, Options{HelperPath: binary, Requirement: `identifier "mechanize.identity.fixture"`, ExpectedUID: &uid})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.Identity()
	if err != nil || identity.PID != client.PID() || identity.UID != uid || identity.StartToken == "" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.WaitStopped(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestSignedHelperBadChallengeReaped(t *testing.T) {
	binary := signedIdentityFixture(t)
	uid := uint32(os.Getuid())
	t.Setenv("MECHANIZE_TEST_BAD_NONCE", "1")
	client, err := NewClient(context.Background(), Options{HelperPath: binary, Requirement: `identifier "mechanize.identity.fixture"`, ExpectedUID: &uid})
	if err == nil || client != nil {
		t.Fatalf("client=%v error=%v", client, err)
	}
}
func TestSignedHelperWrongRequirementRejectedBeforeLaunch(t *testing.T) {
	binary := signedIdentityFixture(t)
	uid := uint32(os.Getuid())
	client, err := NewClient(context.Background(), Options{HelperPath: binary, Requirement: `identifier "wrong.fixture"`, ExpectedUID: &uid})
	if err == nil || client != nil {
		t.Fatalf("client=%v error=%v", client, err)
	}
}

func TestSameSignedForeignPeerRejected(t *testing.T) {
	binary := signedIdentityFixture(t)
	uid := uint32(os.Getuid())
	t.Setenv("MECHANIZE_TEST_FOREIGN_PID", "1")
	client, err := NewClient(context.Background(), Options{HelperPath: binary, Requirement: `identifier "mechanize.identity.fixture"`, ExpectedUID: &uid})
	if err == nil || client != nil {
		t.Fatalf("client=%v error=%v", client, err)
	}
	if !strings.Contains(err.Error(), "not the launched helper") {
		t.Fatalf("expected exact child PID rejection: %v", err)
	}
}

func TestSignedLaunchOnlyUsesSeparateAuthority(t *testing.T) {
	binary := signedIdentityFixture(t)
	uid := uint32(os.Getuid())
	fence, err := os.CreateTemp(t.TempDir(), "fence")
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	client, err := NewClient(context.Background(), Options{HelperPath: binary, Requirement: `identifier "mechanize.identity.fixture"`, ExpectedUID: &uid, Fence: fence, AllowLaunch: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if len(client.command.Args) != 2 || client.command.Args[1] != "--allow-launch" {
		t.Fatalf("authority arguments: %v", client.command.Args)
	}
	if client.inputPossible || !client.businessPossible {
		t.Fatal("launch uncertainty must remain separate from raw input authority")
	}
	if _, trusted := client.TrustedIdentity(); !trusted {
		t.Fatal("launch-only client lacks signed peer proof")
	}
}

func TestSignedRecordingOnlyHasNoInputOrDesktopFenceAuthority(t *testing.T) {
	binary := signedIdentityFixture(t)
	ctx, owner := recordingFixtureOwner()
	uid := uint32(os.Getuid())
	client, err := NewClient(ctx, Options{HelperPath: binary, Requirement: `identifier "mechanize.identity.fixture"`, ExpectedUID: &uid, AllowRecording: true, RecordingOwner: &owner})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if len(client.command.Args) != 2 || client.command.Args[1] != "--allow-recording" || client.inputPossible || client.recording == nil {
		t.Fatal("signed passive profile borrowed action authority")
	}
	if actual, trusted := client.TrustedIdentity(); !trusted || actual.UID != uid {
		t.Fatal("passive profile lacks exact signed helper identity")
	}
}
