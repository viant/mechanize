#!/usr/bin/env python3
"""Disposable signed broker/helper tests. No desktop input or permission grants.

Run: python3 native/macos/Tests/IdentityIntegration/test_signed_launch.py
All executables, signatures and Mach-O enrollment metadata live in a temporary
scratch directory. Existing development artifacts and installs are untouched.
"""
import json
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
BROKER_SOURCE = r'''
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
static int listener(const char *path) {
 int fd=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
 strncpy(addr.sun_path,path,sizeof(addr.sun_path)-1);
 if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))||listen(fd,1))exit(90);return fd;
}
static void serve(int fd) {
 struct pollfd ready={.fd=fd,.events=POLLIN};
 if(poll(&ready,1,3000)<=0)return;
 int conn=accept(fd,0,0);if(conn<0)return;
 unsigned char frame[68];int received=0;
 while(received<68){int n=read(conn,frame+received,68-received);if(n<=0)break;received+=n;}
 fprintf(stderr,"identity-frame-bytes:%d\n",received);
 if(received==68){unsigned char ack=1;write(conn,&ack,1);}close(conn);
}
int main(int argc,char **argv) {
 if(argc!=4)return 89;signal(SIGPIPE,SIG_IGN);
 const char *mode=argv[3];int server=-1, fd=-1;
 if(!strcmp(mode,"foreign")) {
  int gate[2];pipe(gate);server=fork();
  if(server==0){close(gate[0]);fd=listener(argv[2]);write(gate[1],"r",1);close(gate[1]);serve(fd);exit(0);}
  close(gate[1]);char ready;read(gate[0],&ready,1);close(gate[0]);
 }else{fd=listener(argv[2]);}
 int input[2],output[2];pipe(input);pipe(output);int child=fork();
 if(child==0){
  dup2(input[0],0);dup2(output[1],1);for(int n=3;n<256;n++)close(n);
  setenv("MECHANIZE_IDENTITY_SOCKET",argv[2],1);
  setenv("MECHANIZE_IDENTITY_NONCE","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1);
  // These attacker-supplied values must never substitute for signed metadata.
  setenv("MECHANIZE_BROKER_REQUIREMENT","identifier \"mechanize.fixture.bad\"",1);
  setenv("MECHANIZE_BROKER_EXPECTED_UID","0",1);
  execl(argv[1],argv[1],!strcmp(mode,"mutation")?"--allow-mutations":(!strcmp(mode,"launch")?"--allow-launch":(!strcmp(mode,"record")?"--allow-recording":NULL)),NULL);_exit(91);
 }
 close(input[0]);close(output[1]);
 if(server<0){serve(fd);close(fd);}else{waitpid(server,0,0);}
 const char *request="{\"protocolVersion\":1,\"requestId\":\"identity-fixture\",\"method\":\"doctor\",\"deadlineRemainingMs\":30000,\"params\":{}}";
 unsigned int count=(unsigned int)strlen(request);unsigned char header[4]={count>>24,count>>16,count>>8,count};
 write(input[1],header,4);write(input[1],request,count);close(input[1]);
 char buffer[4096];int n;while((n=read(output[0],buffer,sizeof(buffer)))>0)write(1,buffer,n);close(output[0]);
 int status;waitpid(child,&status,0);return WIFEXITED(status)?WEXITSTATUS(status):92;
}
'''


def run(*args, check=True, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=check, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=90, **kwargs)


def sign(path, identifier):
    run("codesign", "--force", "--sign", "-", "--identifier", identifier, str(path))
    result = run("codesign", "--display", "--verbose=4", str(path))
    match = re.search(rb"^CDHash=([a-fA-F0-9]{40})$", result.stderr, re.MULTILINE)
    if not match:
        raise AssertionError("exact fixture CDHash missing")
    return f'identifier "{identifier}" and cdhash H"{match[1].decode().lower()}"'


@unittest.skipUnless(sys.platform == "darwin", "kernel audit tokens require macOS")
class SignedLaunchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("swift", "clang", "codesign"):
            if not shutil.which(tool):
                raise unittest.SkipTest(tool + " unavailable")
        cls.temporary = tempfile.TemporaryDirectory(prefix="mechanize-reverse-identity-", dir="/tmp")
        cls.directory = Path(cls.temporary.name).resolve()
        source = cls.directory / "broker.c"
        source.write_text(BROKER_SOURCE)
        cls.good = cls.directory / "good-broker"
        cls.bad = cls.directory / "bad-broker"
        run("clang", str(source), "-o", str(cls.good))
        shutil.copyfile(cls.good, cls.bad)
        os.chmod(cls.bad, 0o700)
        good_requirement = sign(cls.good, "mechanize.fixture.good")
        sign(cls.bad, "mechanize.fixture.bad")
        scratch = cls.directory / "build"
        base = ["swift", "build", "--package-path", "native/macos", "--scratch-path", str(scratch)]
        run(*base)
        binary_directory = Path(run(*base, "--show-bin-path").stdout.decode().strip())
        cls.unpinned = cls.directory / "unpinned-helper"
        shutil.copyfile(binary_directory / "mechanize-native", cls.unpinned)
        os.chmod(cls.unpinned, 0o700)
        sign(cls.unpinned, "mechanize.fixture.native")
        plist = cls.directory / "identity.plist"
        plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "mechanize.fixture.native",
                                         "MechanizeBrokerRequirement": good_requirement}))
        run(*base, "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist", "-Xlinker", str(plist))
        cls.pinned = cls.directory / "pinned-helper"
        shutil.copyfile(binary_directory / "mechanize-native", cls.pinned)
        os.chmod(cls.pinned, 0o700)
        sign(cls.pinned, "mechanize.fixture.native")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def launch(self, broker, helper=None, mode="read"):
        socket = self.directory / (hashlib.sha256(self.id().encode()).hexdigest()[:10] + ".sock")
        return run(str(broker), str(helper or self.pinned), str(socket), mode, check=False)

    def doctor(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertGreaterEqual(len(result.stdout), 4)
        count = struct.unpack(">I", result.stdout[:4])[0]
        self.assertEqual(len(result.stdout), count + 4)
        return json.loads(result.stdout[4:])["result"]

    def assert_rejected(self, result):
        self.assertEqual(result.returncode, 78, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"identity-frame-bytes:68", result.stderr)
        self.assertNotIn(b"aaaaaaaa", result.stderr)

    def test_embedded_exact_broker_authenticated(self):
        result = self.launch(self.good)
        doctor = self.doctor(result)
        self.assertTrue(doctor["brokerIdentityAuthenticated"])
        self.assertFalse(doctor["productionIdentityQualified"])
        self.assertFalse(doctor["mutationEnabled"])

    def test_mutation_launch_authenticates_before_native_services(self):
        doctor = self.doctor(self.launch(self.good, mode="mutation"))
        self.assertTrue(doctor["brokerIdentityAuthenticated"])
        # This disposable fixture deliberately has no physical fence/watchdog.
        self.assertFalse(doctor["mutationEnabled"])

    def test_launch_only_authenticates_without_input_authority(self):
        doctor = self.doctor(self.launch(self.good, mode="launch"))
        self.assertTrue(doctor["brokerIdentityAuthenticated"])
        self.assertFalse(doctor["mutationEnabled"])
        self.assertFalse(doctor["launchEnabled"])  # No inherited fence/watchdog.
        self.assertIn("windowSession", doctor)
        self.assertNotIn("unlocked", doctor["windowSession"])

    def test_recording_profile_does_not_start_capture_or_borrow_fence(self):
        doctor = self.doctor(self.launch(self.good, mode="record"))
        self.assertTrue(doctor["brokerIdentityAuthenticated"])
        self.assertTrue(doctor["passiveRecordingOnly"])
        self.assertFalse(doctor["recordingEnabled"])  # No inherited watchdog.
        self.assertFalse(doctor["mutationEnabled"])
        self.assertFalse(doctor["launchEnabled"])
        self.assertFalse(doctor["physicalFenceEnrolled"])

    def test_recording_without_rendezvous_rejected(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MECHANIZE_IDENTITY_SOCKET", "MECHANIZE_IDENTITY_NONCE")}
        self.assert_rejected(run(str(self.pinned), "--allow-recording", input=b"", env=environment, check=False))

    def test_wrong_signed_parent_and_environment_override_rejected(self):
        self.assert_rejected(self.launch(self.bad))

    def test_same_signed_foreign_socket_owner_rejected(self):
        self.assert_rejected(self.launch(self.good, mode="foreign"))

    def test_missing_signed_metadata_rejected(self):
        self.assert_rejected(self.launch(self.good, helper=self.unpinned))

    def test_readonly_without_rendezvous_is_unqualified(self):
        request = json.dumps({"protocolVersion": 1, "requestId": "readonly", "method": "doctor",
                              "deadlineRemainingMs": 30000, "params": {}}).encode()
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MECHANIZE_IDENTITY_SOCKET", "MECHANIZE_IDENTITY_NONCE")}
        result = run(str(self.unpinned), input=struct.pack(">I", len(request)) + request, env=environment)
        doctor = self.doctor(result)
        self.assertFalse(doctor["brokerIdentityAuthenticated"])
        self.assertFalse(doctor["productionIdentityQualified"])
        self.assertFalse(doctor["mutationEnabled"])

    def test_launch_only_without_rendezvous_rejected(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MECHANIZE_IDENTITY_SOCKET", "MECHANIZE_IDENTITY_NONCE")}
        self.assert_rejected(run(str(self.pinned), "--allow-launch", input=b"", env=environment, check=False))

    def test_conflicting_action_flags_rejected(self):
        self.assert_rejected(run(str(self.pinned), "--allow-launch", "--allow-mutations", input=b"", check=False))

    def test_mutation_without_rendezvous_rejected(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MECHANIZE_IDENTITY_SOCKET", "MECHANIZE_IDENTITY_NONCE")}
        self.assert_rejected(run(str(self.pinned), "--allow-mutations", input=b"", env=environment, check=False))


if __name__ == "__main__":
    unittest.main()
