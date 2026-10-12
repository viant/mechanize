//go:build darwin && cgo

package keychain

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// Sign only a disposable fixture. Every item/interaction API is replaced with
// an aborting stub, and the writer receives a nil snapshot. A valid self-role
// probe is exercised without any Vault/item access or authorization UI.
func TestNativeMigrationWriterExactSelfRoleWithoutKeychain(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal(err)
	}
	signing, err := exec.LookPath("codesign")
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "role.m"), filepath.Join(dir, "role")
	program := "#include " + strconv.Quote(filepath.Join(cwd, "migration_metadata_darwin.h")) + "\n" + `#import <Foundation/Foundation.h>
#include <stdlib.h>
static OSStatus forbiddenLookup(CFDictionaryRef q, CFTypeRef *r) { abort(); }
static OSStatus forbiddenSet(SecKeychainItemRef i, SecAccessRef a) { abort(); }
static OSStatus forbiddenInteraction(Boolean a) { abort(); }
static OSStatus forbiddenReference(SecKeychainItemRef i, CFDataRef *r) { abort(); }
static OSStatus forbiddenAccess(SecKeychainItemRef i, SecAccessRef *a) { abort(); }
#define SecItemCopyMatching forbiddenLookup
#define SecKeychainItemSetAccess forbiddenSet
#define SecKeychainSetUserInteractionAllowed forbiddenInteraction
#define SecKeychainItemCreatePersistentReference forbiddenReference
#define SecKeychainItemCopyAccess forbiddenAccess
` + "#include " + strconv.Quote(filepath.Join(cwd, "migration_write_darwin.m")) + "\n" + `int mechanize_master_access_policy_matches(SecAccessRef a, SecAccessRef b) { abort(); }
int mechanize_master_prepare_single_acl(SecAccessRef a, SecAccessRef b, SecTrustedApplicationRef c, SecAccessRef d) { abort(); }
int mechanize_migration_metadata_verify(MechanizeMigrationMetadata *s, const char *p,const char *r,const char *v,const char *a) { abort(); }
int mechanize_migration_metadata_inspect(const char *p,const char *r,const char *v,const char *a,const void *i,int n) { abort(); }
int main(int argc,const char **argv) { @autoreleasepool {
 if ((argc!=5 && argc!=6) || !mechanize_migration_executor_matches(argv[1])) return 1;
 if (mechanize_migration_write(NULL,"/must-not-be-inspected",NULL,NULL,NULL,argv[1])!=0) return 2;
 if (migration_write_candidate(argv[2],argv[3]) != (argv[4][0]=='1')) return 3;
 if (argc==6) {
   CFURLRef firstURL=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8 *)argv[5],strlen(argv[5]),false);
   CFURLRef secondURL=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8 *)argv[2],strlen(argv[2]),false);
   SecStaticCodeRef first=NULL,second=NULL;SecRequirementRef firstDR=NULL,secondDR=NULL;
   int stable=firstURL && secondURL && SecStaticCodeCreateWithPath(firstURL,0,&first)==errSecSuccess &&
     SecStaticCodeCreateWithPath(secondURL,0,&second)==errSecSuccess && SecCodeCopyDesignatedRequirement(first,0,&firstDR)==errSecSuccess &&
     SecCodeCopyDesignatedRequirement(second,0,&secondDR)==errSecSuccess && migration_write_requirement_equal(firstDR,secondDR) &&
     SecStaticCodeCheckValidity(second,kSecCSStrictValidate,firstDR)==errSecSuccess;
   if(firstURL)CFRelease(firstURL);if(secondURL)CFRelease(secondURL);if(first)CFRelease(first);if(second)CFRelease(second);if(firstDR)CFRelease(firstDR);if(secondDR)CFRelease(secondDR);
   if (!stable) return 5;
 }
 return 0;
} }
`
	if err = os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, clang, "-Wno-deprecated-declarations", "-framework", "Security", "-framework", "Foundation", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v: %s", err, out)
	}
	if out, err := exec.CommandContext(ctx, signing, "--force", "--sign", "-", "--identifier", "com.viant.mechanize.custody-migration", binary).CombinedOutput(); err != nil {
		t.Fatalf("fixture signing: %v: %s", err, out)
	}
	out, err := exec.CommandContext(ctx, signing, "--display", "--verbose=4", binary).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`).FindSubmatch(out)
	if len(match) != 2 {
		t.Fatal("fixture has no exact hash")
	}
	rule := `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + string(match[1]) + `"`
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(canonicalDir, "public-broker-fixture")
	contents, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, contents, 0700); err != nil {
		t.Fatal(err)
	}
	for _, broad := range []bool{false, true} {
		arguments := []string{"--force", "--sign", "-", "--identifier", "com.viant.mechanize.broker"}
		if broad {
			arguments = append(arguments, "--requirements", `=designated => identifier "com.viant.mechanize.broker"`)
		}
		arguments = append(arguments, target)
		if out, err := exec.CommandContext(ctx, signing, arguments...).CombinedOutput(); err != nil {
			t.Fatalf("public fixture signing: %v: %s", err, out)
		}
		out, err := exec.CommandContext(ctx, signing, "--display", "--verbose=4", target).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		hash := regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`).FindSubmatch(out)
		if len(hash) != 2 {
			t.Fatal("candidate fixture has no exact hash")
		}
		targetRule := `identifier "com.viant.mechanize.broker" and cdhash H"` + string(hash[1]) + `"`
		want := "1"
		if broad {
			want = "0"
		}
		if err = exec.CommandContext(ctx, binary, rule, target, targetRule, want).Run(); err != nil {
			t.Fatalf("code-only identity gates (broad=%v): %v", broad, err)
		}
	}
	// Explicit opt-in uses a PUBLIC certificate SHA1 only. It signs disposable
	// files; the private key remains non-extractable in the operator's Keychain.
	// No identity/certificate/trust/item creation or mutation occurs here.
	if identity := os.Getenv("MECHANIZE_TEST_SIGNING_IDENTITY_SHA1"); identity != "" {
		if !regexp.MustCompile(`^[0-9A-Fa-f]{40}$`).MatchString(identity) {
			t.Fatal("invalid public test identity fingerprint")
		}
		stable := `identifier "com.viant.mechanize.broker" and certificate leaf = H"` + identity + `"`
		var firstHash string
		for _, mode := range []string{"firstImage", "secondImage", "wideIdentifier", "wideSigner", "foreignLeafDR", "foreignIdentifier"} {
			candidate := filepath.Join(canonicalDir, mode)
			// Distinct valid Mach-O code images before signing: the second image
			// compiles an additional function into the code pages.
			if err = os.WriteFile(candidate, contents, 0700); err != nil {
				t.Fatal(err)
			}
			if mode == "secondImage" {
				secondSource := filepath.Join(dir, "second-role.m")
				if err = os.WriteFile(secondSource, []byte(program+"\nint mechanize_distinct_code_image_fixture(void) { return 827; }\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if output, e := exec.CommandContext(ctx, clang, "-Wno-deprecated-declarations", "-framework", "Security", "-framework", "Foundation", secondSource, "-o", candidate).CombinedOutput(); e != nil {
					t.Fatalf("second code image compile: %v: %s", e, output)
				}
			}
			identifier := "com.viant.mechanize.broker"
			designated := stable
			want := "1"
			switch mode {
			case "wideIdentifier":
				designated = `identifier "com.viant.mechanize.broker"`
				want = "0"
			case "wideSigner":
				designated = `certificate leaf = H"` + identity + `"`
				want = "0"
			case "foreignLeafDR":
				designated = `identifier "com.viant.mechanize.broker" and certificate leaf = H"0000000000000000000000000000000000000000"`
				want = "0"
			case "foreignIdentifier":
				identifier = "com.viant.foreign"
				designated = `identifier "com.viant.foreign" and certificate leaf = H"` + identity + `"`
				want = "0"
			}
			if output, e := exec.CommandContext(ctx, signing, "--force", "--sign", identity, "--identifier", identifier, "--requirements", "=designated => "+designated, candidate).CombinedOutput(); e != nil {
				t.Fatalf("certificate fixture signing (%s): %v: %s", mode, e, output)
			}
			output, e := exec.CommandContext(ctx, signing, "--display", "--verbose=4", candidate).CombinedOutput()
			if e != nil {
				t.Fatal(e)
			}
			hash := regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`).FindSubmatch(output)
			if len(hash) != 2 {
				t.Fatal("certificate fixture has no exact code hash")
			}
			if mode == "firstImage" {
				firstHash = string(hash[1])
			}
			if mode == "secondImage" && firstHash == string(hash[1]) {
				t.Fatal("stability test did not change code image")
			}
			exact := `identifier "com.viant.mechanize.broker" and cdhash H"` + string(hash[1]) + `"`
			probeArguments := []string{rule, candidate, exact, want}
			if mode == "secondImage" {
				probeArguments = append(probeArguments, filepath.Join(canonicalDir, "firstImage"))
			}
			if e = exec.CommandContext(ctx, binary, probeArguments...).Run(); e != nil {
				t.Fatalf("reviewed exact-image stable policy (%s): %v", mode, e)
			}
		}
	} else {
		t.Log("certificate-backed image fixtures not run: public local signing identity not supplied")
	}

}
