//go:build darwin && cgo

package keychain

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This exercises only in-memory access objects and public executable identities.
// No Keychain item is searched, read, created or changed. It is a migration
// design gate, not installed migration or SecurityAgent authorization proof.
func TestNativeSingleACLMigrationPolicyWithoutKeychain(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "migration-policy.m"), filepath.Join(dir, "migration-policy")
	copied := filepath.Join(dir, "same-public-system-executable")
	bytes, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(copied, bytes, 0700); err != nil {
		t.Fatal(err)
	}
	program := "#include " + strconv.Quote(filepath.Join(cwd, "master_darwin.m")) + `
static int get(SecAccessRef a, CSSM_ACL_OWNER_PROTOTYPE **o, uint32 *c, CSSM_ACL_ENTRY_INFO **e) {
 return SecAccessGetOwnerAndACL(a,o,c,e)==errSecSuccess;
}
int main(int argc, const char **argv) { @autoreleasepool {
 SecAccessRef original=master_expected_access(), target=NULL;
 SecTrustedApplicationRef other=NULL;
 if (!original || SecTrustedApplicationCreateFromPath("/usr/bin/true", &other)) return 1;
 CFArrayRef singleton=(CFArrayRef)@[ (id)other ];
 if (SecAccessCreate(CFSTR("Mechanize Vault encryption"),singleton,&target)) return 2;
 CSSM_ACL_OWNER_PROTOTYPE *a=NULL,*b=NULL,*c=NULL;
 CSSM_ACL_ENTRY_INFO *ae=NULL,*be=NULL,*ce=NULL;
 uint32 an=0,bn=0,cn=0;
 if (!get(original,&a,&an,&ae) || !get(target,&b,&bn,&be)) return 3;
 int ownerSame=a->Delegate==b->Delegate && master_subject_equal(&a->TypedSubject,&b->TypedSubject,0);
 int policyDifferent=!master_policy_equal(a,an,ae,b,bn,be);
 SecAccessRef expectedOld=master_expected_access();
 if (!expectedOld || master_prepare_single_acl(original,original,other,target) ||
     !master_prepare_single_acl(original,expectedOld,other,target)) return 4;
 // The preparation must reject an already transitioned or mismatched old policy.
 if (master_prepare_single_acl(original,expectedOld,other,target)) return 5;
 CFRelease(expectedOld);
 if (!get(original,&c,&cn,&ce)) return 8;
 int ownerPreserved=c->Delegate==a->Delegate && master_subject_equal(&c->TypedSubject,&a->TypedSubject,0);
 int exactTarget=master_policy_equal(c,cn,ce,b,bn,be);
 // Same signed bytes at a different path cannot substitute for final-path policy.
 if (argc != 2) return 10;
 SecTrustedApplicationRef copied=NULL; SecAccessRef copiedPolicy=NULL;
 if (SecTrustedApplicationCreateFromPath(argv[1], &copied) ||
     SecAccessCreate(CFSTR("Mechanize Vault encryption"),(CFArrayRef)@[ (id)copied ],&copiedPolicy)) return 11;
 CSSM_ACL_OWNER_PROTOTYPE *d=NULL; CSSM_ACL_ENTRY_INFO *de=NULL; uint32 dn=0;
 if (!get(copiedPolicy,&d,&dn,&de)) return 12;
 int pathDistinct=!master_policy_equal(b,bn,be,d,dn,de);
 master_free_policy(d,dn,de); CFRelease(copiedPolicy); CFRelease(copied);
 if (!pathDistinct) return 13;
 master_free_policy(a,an,ae); master_free_policy(b,bn,be); master_free_policy(c,cn,ce);
 CFRelease(other); CFRelease(original); CFRelease(target);
 return ownerSame && policyDifferent && ownerPreserved && exactTarget ? 0 : 9;
} }
`
	if err = os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, compiler, "-Wno-deprecated-declarations", "-framework", "Security", "-framework", "Foundation", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v: %s", err, output)
	}
	runCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err = exec.CommandContext(runCtx, binary, copied).Run(); err != nil {
		t.Fatalf("single ACL/final-path policy fixture: %v", err)
	}
}
