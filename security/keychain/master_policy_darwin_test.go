//go:build darwin && cgo

package keychain

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// Exercise the exact native comparator against in-memory Security.framework
// policies. This program never queries, reads, creates or changes a Keychain item.
func TestNativeMasterPolicyComparisonWithoutKeychain(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("native policy test requires the cgo clang toolchain")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "policy.m")
	binary := filepath.Join(dir, "policy")
	program := "#include " + strconv.Quote(filepath.Join(cwd, "master_darwin.m")) + `
int main(void) { @autoreleasepool {
    SecAccessRef expectedAccess = master_expected_access(), actualAccess = master_expected_access();
    CSSM_ACL_OWNER_PROTOTYPE *expectedOwner = NULL, *owner = NULL;
    CSSM_ACL_ENTRY_INFO *expected = NULL, *actual = NULL;
    uint32 expectedCount = 0, count = 0;
    if (!expectedAccess || !actualAccess ||
        SecAccessGetOwnerAndACL(expectedAccess, &expectedOwner, &expectedCount, &expected) ||
        SecAccessGetOwnerAndACL(actualAccess, &owner, &count, &actual)) return 1;
    if (!master_policy_equal(owner, count, actual, expectedOwner, expectedCount, expected)) return 2;
    owner->Delegate = !owner->Delegate;
    if (master_policy_equal(owner, count, actual, expectedOwner, expectedCount, expected)) return 3;
    owner->Delegate = !owner->Delegate;
    if (!actual[0].EntryPublicInfo.TypedSubject.Head) return 4;
    actual[0].EntryPublicInfo.TypedSubject.Head->WordID ^= 0x40000000;
    if (master_policy_equal(owner, count, actual, expectedOwner, expectedCount, expected)) return 5;
    actual[0].EntryPublicInfo.TypedSubject.Head->WordID ^= 0x40000000;
    CSSM_ACL_ENTRY_INFO expanded[34] = {0};
    if (count > 30) return 6;
    memcpy(expanded, actual, count * sizeof(*actual));
    expanded[count] = actual[0];
    if (master_policy_equal(owner, count + 1, expanded, expectedOwner, expectedCount, expected)) return 7;
    if (!master_duplicate_policy_equivalent(owner, count + 1, expanded, expectedOwner, expectedCount, expected)) return 19;
    expanded[count + 1] = actual[0];
    if (master_duplicate_policy_equivalent(owner, count + 2, expanded, expectedOwner, expectedCount, expected)) return 20;
    CSSM_ACL_AUTHORIZATION_TAG tags[2] = { CSSM_ACL_AUTHORIZATION_PARTITION_ID, CSSM_ACL_AUTHORIZATION_DECRYPT };
    memset(&expanded[count], 0, sizeof(*expanded));
    expanded[count].EntryPublicInfo.Authorization.NumberOfAuthTags = 1;
    expanded[count].EntryPublicInfo.Authorization.AuthTags = tags;
    strcpy(expanded[count].EntryPublicInfo.EntryTag, CSSM_APPLE_ACL_TAG_PARTITION_ID);
    if (!master_policy_equal(owner, count + 1, expanded, expectedOwner, expectedCount, expected)) return 8;
    expanded[count].EntryPublicInfo.Authorization.NumberOfAuthTags = 2;
    if (master_policy_equal(owner, count + 1, expanded, expectedOwner, expectedCount, expected)) return 9;
    expanded[count].EntryPublicInfo.Authorization.NumberOfAuthTags = 1;
    expanded[count + 1] = expanded[count];
    if (master_policy_equal(owner, count + 2, expanded, expectedOwner, expectedCount, expected)) return 10;
    // Same visible path/comment but distinct signing subject bytes must fail.
    CSSM_LIST_ELEMENT a = {0}, b = {0};
    unsigned char first[] = {1, 2, 3}, second[] = {1, 2, 4};
    a.ElementType = b.ElementType = CSSM_LIST_ELEMENT_DATUM;
    a.Element.Word.Data = first; a.Element.Word.Length = sizeof(first);
    b.Element.Word.Data = second; b.Element.Word.Length = sizeof(second);
    CSSM_LIST left = { .Head = &a, .Tail = &a }, right = { .Head = &b, .Tail = &b };
    if (master_subject_equal(&left, &right, 0)) return 11;
    // Across signed builds only the same parsed requirement is an identity.
    SecRequirementRef req = NULL, foreign = NULL;
    CFDataRef reqData = NULL, foreignData = NULL;
    if (SecRequirementCreateWithString(CFSTR("identifier \"com.viant.mechanize.broker\""), 0, &req) ||
        SecRequirementCreateWithString(CFSTR("identifier \"foreign\""), 0, &foreign) ||
        SecRequirementCopyData(req, 0, &reqData) || SecRequirementCopyData(foreign, 0, &foreignData)) return 12;
    CSSM_LIST_ELEMENT l[6] = {0}, r[6] = {0};
    unsigned char hashA[20] = {1}, hashB[20] = {2};
    unsigned char pathA[] = "/old/image", pathB[] = "/new/image";
    for (unsigned side = 0; side < 2; side++) {
        CSSM_LIST_ELEMENT *v = side ? r : l;
        v[0].ElementType = v[1].ElementType = CSSM_LIST_ELEMENT_WORDID;
        v[0].WordID = CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE; v[1].WordID = CSSM_ACL_CODE_SIGNATURE_OSX;
        for (unsigned n = 2; n < 5; n++) v[n].ElementType = CSSM_LIST_ELEMENT_DATUM;
        v[2].Element.Word.Data = side ? hashB : hashA; v[2].Element.Word.Length = 20;
        v[3].Element.Word.Data = side ? pathB : pathA; v[3].Element.Word.Length = sizeof(pathA);
        v[4].Element.Word.Data = (uint8 *)CFDataGetBytePtr(reqData); v[4].Element.Word.Length = (uint32)CFDataGetLength(reqData);
        for (unsigned n = 0; n < 4; n++) v[n].NextElement = &v[n+1];
    }
    CSSM_LIST signedLeft = { .Head = l, .Tail = &l[4] }, signedRight = { .Head = r, .Tail = &r[4] };
    if (master_subject_equal(&signedLeft, &signedRight, 0) || !master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 13;
    r[4].Element.Word.Data = (uint8 *)CFDataGetBytePtr(foreignData); r[4].Element.Word.Length = (uint32)CFDataGetLength(foreignData);
    if (master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 14;
    r[4].Element.Word = l[4].Element.Word;
    r[4].NextElement = &r[5];
    if (master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 15;
    r[4].NextElement = NULL;
    r[2].Element.Word.Length = 19;
    if (master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 16;
    r[2].Element.Word.Length = 20;
    unsigned char malformed[8] = {0};
    r[4].Element.Word.Data = malformed; r[4].Element.Word.Length = sizeof(malformed);
    if (master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 17;
    l[3].NextElement = r[3].NextElement = NULL; // Unsigned legacy hash still binds the exact image.
    if (master_subject_equal_mode(&signedLeft, &signedRight, 0, 1)) return 18;
    CFRelease(reqData); CFRelease(foreignData); CFRelease(req); CFRelease(foreign);
    master_free_policy(owner, count, actual); master_free_policy(expectedOwner, expectedCount, expected);
    CFRelease(expectedAccess); CFRelease(actualAccess);
    return 0;
} }
`
	if err = os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(compiler, "-Wno-deprecated-declarations", "-framework", "Security", "-framework", "Foundation", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("native policy fixture failed to compile: %v: %s", err, output)
	}
	if err = exec.Command(binary).Run(); err != nil {
		t.Fatalf("native policy fixture rejected expected comparison: %v", err)
	}
}
