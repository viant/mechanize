#import <Security/Security.h>
#import <Foundation/Foundation.h>
#include <stdio.h>

// Explicit local diagnostics contain fixed phases and numeric OS statuses only.
// Never log an item name, path, requirement, persistent reference or key bytes.
static void master_diagnostic(const char *phase, OSStatus status) {
    const char *enabled = getenv("MECHANIZE_VAULT_DIAGNOSTICS");
    if (enabled && strcmp(enabled, "1") == 0)
        fprintf(stderr, "mechanizeVault:%s:%d\n", phase, (int)status);
}

static int master_own_code(const char *text) {
    SecCodeRef code = NULL; SecRequirementRef requirement = NULL;
    CFStringRef string = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    if (!string) return 0;
    OSStatus status = SecRequirementCreateWithString(string, kSecCSDefaultFlags, &requirement);
    CFRelease(string);
    if (status == errSecSuccess) status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    if (code) CFRelease(code); if (requirement) CFRelease(requirement);
    if (status != errSecSuccess) master_diagnostic("selfSignature", status);
    return status == errSecSuccess;
}
static NSMutableDictionary *master_query(const char *service, const char *account) {
    NSString *s = [NSString stringWithUTF8String:service];
    NSString *a = [NSString stringWithUTF8String:account];
    if (!s || !a) return nil;
    return [NSMutableDictionary dictionaryWithDictionary:@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: s, (id)kSecAttrAccount: a,
        (id)kSecAttrSynchronizable: @NO,
        (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIFail
    }];
}

// Compare the complete public CSSM subjects, including their signing
// requirement blobs. A path or a legacy image hash alone is never accepted
// as the identity of a signed application.
static int master_data_equal(const CSSM_DATA *a, const CSSM_DATA *b) {
    return a->Length == b->Length && a->Length <= 65536 &&
        (a->Length == 0 || (a->Data && b->Data && memcmp(a->Data, b->Data, a->Length) == 0));
}
// Signed ACL subjects carry a legacy image hash and a descriptive path as well
// as their actual signing requirement. Apple validates the requirement when it
// exists. Own-key custody may compare that identity across builds, but migration
// snapshots below continue to compare every public byte exactly.
// Apple implementation reference: Security/OSX/libsecurity_cdsa_utilities/lib/acl_codesigning.cpp
// and libsecurity_keychain/lib/TrustedApplication.cpp (verifyToDisk).
static int master_signed_identity_equal(const CSSM_LIST *a, const CSSM_LIST *b) {
    const CSSM_LIST_ELEMENT *x = a->Head, *y = b->Head;
    if (!x || !y || x->ElementType != CSSM_LIST_ELEMENT_WORDID || y->ElementType != CSSM_LIST_ELEMENT_WORDID ||
        x->WordID != CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE || y->WordID != CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE) return -1;
    const CSSM_LIST_ELEMENT *left[5], *right[5];
    for (unsigned i = 0; i < 5; i++) {
        if (!x || !y) return -1; // Legacy unsigned subjects retain exact comparison.
        left[i] = x; right[i] = y; x = x->NextElement; y = y->NextElement;
    }
    if (x || y) return 0; // Unrecognized auxiliary blobs are not normalized.
    for (unsigned side = 0; side < 2; side++) {
        const CSSM_LIST_ELEMENT **v = side ? right : left;
        if (v[1]->ElementType != CSSM_LIST_ELEMENT_WORDID || v[1]->WordID != CSSM_ACL_CODE_SIGNATURE_OSX ||
            v[2]->ElementType != CSSM_LIST_ELEMENT_DATUM || v[2]->Element.Word.Length != 20 || !v[2]->Element.Word.Data ||
            v[3]->ElementType != CSSM_LIST_ELEMENT_DATUM || !v[3]->Element.Word.Data ||
            v[3]->Element.Word.Length < 1 || v[3]->Element.Word.Length > 4096 ||
            v[3]->Element.Word.Data[v[3]->Element.Word.Length - 1] != 0 ||
            memchr(v[3]->Element.Word.Data, 0, v[3]->Element.Word.Length - 1) ||
            v[4]->ElementType != CSSM_LIST_ELEMENT_DATUM || !v[4]->Element.Word.Data ||
            v[4]->Element.Word.Length < 8 || v[4]->Element.Word.Length > 65536) return 0;
        CFDataRef data = CFDataCreate(NULL, v[4]->Element.Word.Data, v[4]->Element.Word.Length);
        SecRequirementRef requirement = NULL;
        OSStatus status = data ? SecRequirementCreateWithData(data, kSecCSDefaultFlags, &requirement) : errSecParam;
        if (data) CFRelease(data); if (requirement) CFRelease(requirement);
        if (status != errSecSuccess) return 0;
    }
    return master_data_equal(&left[4]->Element.Word, &right[4]->Element.Word);
}
static int master_subject_equal_mode(const CSSM_LIST *a, const CSSM_LIST *b, unsigned depth, int identity) {
    if (depth > 16 || a->ListType != b->ListType) return 0;
    if (identity) {
        int signedIdentity = master_signed_identity_equal(a, b);
        if (signedIdentity >= 0) return signedIdentity;
    }
    const CSSM_LIST_ELEMENT *x = a->Head, *y = b->Head;
    unsigned count = 0;
    while (x && y) {
        if (++count > 128 || x->ElementType != y->ElementType || x->WordID != y->WordID) return 0;
        switch (x->ElementType) {
        case CSSM_LIST_ELEMENT_DATUM:
            if (!master_data_equal(&x->Element.Word, &y->Element.Word)) return 0; break;
        case CSSM_LIST_ELEMENT_SUBLIST:
            if (!master_subject_equal_mode(&x->Element.Sublist, &y->Element.Sublist, depth + 1, identity)) return 0; break;
        case CSSM_LIST_ELEMENT_WORDID: break;
        default: return 0;
        }
        x = x->NextElement; y = y->NextElement;
    }
    return x == NULL && y == NULL;
}
static int master_subject_equal(const CSSM_LIST *a, const CSSM_LIST *b, unsigned depth) {
    return master_subject_equal_mode(a, b, depth, 0);
}
static int master_acl_equal_mode(const CSSM_ACL_ENTRY_PROTOTYPE *a, const CSSM_ACL_ENTRY_PROTOTYPE *b, int identity) {
    if (a->Delegate != b->Delegate || a->Authorization.NumberOfAuthTags != b->Authorization.NumberOfAuthTags ||
        a->Authorization.NumberOfAuthTags > 32 ||
        !master_data_equal(&a->TimeRange.StartDate, &b->TimeRange.StartDate) ||
        !master_data_equal(&a->TimeRange.EndDate, &b->TimeRange.EndDate) ||
        strncmp(a->EntryTag, b->EntryTag, sizeof(a->EntryTag)) != 0 ||
        !master_subject_equal_mode(&a->TypedSubject, &b->TypedSubject, 0, identity)) return 0;
    if (a->Authorization.NumberOfAuthTags && (!a->Authorization.AuthTags || !b->Authorization.AuthTags)) return 0;
    for (uint32 i = 0; i < a->Authorization.NumberOfAuthTags; i++) {
        if (a->Authorization.AuthTags[i] != b->Authorization.AuthTags[i]) return 0;
    }
    return 1;
}
static int master_system_acl(const CSSM_ACL_ENTRY_PROTOTYPE *a) {
    // These system metadata entries do not grant decrypt/change-owner/ACL/etc.
    // Never ignore an entry that combines one of these tags with permissions.
    if (a->Delegate || a->Authorization.NumberOfAuthTags != 1 || !a->Authorization.AuthTags ||
        a->TimeRange.StartDate.Length || a->TimeRange.EndDate.Length) return 0;
    if (a->Authorization.AuthTags[0] == CSSM_ACL_AUTHORIZATION_PARTITION_ID &&
        strncmp(a->EntryTag, CSSM_APPLE_ACL_TAG_PARTITION_ID, sizeof(a->EntryTag)) == 0) return 1;
    if (a->Authorization.AuthTags[0] == CSSM_ACL_AUTHORIZATION_INTEGRITY &&
        strncmp(a->EntryTag, CSSM_APPLE_ACL_TAG_INTEGRITY, sizeof(a->EntryTag)) == 0) return 2;
    return 0;
}
static int master_policy_equal_mode(const CSSM_ACL_OWNER_PROTOTYPE *owner, uint32 count, const CSSM_ACL_ENTRY_INFO *entries,
                              const CSSM_ACL_OWNER_PROTOTYPE *expectedOwner, uint32 expectedCount, const CSSM_ACL_ENTRY_INFO *expected, int identity) {
    if (!owner || !expectedOwner || !entries || !expected || !count || count > 32 || !expectedCount || expectedCount > 30 ||
        owner->Delegate != expectedOwner->Delegate || !master_subject_equal_mode(&owner->TypedSubject, &expectedOwner->TypedSubject, 0, identity)) return 0;
    unsigned matched = 0, systemSeen = 0;
    for (uint32 i = 0; i < count; i++) {
        int system = master_system_acl(&entries[i].EntryPublicInfo);
        if (system) {
            if (systemSeen & (1U << system)) return 0;
            systemSeen |= (1U << system); continue;
        }
        int found = 0;
        for (uint32 j = 0; j < expectedCount; j++) {
            if (!(matched & (1U << j)) && master_acl_equal_mode(&entries[i].EntryPublicInfo, &expected[j].EntryPublicInfo, identity)) {
                matched |= 1U << j; found = 1; break;
            }
        }
        if (!found) return 0;
    }
    return matched == ((1U << expectedCount) - 1);
}
static int master_policy_equal(const CSSM_ACL_OWNER_PROTOTYPE *owner, uint32 count, const CSSM_ACL_ENTRY_INFO *entries,
                              const CSSM_ACL_OWNER_PROTOTYPE *expectedOwner, uint32 expectedCount, const CSSM_ACL_ENTRY_INFO *expected) {
    return master_policy_equal_mode(owner, count, entries, expectedOwner, expectedCount, expected, 0);
}
// Explicit repair only: duplicate entries must each be equivalent to one of
// the expected narrow permissions. Ordinary custody still rejects duplicates.
static void master_free_policy(CSSM_ACL_OWNER_PROTOTYPE *, uint32, CSSM_ACL_ENTRY_INFO *);
static int master_access_policy_equal(SecAccessRef, SecAccessRef);
static int master_duplicate_policy_equivalent(const CSSM_ACL_OWNER_PROTOTYPE *owner, uint32 count, const CSSM_ACL_ENTRY_INFO *entries,
    const CSSM_ACL_OWNER_PROTOTYPE *expectedOwner, uint32 expectedCount, const CSSM_ACL_ENTRY_INFO *expected) {
    if (!owner || !expectedOwner || !entries || !expected || !count || count > 32 || !expectedCount || expectedCount > 15 ||
        owner->Delegate != expectedOwner->Delegate || !master_subject_equal_mode(&owner->TypedSubject, &expectedOwner->TypedSubject, 0, 1)) return 0;
    unsigned matched[16] = {0}, systems = 0;
    for (uint32 i = 0; i < count; i++) {
        int system = master_system_acl(&entries[i].EntryPublicInfo);
        if (system) { if (systems & (1U << system)) return 0; systems |= 1U << system; continue; }
        int found = 0;
        for (uint32 j = 0; j < expectedCount; j++) {
            if (master_acl_equal_mode(&entries[i].EntryPublicInfo, &expected[j].EntryPublicInfo, 1)) {
                if (++matched[j] > 2) return 0;
                found = 1; break;
            }
        }
        if (!found) return 0;
    }
    for (uint32 j = 0; j < expectedCount; j++) if (!matched[j]) return 0;
    return 1;
}
static int master_access_duplicate_equivalent(SecAccessRef copy, SecAccessRef expected) {
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL, *expectedOwner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL, *expectedEntries = NULL; uint32 count = 0, expectedCount = 0;
    int valid = copy && expected && SecAccessGetOwnerAndACL(copy, &owner, &count, &entries) == errSecSuccess &&
        SecAccessGetOwnerAndACL(expected, &expectedOwner, &expectedCount, &expectedEntries) == errSecSuccess &&
        master_duplicate_policy_equivalent(owner, count, entries, expectedOwner, expectedCount, expectedEntries);
    master_free_policy(owner, count, entries); master_free_policy(expectedOwner, expectedCount, expectedEntries); return valid;
}

// Edit the detached existing access object, preserving its ACL handles. Passing
// a newly-created SecAccess to SetAccess can append entries instead of replacing
// them. This function itself never queries or mutates a Keychain item.
static int master_rights_equal(CFArrayRef a, CFArrayRef b) {
    if (!a || !b || CFArrayGetCount(a) != CFArrayGetCount(b) || CFArrayGetCount(a) > 32) return 0;
    const void *left[32], *right[32]; CFIndex size = CFArrayGetCount(a);
    CFArrayGetValues(a, CFRangeMake(0, size), left); CFArrayGetValues(b, CFRangeMake(0, size), right);
    CFSetRef x = CFSetCreate(NULL, left, size, &kCFTypeSetCallBacks), y = CFSetCreate(NULL, right, size, &kCFTypeSetCallBacks);
    int equal = x && y && CFSetGetCount(x) == size && CFSetGetCount(y) == size && CFEqual(x, y);
    if (x) CFRelease(x); if (y) CFRelease(y); return equal;
}
static int master_prepare_equivalent_access(SecAccessRef copy, SecAccessRef expected, SecTrustedApplicationRef target) {
    if (!copy || !expected || !target || copy == expected) return 0;
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL, *expectedOwner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL, *expectedEntries = NULL;
    uint32 count = 0, expectedCount = 0;
    int valid = SecAccessGetOwnerAndACL(copy, &owner, &count, &entries) == errSecSuccess &&
        SecAccessGetOwnerAndACL(expected, &expectedOwner, &expectedCount, &expectedEntries) == errSecSuccess &&
        master_duplicate_policy_equivalent(owner, count, entries, expectedOwner, expectedCount, expectedEntries);
    master_free_policy(owner, count, entries); master_free_policy(expectedOwner, expectedCount, expectedEntries);
    if (!valid) { master_diagnostic("repairPolicyProof", errSecAuthFailed); return 0; }
    CFArrayRef acls = NULL, expectedACLs = NULL;
    if (SecAccessCopyACLList(copy, &acls) != errSecSuccess || !acls ||
        SecAccessCopyACLList(expected, &expectedACLs) != errSecSuccess || !expectedACLs) {
        if (acls) CFRelease(acls); if (expectedACLs) CFRelease(expectedACLs); return 0;
    }
    CFIndex expectedSize = CFArrayGetCount(expectedACLs), size = CFArrayGetCount(acls);
    unsigned seen[16] = {0};
    valid = expectedSize > 0 && expectedSize <= 15 && size > 0 && size <= 32;
    for (CFIndex i = 0; valid && i < size; i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef rights = SecACLCopyAuthorizations(acl);
        if (!rights) { master_diagnostic("repairRights", errSecParam); valid = 0; break; }
        CFIndex matching = -1;
        for (CFIndex j = 0; j < expectedSize; j++) {
            CFArrayRef expectedRights = SecACLCopyAuthorizations((SecACLRef)CFArrayGetValueAtIndex(expectedACLs, j));
            Boolean same = master_rights_equal(rights, expectedRights);
            if (expectedRights) CFRelease(expectedRights);
            if (same) { if (matching >= 0) { valid = 0; break; } matching = j; }
        }
        Boolean decrypt = CFArrayContainsValue(rights, CFRangeMake(0, CFArrayGetCount(rights)), kSecACLAuthorizationDecrypt);
        CFRelease(rights);
        if (!valid) break;
        if (matching < 0) continue; // Independently validated system metadata.
        if (++seen[matching] > 1) {
            OSStatus removed = SecACLRemove(acl); valid = removed == errSecSuccess;
            if (!valid) master_diagnostic("repairDuplicate", removed); continue;
        }
        if (decrypt) {
            CFArrayRef applications = NULL; CFStringRef description = NULL; SecKeychainPromptSelector prompt = 0;
            valid = SecACLCopyContents(acl, &applications, &description, &prompt) == errSecSuccess &&
                applications && CFArrayGetCount(applications) == 1 && description;
            if (!valid) master_diagnostic("repairContents", errSecParam);
            if (valid) {
                OSStatus changed = SecACLSetContents(acl, (CFArrayRef)@[ (id)target ], description, prompt);
                valid = changed == errSecSuccess; if (!valid) master_diagnostic("repairTarget", changed);
            }
            if (applications) CFRelease(applications); if (description) CFRelease(description);
        }
    }
    for (CFIndex j = 0; valid && j < expectedSize; j++) if (!seen[j]) valid = 0;
    CFRelease(acls); CFRelease(expectedACLs);
    // Apple's detached Access retains deleted ACL handles until SetAccess
    // applies them. copyOwnerAndAcl also exports those marked entries. Verify
    // their unchanged authority here; require exact live readback after commit.
    int confirmed = valid && master_access_duplicate_equivalent(copy, expected);
    if (!confirmed) master_diagnostic("repairFinalPolicy", errSecAuthFailed);
    return confirmed;
}
static SecAccessRef master_expected_access(void) {
    SecTrustedApplicationRef application = NULL; SecAccessRef access = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &application);
    if (status == errSecSuccess) status = SecAccessCreate(CFSTR("Mechanize Vault encryption"), (CFArrayRef)@[ (id)application ], &access);
    if (application) CFRelease(application);
    if (status != errSecSuccess) { if (access) CFRelease(access); return NULL; }
    return access;
}
// SecAccessGetOwnerAndACL deep-copies into the standard malloc allocator.
// Release those public subject/authorization structures after comparison.
static void master_free_subject(CSSM_LIST *list) {
    CSSM_LIST_ELEMENT *element = list->Head;
    while (element) {
        CSSM_LIST_ELEMENT *next = element->NextElement;
        if (element->ElementType == CSSM_LIST_ELEMENT_SUBLIST) master_free_subject(&element->Element.Sublist);
        else if (element->ElementType == CSSM_LIST_ELEMENT_DATUM) free(element->Element.Word.Data);
        free(element); element = next;
    }
}
static void master_free_policy(CSSM_ACL_OWNER_PROTOTYPE *owner, uint32 count, CSSM_ACL_ENTRY_INFO *entries) {
    if (owner) { master_free_subject(&owner->TypedSubject); free(owner); }
    if (entries) {
        for (uint32 i = 0; i < count; i++) {
            CSSM_ACL_ENTRY_PROTOTYPE *entry = &entries[i].EntryPublicInfo;
            master_free_subject(&entry->TypedSubject); free(entry->Authorization.AuthTags);
            free(entry->TimeRange.StartDate.Data); free(entry->TimeRange.EndDate.Data);
        }
        free(entries);
    }
}
// Pure preparation over an independently copied access object. This never
// queries or changes a Keychain item. The future isolated migration backend
// must provide verified old/new policies and discard the copy on any failure.
static int master_access_policy_equal(SecAccessRef actual, SecAccessRef expected) {
    if (!actual || !expected) return 0;
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL, *expectedOwner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL, *expectedEntries = NULL;
    uint32 count = 0, expectedCount = 0;
    int valid = SecAccessGetOwnerAndACL(actual, &owner, &count, &entries) == errSecSuccess &&
        SecAccessGetOwnerAndACL(expected, &expectedOwner, &expectedCount, &expectedEntries) == errSecSuccess &&
        master_policy_equal(owner, count, entries, expectedOwner, expectedCount, expectedEntries);
    master_free_policy(owner, count, entries); master_free_policy(expectedOwner, expectedCount, expectedEntries);
    return valid;
}
static int master_prepare_single_acl(SecAccessRef copy, SecAccessRef expectedOld,
                                     SecTrustedApplicationRef target, SecAccessRef expectedNew) {
    if (!copy || !expectedOld || !target || !expectedNew || copy == expectedOld || copy == expectedNew ||
        !master_access_policy_equal(copy, expectedOld)) return 0;
    CFArrayRef acls = NULL;
    if (SecAccessCopyACLList(copy, &acls) != errSecSuccess || !acls) return 0;
    SecACLRef limited = NULL;
    int valid = 1;
    CFIndex count = CFArrayGetCount(acls);
    if (count < 1 || count > 32) valid = 0;
    for (CFIndex i = 0; valid && i < count; i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        if (!acl || CFGetTypeID(acl) != SecACLGetTypeID()) { valid = 0; break; }
        CFArrayRef rights = SecACLCopyAuthorizations(acl);
        if (!rights || CFArrayGetCount(rights) > 32) { if (rights) CFRelease(rights); valid = 0; break; }
        Boolean decrypt = CFArrayContainsValue(rights, CFRangeMake(0, CFArrayGetCount(rights)), kSecACLAuthorizationDecrypt);
        CFRelease(rights);
        if (decrypt) {
            if (limited) { valid = 0; break; }
            limited = acl;
        }
    }
    if (valid && limited) {
        CFArrayRef applications = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        valid = SecACLCopyContents(limited, &applications, &description, &prompt) == errSecSuccess &&
            applications && CFArrayGetCount(applications) == 1 && description;
        if (valid) {
            CFArrayRef singleton = (CFArrayRef)@[ (id)target ];
            valid = SecACLSetContents(limited, singleton, description, prompt) == errSecSuccess &&
                master_access_policy_equal(copy, expectedNew);
        }
        if (applications) CFRelease(applications); if (description) CFRelease(description);
    } else valid = 0;
    CFRelease(acls);
    return valid;
}
int mechanize_master_prepare_single_acl(SecAccessRef copy, SecAccessRef expectedOld,
                                        SecTrustedApplicationRef target, SecAccessRef expectedNew) {
    return master_prepare_single_acl(copy, expectedOld, target, expectedNew);
}
// Metadata-only bridge for the separate migration preflight adapter. No item
// lookup, mutation, material read or authority bypass is performed here.
int mechanize_master_access_policy_matches(SecAccessRef actual, SecAccessRef expected) {
    return master_access_policy_equal(actual, expected);
}
static int master_custody(SecKeychainItemRef item) {
    SecAccessRef actual = NULL, expected = master_expected_access();
    if (!expected || SecKeychainItemCopyAccess(item, &actual) != errSecSuccess || !actual) {
        if (expected) CFRelease(expected); if (actual) CFRelease(actual); return 0;
    }
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL, *expectedOwner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL, *expectedEntries = NULL;
    uint32 count = 0, expectedCount = 0;
    int valid = SecAccessGetOwnerAndACL(actual, &owner, &count, &entries) == errSecSuccess &&
        SecAccessGetOwnerAndACL(expected, &expectedOwner, &expectedCount, &expectedEntries) == errSecSuccess &&
        master_policy_equal_mode(owner, count, entries, expectedOwner, expectedCount, expectedEntries, 1);
    master_free_policy(owner, count, entries); master_free_policy(expectedOwner, expectedCount, expectedEntries);
    CFRelease(actual); CFRelease(expected);
    if (!valid) master_diagnostic("custodyMismatch", errSecAuthFailed);
    return valid;
}
// Exact service/account search over the normal search list. Match-all is
// mandatory: selecting the first item silently accepts ambiguous keychains.
// Returned item and persistent identity refer to the same custody-checked item.
static int master_unique_item(const char *service, const char *account, SecKeychainItemRef *item, CFDataRef *identity) {
    *item = NULL; *identity = NULL;
    NSMutableDictionary *query = master_query(service, account); if (!query) return -1;
    query[(id)kSecMatchLimit] = (id)kSecMatchLimitAll;
    query[(id)kSecReturnRef] = @YES;
    CFTypeRef raw = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &raw);
    if (status == errSecItemNotFound) { if (raw) CFRelease(raw); return 0; }
    if (status != errSecSuccess || !raw || CFGetTypeID(raw) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)raw) != 1) {
        master_diagnostic("metadataSearch", status);
        if (raw) CFRelease(raw); return -1;
    }
    CFTypeRef value = CFArrayGetValueAtIndex((CFArrayRef)raw, 0);
    if (!value || CFGetTypeID(value) != SecKeychainItemGetTypeID() || !master_custody((SecKeychainItemRef)value)) {
        CFRelease(raw); return -1;
    }
    *item = (SecKeychainItemRef)CFRetain(value); CFRelease(raw);
    status = SecKeychainItemCreatePersistentReference(*item, identity);
    if (status != errSecSuccess || !*identity || CFGetTypeID(*identity) != CFDataGetTypeID() ||
        CFDataGetLength(*identity) <= 0 || CFDataGetLength(*identity) > 16384) {
        CFRelease(*item); *item = NULL; if (*identity) CFRelease(*identity); *identity = NULL; return -1;
    }
    return 0;
}
int mechanize_master_inspect(const char *service, const char *account, const char *requirement, CFDataRef *identity) {
    @autoreleasepool {
        if (!identity) return -1; *identity = NULL;
        if (!master_own_code(requirement) || SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return -1;
        SecKeychainItemRef item = NULL;
        int status = master_unique_item(service, account, &item, identity);
        if (item) CFRelease(item); return status;
    }
}
int mechanize_master_read(const char *service, const char *account, const char *requirement, const void *identityBytes, int count, CFDataRef *data) {
    @autoreleasepool {
        if (!data) return -1; *data = NULL;
        if (!identityBytes || count <= 0 || count > 16384 || !master_own_code(requirement) ||
            SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return -1;
        CFDataRef expected = CFDataCreate(NULL, identityBytes, count), identity = NULL;
        SecKeychainItemRef item = NULL;
        int result = -1;
        if (expected && master_unique_item(service, account, &item, &identity) == 0 && item && identity && CFEqual(expected, identity)) {
            NSMutableDictionary *query = master_query(service, account);
            query[(id)kSecMatchItemList] = @[ (id)item ];
            query[(id)kSecReturnData] = @YES;
            query[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
            CFTypeRef raw = NULL;
            OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &raw);
            if (status == errSecSuccess && raw && CFGetTypeID(raw) == CFDataGetTypeID() && CFDataGetLength((CFDataRef)raw) > 0 && CFDataGetLength((CFDataRef)raw) <= 256 && master_custody(item)) {
                *data = (CFDataRef)raw; result = 0;
            } else {
                master_diagnostic("keyRead", status);
                if (raw) CFRelease(raw);
            }
        }
        if (expected) CFRelease(expected); if (identity) CFRelease(identity); if (item) CFRelease(item);
        return result;
    }
}
// Native setup only. Refresh public legacy image metadata for the same signing
// identity and permission set. No value read, key replacement or wider ACL.
int mechanize_master_refresh_access(const char *service, const char *account, const char *requirement,
                                   const void *identityBytes, int count, CFDataRef *confirmed) {
    @autoreleasepool {
        if (!confirmed) return -1; *confirmed = NULL;
        if (!identityBytes || count <= 0 || count > 16384 || !master_own_code(requirement) ||
            SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return -1;
        CFDataRef expectedIdentity = CFDataCreate(NULL, identityBytes, count), identity = NULL, afterIdentity = NULL;
        SecKeychainItemRef item = NULL, afterItem = NULL;
        SecAccessRef access = NULL, replacement = master_expected_access();
        SecTrustedApplicationRef target = NULL;
        CSSM_ACL_OWNER_PROTOTYPE *owner = NULL, *expectedOwner = NULL;
        CSSM_ACL_ENTRY_INFO *entries = NULL, *expectedEntries = NULL;
        uint32 entryCount = 0, expectedCount = 0;
        int result = -1;
        if (expectedIdentity && replacement && SecTrustedApplicationCreateFromPath(NULL, &target) == errSecSuccess && target &&
            master_unique_item(service, account, &item, &identity) == 0 &&
            item && identity && CFEqual(expectedIdentity, identity) &&
            SecKeychainItemCopyAccess(item, &access) == errSecSuccess && access &&
            SecAccessGetOwnerAndACL(access, &owner, &entryCount, &entries) == errSecSuccess &&
            SecAccessGetOwnerAndACL(replacement, &expectedOwner, &expectedCount, &expectedEntries) == errSecSuccess &&
            master_policy_equal_mode(owner, entryCount, entries, expectedOwner, expectedCount, expectedEntries, 1) &&
            master_prepare_equivalent_access(access, replacement, target)) {
            OSStatus status = SecKeychainItemSetAccess(item, access);
            if (status != errSecSuccess) master_diagnostic("accessRefresh", status);
            if (status == errSecSuccess && master_unique_item(service, account, &afterItem, &afterIdentity) == 0 &&
                afterItem && afterIdentity && CFEqual(expectedIdentity, afterIdentity)) {
                SecAccessRef after = NULL;
                if (SecKeychainItemCopyAccess(afterItem, &after) == errSecSuccess &&
                    master_access_policy_equal(after, replacement)) {
                    *confirmed = (CFDataRef)CFRetain(afterIdentity); result = 0;
                }
                if (after) CFRelease(after);
            }
        }
        master_free_policy(owner, entryCount, entries); master_free_policy(expectedOwner, expectedCount, expectedEntries);
        if (access) CFRelease(access); if (replacement) CFRelease(replacement);
        if (target) CFRelease(target);
        if (item) CFRelease(item); if (afterItem) CFRelease(afterItem);
        if (expectedIdentity) CFRelease(expectedIdentity); if (identity) CFRelease(identity); if (afterIdentity) CFRelease(afterIdentity);
        return result;
    }
}
int mechanize_master_add(const char *service, const char *account, const char *requirement, const void *bytes, int count, CFDataRef *identity) {
    @autoreleasepool {
        if (!identity) return -1; *identity = NULL;
        if (!bytes || count <= 0 || count > 256 || !master_own_code(requirement) || SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return -1;
        NSMutableDictionary *query = master_query(service, account); if (!query) return -1;
        SecAccessRef access = master_expected_access(); if (!access) return -1;
        CFDataRef data = CFDataCreate(NULL, bytes, count);
        if (!data) { CFRelease(access); return -1; }
        query[(id)kSecAttrAccess] = (id)access;
        query[(id)kSecValueData] = (id)data;
        query[(id)kSecAttrLabel] = @"Mechanize Vault encryption";
        query[(id)kSecReturnRef] = @YES;
        CFTypeRef created = NULL;
        OSStatus status = SecItemAdd((CFDictionaryRef)query, &created);
        CFRelease(data); CFRelease(access);
        int result = -1;
        if (status == errSecSuccess && created && CFGetTypeID(created) == SecKeychainItemGetTypeID() && master_custody((SecKeychainItemRef)created)) {
            CFDataRef createdIdentity = NULL, uniqueIdentity = NULL; SecKeychainItemRef unique = NULL;
            if (SecKeychainItemCreatePersistentReference((SecKeychainItemRef)created, &createdIdentity) == errSecSuccess && createdIdentity &&
                master_unique_item(service, account, &unique, &uniqueIdentity) == 0 && unique && uniqueIdentity && CFEqual(createdIdentity, uniqueIdentity)) {
                *identity = (CFDataRef)CFRetain(createdIdentity); result = 0;
            }
            if (createdIdentity) CFRelease(createdIdentity); if (uniqueIdentity) CFRelease(uniqueIdentity); if (unique) CFRelease(unique);
        }
        if (created) CFRelease(created);
        // Failure preserves the created item; never rewrite or delete its ACL.
        return result;
    }
}
