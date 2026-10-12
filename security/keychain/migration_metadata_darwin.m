#import <Security/Security.h>
#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "migration_metadata_darwin.h"

// This adapter is metadata-only. It has no SetAccess, ReturnData, item creation,
// deletion, or UI-enabling call. An isolated write executor remains required.
static int migration_code(const char *path, const char *text) {
    if (!path || !text) return 0;
    char canonical[PATH_MAX];
    if (!realpath(path, canonical) || strcmp(path, canonical)) return 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CFStringRef rule = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    SecRequirementRef requirement = NULL; SecStaticCodeRef code = NULL;
    OSStatus status = url && rule ? SecRequirementCreateWithString(rule, kSecCSDefaultFlags, &requirement) : errSecParam;
    if (status == errSecSuccess) status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    if (url) CFRelease(url); if (rule) CFRelease(rule);
    if (requirement) CFRelease(requirement); if (code) CFRelease(code);
    return status == errSecSuccess;
}
static SecAccessRef migration_expected(const char *path) {
    SecTrustedApplicationRef app = NULL; SecAccessRef access = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(path, &app);
    if (status == errSecSuccess) status = SecAccessCreate(CFSTR("Mechanize Vault encryption"), (CFArrayRef)@[ (id)app ], &access);
    if (app) CFRelease(app);
    if (status != errSecSuccess) { if (access) CFRelease(access); return NULL; }
    return access;
}
static int migration_unique_metadata(const char *service, const char *account, CFDataRef *identity, SecAccessRef *policy) {
    if (!service || !account || !identity || !policy) return 0;
    *identity = NULL; *policy = NULL;
    NSString *s = [NSString stringWithUTF8String:service], *a = [NSString stringWithUTF8String:account];
    if (!s || !a || SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return 0;
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: s, (id)kSecAttrAccount: a,
        (id)kSecAttrSynchronizable: @NO,
        (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIFail,
        (id)kSecMatchLimit: (id)kSecMatchLimitAll,
        (id)kSecReturnRef: @YES
    };
    CFTypeRef raw = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &raw);
    int valid = status == errSecSuccess && raw && CFGetTypeID(raw) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)raw) == 1;
    SecKeychainItemRef item = valid ? (SecKeychainItemRef)CFArrayGetValueAtIndex((CFArrayRef)raw, 0) : NULL;
    valid = item && CFGetTypeID(item) == SecKeychainItemGetTypeID() &&
        SecKeychainItemCreatePersistentReference(item, identity) == errSecSuccess && *identity &&
        CFGetTypeID(*identity) == CFDataGetTypeID() && CFDataGetLength(*identity) > 0 && CFDataGetLength(*identity) <= 16384 &&
        SecKeychainItemCopyAccess(item, policy) == errSecSuccess && *policy;
    if (raw) CFRelease(raw);
    if (!valid) {
        if (*identity) CFRelease(*identity); if (*policy) CFRelease(*policy);
        *identity = NULL; *policy = NULL;
    }
    return valid;
}
void mechanize_migration_metadata_destroy(MechanizeMigrationMetadata *snapshot) {
    if (!snapshot) return;
    if (snapshot->identity) CFRelease(snapshot->identity);
    if (snapshot->oldPolicy) CFRelease(snapshot->oldPolicy);
    free(snapshot);
}
MechanizeMigrationMetadata *mechanize_migration_metadata_prepare(const char *path, const char *oldRule, const char *service, const char *account) {
    @autoreleasepool {
        if (!migration_code(path, oldRule)) return NULL;
        SecAccessRef expected = migration_expected(path), actual = NULL; CFDataRef identity = NULL;
        int valid = expected && migration_unique_metadata(service, account, &identity, &actual) &&
            mechanize_master_access_policy_matches(actual, expected) && migration_code(path, oldRule);
        if (expected) CFRelease(expected);
        if (!valid) { if (identity) CFRelease(identity); if (actual) CFRelease(actual); return NULL; }
        MechanizeMigrationMetadata *snapshot = calloc(1, sizeof(*snapshot));
        if (!snapshot) { CFRelease(identity); CFRelease(actual); return NULL; }
        snapshot->identity = identity; snapshot->oldPolicy = actual; atomic_init(&snapshot->attempted, false);
        return snapshot;
    }
}
int mechanize_migration_metadata_identity(MechanizeMigrationMetadata *snapshot, CFDataRef *identity) {
    if (!snapshot || !snapshot->identity || !identity) return 0;
    *identity = (CFDataRef)CFRetain(snapshot->identity); return 1;
}
int mechanize_migration_metadata_verify(MechanizeMigrationMetadata *snapshot, const char *path, const char *newRule, const char *service, const char *account) {
    @autoreleasepool {
        if (!snapshot || !snapshot->identity || !snapshot->oldPolicy || !migration_code(path, newRule)) return 0;
        CFDataRef identity = NULL; SecAccessRef actual = NULL;
        int valid = migration_unique_metadata(service, account, &identity, &actual) && CFEqual(identity, snapshot->identity) &&
            mechanize_master_access_policy_matches(actual, snapshot->oldPolicy) && migration_code(path, newRule);
        if (identity) CFRelease(identity); if (actual) CFRelease(actual);
        return valid;
    }
}
int mechanize_migration_metadata_inspect(const char *path, const char *newRule, const char *service, const char *account, const void *expectedIdentity, int count) {
    @autoreleasepool {
        if (!expectedIdentity || count <= 0 || count > 16384 || !migration_code(path, newRule)) return 0;
        CFDataRef expected = CFDataCreate(NULL, expectedIdentity, count), identity = NULL;
        SecAccessRef policy = migration_expected(path), actual = NULL;
        int valid = expected && policy && migration_unique_metadata(service, account, &identity, &actual) &&
            CFEqual(identity, expected) && mechanize_master_access_policy_matches(actual, policy) && migration_code(path, newRule);
        if (expected) CFRelease(expected); if (identity) CFRelease(identity);
        if (policy) CFRelease(policy); if (actual) CFRelease(actual);
        return valid;
    }
}
