#import "migration_metadata_darwin.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Source-only isolated-executor primitive. No normal broker role can pass the
// first gate. No exported constructor/endpoint or child-launch path enables it.
// A qualified single-purpose process, deadline watchdog, durable installer/ACL
// journals and independently bound local approval are prerequisites for use.
// In particular, a Go context cannot interrupt SecurityAgent or this C call.
// Results: 0 = pre-dispatch refusal; 1 = same-item/full-policy verified;
// -1 = attempted/unknown. Framework errors and private metadata never escape.

static int migration_write_rule(const char *text, const char *prefix) {
    if (!text || !prefix) return 0;
    size_t count = strlen(prefix), length = strnlen(text, 512);
    if (length != count + 41 || strncmp(text, prefix, count) || text[length - 1] != '"') return 0;
    for (size_t i = count; i < count + 40; i++) {
        char value = text[i];
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return 0;
    }
    return 1;
}
static const char *migration_executor_prefix = "identifier \"com.viant.mechanize.custody-migration\" and cdhash H\"";
static const char *migration_broker_prefix = "identifier \"com.viant.mechanize.broker\" and cdhash H\"";

static int migration_write_own_code(const char *text) {
    if (!migration_write_rule(text, migration_executor_prefix)) return 0;
    CFStringRef string = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    SecRequirementRef rule = NULL; SecCodeRef own = NULL;
    OSStatus status = string ? SecRequirementCreateWithString(string, kSecCSDefaultFlags, &rule) : errSecParam;
    if (status == errSecSuccess) status = SecCodeCopySelf(kSecCSDefaultFlags, &own);
    if (status == errSecSuccess) status = SecCodeCheckValidity(own, kSecCSStrictValidate, rule);
    if (string) CFRelease(string); if (rule) CFRelease(rule); if (own) CFRelease(own);
    return status == errSecSuccess;
}

// Safe role probe: code-signature inspection only, never Keychain access.
int mechanize_migration_executor_matches(const char *text) {
    return migration_write_own_code(text);
}

static int migration_write_requirement_equal(SecRequirementRef first, SecRequirementRef second) {
    CFDataRef a = NULL, b = NULL;
    int same = first && second && SecRequirementCopyData(first, kSecCSDefaultFlags, &a) == errSecSuccess && a &&
        SecRequirementCopyData(second, kSecCSDefaultFlags, &b) == errSecSuccess && b && CFEqual(a, b);
    if (a) CFRelease(a); if (b) CFRelease(b); return same;
}
// A stable signer is adopted only from the exact already-reviewed image below.
// Neither the caller nor a Team/path/anchor-only DR chooses signer authority.
static int migration_write_stable_designated(SecStaticCodeRef code, SecRequirementRef designated) {
    CFDictionaryRef info = NULL;
    SecPolicyRef policy = NULL;
    SecTrustRef trust = NULL;
    CFDataRef leafDER = NULL;
    CFStringRef expectedString = NULL;
    SecRequirementRef expected = NULL;
    int valid = 0;
    if (!code || !designated || SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess || !info) goto finish;
    CFTypeRef raw = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (!raw || CFGetTypeID(raw) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)raw) < 1) goto finish;
    CFArrayRef chain = (CFArrayRef)raw;
    SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0);
    if (!leaf || CFGetTypeID(leaf) != SecCertificateGetTypeID()) goto finish;
    policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, NULL);
    if (!policy || SecTrustCreateWithCertificates(chain, policy, &trust) != errSecSuccess || !trust ||
        SecTrustSetNetworkFetchAllowed(trust, false) != errSecSuccess || !SecTrustEvaluateWithError(trust, NULL)) goto finish;
    leafDER = SecCertificateCopyData(leaf);
    if (!leafDER || CFDataGetLength(leafDER) <= 0 || CFDataGetLength(leafDER) > 65536) goto finish;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    if (!CC_SHA1(CFDataGetBytePtr(leafDER), (CC_LONG)CFDataGetLength(leafDER), digest)) goto finish;
    char hash[CC_SHA1_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) snprintf(hash + i * 2, 3, "%02x", digest[i]);
    char text[160];
    snprintf(text, sizeof(text), "identifier \"com.viant.mechanize.broker\" and certificate leaf = H\"%s\"", hash);
    expectedString = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    if (!expectedString || SecRequirementCreateWithString(expectedString, kSecCSDefaultFlags, &expected) != errSecSuccess) goto finish;
    valid = migration_write_requirement_equal(designated, expected) &&
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate, expected) == errSecSuccess;
finish:
    if (info) CFRelease(info); if (policy) CFRelease(policy); if (trust) CFRelease(trust);
    if (leafDER) CFRelease(leafDER); if (expectedString) CFRelease(expectedString); if (expected) CFRelease(expected);
    return valid;
}

static int migration_write_candidate(const char *path, const char *text) {
    if (!path || !migration_write_rule(text, migration_broker_prefix) || path[0] != '/' ||
        strnlen(path, PATH_MAX) >= PATH_MAX || strchr(path, '\n') || strchr(path, '\r')) return 0;
    char canonical[PATH_MAX];
    if (!realpath(path, canonical) || strcmp(path, canonical)) return 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CFStringRef string = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    SecRequirementRef rule = NULL, designated = NULL, hashOnly = NULL;
    SecStaticCodeRef code = NULL;
    OSStatus status = url && string ? SecRequirementCreateWithString(string, kSecCSDefaultFlags, &rule) : errSecParam;
    if (status == errSecSuccess) status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, rule);
    if (status == errSecSuccess) status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &designated);
    // A file can satisfy an exact external pin while carrying a broader signer
    // DR. CreateFromPath would place that broader DR into the ACL. Refuse it.
    // Preserve the explicit exact rule and normal ad-hoc singleton hash DR.
    // A certificate-backed stable DR must equal the fixed role+actual trusted
    // leaf rule. The reviewed external cdhash pin still binds this image.
    char hashRule[64];
    snprintf(hashRule, sizeof(hashRule), "cdhash H\"%.*s\"", 40, text + strlen(migration_broker_prefix));
    CFStringRef hashString = CFStringCreateWithCString(NULL, hashRule, kCFStringEncodingUTF8);
    if (status == errSecSuccess) status = hashString ? SecRequirementCreateWithString(hashString, kSecCSDefaultFlags, &hashOnly) : errSecParam;
    int valid = status == errSecSuccess &&
        (migration_write_requirement_equal(designated, rule) || migration_write_requirement_equal(designated, hashOnly) ||
         migration_write_stable_designated(code, designated));
    if (url) CFRelease(url); if (string) CFRelease(string); if (hashString) CFRelease(hashString);
    if (rule) CFRelease(rule); if (designated) CFRelease(designated); if (hashOnly) CFRelease(hashOnly); if (code) CFRelease(code);
    return valid;
}

// Return only a unique metadata reference. No ReturnData, item copying, create,
// deletion, content update or password-bearing API is permitted in this file.
static int migration_write_item(const char *service, const char *account,
                                SecKeychainItemRef *item, CFDataRef *identity, SecAccessRef *policy) {
    *item = NULL; *identity = NULL; *policy = NULL;
    if (!service || strcmp(service, "com.viant.mechanize.vault") || !account ||
        !strnlen(account, 1025) || strnlen(account, 1025) > 1024 || strchr(account, '\n') || strchr(account, '\r')) return 0;
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
    SecKeychainItemRef found = valid ? (SecKeychainItemRef)CFArrayGetValueAtIndex((CFArrayRef)raw, 0) : NULL;
    valid = found && CFGetTypeID(found) == SecKeychainItemGetTypeID() &&
        SecKeychainItemCreatePersistentReference(found, identity) == errSecSuccess && *identity &&
        CFGetTypeID(*identity) == CFDataGetTypeID() && CFDataGetLength(*identity) > 0 && CFDataGetLength(*identity) <= 16384 &&
        SecKeychainItemCopyAccess(found, policy) == errSecSuccess && *policy;
    if (valid) *item = (SecKeychainItemRef)CFRetain(found);
    if (raw) CFRelease(raw);
    if (!valid) {
        if (*identity) CFRelease(*identity); if (*policy) CFRelease(*policy);
        *identity = NULL; *policy = NULL;
    }
    return valid;
}

int mechanize_migration_write(MechanizeMigrationMetadata *snapshot, const char *path, const char *newBrokerRule,
                             const char *service, const char *account, const char *selfExecutorRequirement) {
    @autoreleasepool {
        // This must precede snapshot dereference, path IO, Keychain queries and
        // all interaction-policy calls. A broker/test binary cannot pass it.
        if (!migration_write_own_code(selfExecutorRequirement)) return 0;
        if (!snapshot || !snapshot->identity || !snapshot->oldPolicy ||
            CFGetTypeID(snapshot->identity) != CFDataGetTypeID() || CFDataGetLength(snapshot->identity) <= 0 ||
            CFDataGetLength(snapshot->identity) > 16384) return 0;
        if (atomic_load(&snapshot->attempted)) return -1;
        if (!migration_write_candidate(path, newBrokerRule)) return 0;

        SecKeychainItemRef initialItem = NULL, finalItem = NULL;
        CFDataRef initialIdentity = NULL, finalIdentity = NULL;
        SecAccessRef initialCopy = NULL, finalCopy = NULL, expectedNew = NULL;
        SecTrustedApplicationRef target = NULL;
        int result = 0;
        if (!migration_write_item(service, account, &initialItem, &initialIdentity, &initialCopy) ||
            !CFEqual(initialIdentity, snapshot->identity) ||
            !mechanize_master_access_policy_matches(initialCopy, snapshot->oldPolicy)) goto finish;
        if (SecTrustedApplicationCreateFromPath(path, &target) != errSecSuccess || !target ||
            SecAccessCreate(CFSTR("Mechanize Vault encryption"), (CFArrayRef)@[ (id)target ], &expectedNew) != errSecSuccess || !expectedNew ||
            !mechanize_master_prepare_single_acl(initialCopy, snapshot->oldPolicy, target, expectedNew)) goto finish;

        // Reacquire uniqueness, persistent identity and the exact old policy.
        // Prepare the final independent copy using CURRENT ACL handles; a
        // policy-equivalent external rewrite could have changed those handles.
        if (!migration_write_candidate(path, newBrokerRule) ||
            !migration_write_item(service, account, &finalItem, &finalIdentity, &finalCopy) ||
            !CFEqual(finalIdentity, snapshot->identity) || !CFEqual(finalIdentity, initialIdentity) ||
            !mechanize_master_access_policy_matches(finalCopy, snapshot->oldPolicy) ||
            !mechanize_master_prepare_single_acl(finalCopy, snapshot->oldPolicy, target, expectedNew) ||
            !migration_write_candidate(path, newBrokerRule) || !migration_write_own_code(selfExecutorRequirement)) goto finish;

        // The caller must exclude cooperating installer/broker activity. Public
        // Keychain APIs do not offer a compare-and-swap transaction spanning
        // metadata checks, filesystem pins and the subsequent ACL replacement.
        bool expectedAttempt = false;
        if (!atomic_compare_exchange_strong(&snapshot->attempted, &expectedAttempt, true)) { result = -1; goto finish; }
        result = -1;
        OSStatus mutation = errSecInternalComponent, restored = errSecInternalComponent;
        @try {
            if (SecKeychainSetUserInteractionAllowed(true) == errSecSuccess) {
                // Exactly one platform mutation. No retry or automatic reversal.
                mutation = SecKeychainItemSetAccess(finalItem, finalCopy);
            }
        } @catch (NSException *ignored) {
            (void)ignored;
        } @finally {
            restored = SecKeychainSetUserInteractionAllowed(false);
        }
        if (mutation != errSecSuccess || restored != errSecSuccess) goto finish;
        if (!migration_write_candidate(path, newBrokerRule) ||
            !mechanize_migration_metadata_inspect(path, newBrokerRule, service, account,
                CFDataGetBytePtr(snapshot->identity), (int)CFDataGetLength(snapshot->identity))) goto finish;
        result = 1;
    finish:
        if (initialItem) CFRelease(initialItem); if (finalItem) CFRelease(finalItem);
        if (initialIdentity) CFRelease(initialIdentity); if (finalIdentity) CFRelease(finalIdentity);
        if (initialCopy) CFRelease(initialCopy); if (finalCopy) CFRelease(finalCopy);
        if (expectedNew) CFRelease(expectedNew); if (target) CFRelease(target);
        return result;
    }
}
