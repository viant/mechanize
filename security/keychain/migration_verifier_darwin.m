#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <limits.h>
#include <string.h>

// Public code identity metadata only. No Keychain, credentials, authorization
// UI, trust modification, item mutation or process creation is performed here.
int mechanize_migration_verify_process(int pid, const char *path, const char *text) {
    const char *prefix = "identifier \"com.viant.mechanize.custody-migration\" and cdhash H\"";
    if (pid <= 0 || !path || path[0] != '/' || strnlen(path, PATH_MAX) >= PATH_MAX || !text) return 0;
    size_t prefixLength = strlen(prefix), length = strnlen(text, 512);
    if (length != prefixLength + 41 || strncmp(text, prefix, prefixLength) || text[length - 1] != '"') return 0;
    for (size_t i = prefixLength; i < prefixLength + 40; i++) {
        char c = text[i]; if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    const void *keys[] = { kSecGuestAttributePid }, *values[] = { number };
    CFDictionaryRef attributes = number ? CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
    CFStringRef ruleString = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    SecRequirementRef requirement = NULL; SecCodeRef guest = NULL; CFURLRef actualPath = NULL;
    OSStatus status = attributes && ruleString ? SecRequirementCreateWithString(ruleString, kSecCSDefaultFlags, &requirement) : errSecParam;
    if (status == errSecSuccess) status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &guest);
    if (status == errSecSuccess) status = SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement);
    if (status == errSecSuccess) status = SecCodeCopyPath(guest, kSecCSDefaultFlags, &actualPath);
    UInt8 representation[PATH_MAX];
    int valid = status == errSecSuccess && actualPath && CFURLGetFileSystemRepresentation(actualPath, true, representation, sizeof(representation)) &&
        strcmp(path, (const char *)representation) == 0;
    if (number) CFRelease(number); if (attributes) CFRelease(attributes); if (ruleString) CFRelease(ruleString);
    if (requirement) CFRelease(requirement); if (guest) CFRelease(guest); if (actualPath) CFRelease(actualPath);
    return valid;
}
