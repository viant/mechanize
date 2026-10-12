//go:build darwin && cgo

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Read validated public signing metadata only. No Keychain access or UI.
char *mechanize_migration_own_requirement(void) {
    SecCodeRef own = NULL;
    CFDictionaryRef info = NULL;
    char *result = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &own) != errSecSuccess) goto done;
    if (SecCodeCheckValidity(own, kSecCSStrictValidate, NULL) != errSecSuccess) goto done;
    if (SecCodeCopySigningInformation(own, kSecCSSigningInformation, &info) != errSecSuccess) goto done;
    CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (!identifier || CFGetTypeID(identifier) != CFStringGetTypeID() ||
        CFStringCompare(identifier, CFSTR("com.viant.mechanize.custody-migration"), 0) != kCFCompareEqualTo ||
        !hash || CFGetTypeID(hash) != CFDataGetTypeID() || CFDataGetLength(hash) != 20) goto done;
    char hex[41]; const UInt8 *bytes = CFDataGetBytePtr(hash);
    for (int i=0;i<20;i++) snprintf(hex+i*2,3,"%02x",bytes[i]);
    result = calloc(160,1);
    if (result) snprintf(result,160,"identifier \"com.viant.mechanize.custody-migration\" and cdhash H\"%s\"",hex);
 done:
    if (info) CFRelease(info);
    if (own) CFRelease(own);
    return result;
}
