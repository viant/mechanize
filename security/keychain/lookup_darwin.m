#import <Security/Security.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

OSStatus mechanize_keychain_lookup(const char *service, const char *account, CFDataRef *result) {
 LAContext *authContext = [[LAContext alloc] init];
 authContext.interactionNotAllowed = YES;
 CFStringRef s = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
 CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
 if (!s || !a) { if (s) CFRelease(s); if (a) CFRelease(a); [authContext release]; return errSecParam; }
 const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit, kSecUseAuthenticationContext, kSecAttrSynchronizable };
 const void *values[] = { kSecClassGenericPassword, s, a, kCFBooleanTrue, kSecMatchLimitOne, authContext, kCFBooleanFalse };
 CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 7, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
 CFRelease(s); CFRelease(a); [authContext release];
 if (!query) return errSecAllocate;
 OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)result);
 CFRelease(query);
 if (status == errSecSuccess && (!*result || CFGetTypeID(*result) != CFDataGetTypeID())) {
  if (*result) CFRelease(*result); *result = NULL; return errSecDecode;
 }
 return status;
}
