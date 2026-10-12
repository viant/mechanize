#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <time.h>

static int vault_process_info(pid_t pid, unsigned int uid, struct proc_bsdinfo *info) {
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info));
    return size == sizeof(*info) && info->pbi_pid == pid && info->pbi_uid == uid && info->pbi_status != 5;
}
static int vault_process_matches(pid_t pid, SecRequirementRef requirement) {
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    if (!number) return 0;
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { number };
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(number);
    if (!attributes) return 0;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    if (status != errSecSuccess || !code) return 0;
    status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    CFRelease(code);
    return status == errSecSuccess;
}

// Fixed value-free status contract shared with native_window_error.go.
enum {
    vault_probe_ax_trust_denied = 1,
    vault_probe_process_invalid = 2,
    vault_probe_signature_invalid = 3,
    vault_probe_ipc_unavailable = 4,
    vault_probe_window_shape_unavailable = 5,
    vault_probe_response_timeout = 6,
    vault_probe_configuration_invalid = 7,
    vault_probe_console_inventory_unavailable = 8
};
static const uint64_t vault_ax_reply_budget_ns = 50000000;
static uint64_t vault_monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}
static int vault_ax_failure(AXError error, uint64_t elapsed) {
    if (error == kAXErrorSuccess) return 0;
    // CannotComplete alone does not establish timeout or missing AX trust.
    if (error == kAXErrorCannotComplete && elapsed >= vault_ax_reply_budget_ns) return vault_probe_response_timeout;
    if (error == kAXErrorAttributeUnsupported || error == kAXErrorNoValue || error == kAXErrorIllegalArgument) return vault_probe_window_shape_unavailable;
    return vault_probe_ipc_unavailable;
}
static int vault_copy_window_attribute(AXUIElementRef element, CFStringRef attribute, CFTypeRef *result) {
    uint64_t started = vault_monotonic_ns();
    AXError error = AXUIElementCopyAttributeValue(element, attribute, result);
    uint64_t finished = vault_monotonic_ns();
    uint64_t elapsed = started && finished >= started ? finished - started : 0;
    return vault_ax_failure(error, elapsed);
}

// Read only window roles/titles of the enrolled console. No element children,
// AXValue, clipboard, image, credential or text buffer crosses this boundary.
// Every unavailable/malformed IPC result refuses exposure. Calls are bounded
// by four console processes, 32 windows each and a 50ms AX messaging timeout.
int mechanize_vault_console_windows(unsigned int uid, const char *requirementText, const char *prefixText, const char *expectedTitleText, int *consoles, int *protectedWindow, int *matched) {
    @autoreleasepool {
        if (!consoles || !protectedWindow || !matched || !requirementText || !prefixText || !expectedTitleText) return vault_probe_configuration_invalid;
        *consoles = 0; *protectedWindow = 0; *matched = 0;
        if (!AXIsProcessTrusted()) return vault_probe_ax_trust_denied;
        CFStringRef text = CFStringCreateWithCString(NULL, requirementText, kCFStringEncodingUTF8);
        CFStringRef prefix = CFStringCreateWithCString(NULL, prefixText, kCFStringEncodingUTF8);
        CFStringRef expectedTitle = CFStringCreateWithCString(NULL, expectedTitleText, kCFStringEncodingUTF8);
        SecRequirementRef requirement = NULL;
        if (!text || !prefix || !expectedTitle) { if (text) CFRelease(text); if (prefix) CFRelease(prefix); if (expectedTitle) CFRelease(expectedTitle); return vault_probe_configuration_invalid; }
        OSStatus parsed = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
        CFRelease(text);
        if (parsed != errSecSuccess || !requirement) { CFRelease(prefix); CFRelease(expectedTitle); return vault_probe_configuration_invalid; }
        NSArray<NSRunningApplication *> *applications = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.viant.mechanize.consent"];
        int result = 0;
        if (applications.count > 4) result = vault_probe_console_inventory_unavailable;
        for (NSRunningApplication *app in applications) {
            if (result != 0) break;
            pid_t pid = app.processIdentifier;
            struct proc_bsdinfo before = {0}, after = {0};
            if (!vault_process_info(pid, uid, &before)) { result = vault_probe_process_invalid; break; }
            if (!vault_process_matches(pid, requirement)) { result = vault_probe_signature_invalid; break; }
            AXUIElementRef root = AXUIElementCreateApplication(pid);
            if (!root || AXUIElementSetMessagingTimeout(root, 0.05) != kAXErrorSuccess) { if (root) CFRelease(root); result = vault_probe_ipc_unavailable; break; }
            CFTypeRef raw = NULL;
            result = vault_copy_window_attribute(root, kAXWindowsAttribute, &raw);
            CFRelease(root);
            if (result != 0 || !raw || CFGetTypeID(raw) != CFArrayGetTypeID() || CFArrayGetCount(raw) > 32) {
                if (raw) CFRelease(raw); if (result == 0) result = vault_probe_window_shape_unavailable; break;
            }
            CFArrayRef windows = (CFArrayRef)raw;
            for (CFIndex i = 0; i < CFArrayGetCount(windows); i++) {
                CFTypeRef element = CFArrayGetValueAtIndex(windows, i);
                if (!element || CFGetTypeID(element) != AXUIElementGetTypeID()) { result = vault_probe_window_shape_unavailable; break; }
                AXUIElementRef window = (AXUIElementRef)element;
                if (AXUIElementSetMessagingTimeout(window, 0.05) != kAXErrorSuccess) { result = vault_probe_ipc_unavailable; break; }
                CFTypeRef role = NULL, title = NULL;
                result = vault_copy_window_attribute(window, kAXRoleAttribute, &role);
                if (result == 0) result = vault_copy_window_attribute(window, kAXTitleAttribute, &title);
                if (result == 0) {
                    if (!role || CFGetTypeID(role) != CFStringGetTypeID() || !CFEqual(role, kAXWindowRole) ||
                        !title || CFGetTypeID(title) != CFStringGetTypeID() || CFStringGetLength(title) > 1024) {
                        result = vault_probe_window_shape_unavailable;
                    } else if (CFStringHasPrefix((CFStringRef)title, prefix)) {
                        (*protectedWindow)++;
                        if (CFStringGetLength(expectedTitle) > 0 && CFEqual(title, expectedTitle)) (*matched)++;
                    }
                }
                if (role) CFRelease(role); if (title) CFRelease(title);
                if (result != 0) break;
            }
            CFRelease(windows);
            // Preserve the first precise failure rather than overwriting it
            // with a later secondary process/signature check.
            if (result == 0 && (!vault_process_info(pid, uid, &after) || before.pbi_start_tvsec != after.pbi_start_tvsec || before.pbi_start_tvusec != after.pbi_start_tvusec)) result = vault_probe_process_invalid;
            if (result == 0 && !vault_process_matches(pid, requirement)) result = vault_probe_signature_invalid;
            if (result == 0) (*consoles)++;
        }
        CFRelease(requirement); CFRelease(prefix); CFRelease(expectedTitle);
        return result;
    }
}
