// Compatibility entry points; credentials remain encrypted in macOS Keychain.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <stdlib.h>

extern OSStatus MCMacLegacyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
extern OSStatus MCMacKeyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
extern OSStatus MCMacGenerateKeyPair(CFDictionaryRef, SecKeyRef *, SecKeyRef *);
extern SecKeyRef MCMacCreateRandomKey(CFDictionaryRef, CFErrorRef *);
extern void MCMacInstallInputFix(void);
extern void MCMacInstallTerminationFix(void);
extern void MCMacInstallSyntheticMouseBridge(void);
extern void MCMacInstallRunLoopPump(void);
extern void MCMacInstallSyntheticKeyboardBridge(void);
extern void MCMacInstallKeyboardRoutingFix(void);
extern void MCMacLogGeometry(void);
extern void MCMacInstallDisplayMetricsFix(void);

static OSStatus BridgeItem(CFDictionaryRef query, CFDictionaryRef changes, CFTypeRef *result, int operation) {
    OSStatus status = MCMacKeyItem(query, changes, result, operation);
    return status == errSecUnimplemented ? MCMacLegacyItem(query, changes, result, operation) : status;
}

static void LogStatus(const char *operation, OSStatus status) {
    if (status && status != errSecItemNotFound && status != errSecDuplicateItem)
        NSLog(@"[mcmac] keychain %s status=%d", operation, (int)status);
}

static OSStatus MacAdd(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = BridgeItem(query, NULL, result, 0);
    if (status == errSecUnimplemented) status = SecItemAdd(query, result);
    LogStatus("add", status);
    return status;
}
static OSStatus MacFind(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = BridgeItem(query, NULL, result, 1);
    if (status == errSecUnimplemented) status = SecItemCopyMatching(query, result);
    LogStatus("find", status);
    return status;
}
static OSStatus MacUpdate(CFDictionaryRef query, CFDictionaryRef changes) {
    OSStatus status = BridgeItem(query, changes, NULL, 2);
    if (status == errSecUnimplemented) status = SecItemUpdate(query, changes);
    LogStatus("update", status);
    return status;
}
static OSStatus MacDelete(CFDictionaryRef query) {
    OSStatus status = BridgeItem(query, NULL, NULL, 3);
    if (status == errSecUnimplemented) status = SecItemDelete(query);
    LogStatus("delete", status);
    if (status == errSecMissingEntitlement && query && CFGetTypeID(query) == CFDictionaryGetTypeID()) {
        NSDictionary *shape = (__bridge NSDictionary *)query;
        id itemClass = shape[(__bridge id)kSecClass];
        const char *className = !itemClass ? "absent" :
            [itemClass isEqual:(__bridge id)kSecClassKey] ? "key" :
            [itemClass isEqual:(__bridge id)kSecClassGenericPassword] ? "generic-password" : "other";
        id tag = shape[(__bridge id)kSecAttrApplicationTag];
        // Only types and field presence: never print identity or key values.
        NSLog(@"[mcmac] delete shape class=%s type-present=%d tag-kind=%@ label-present=%d",
              className, shape[(__bridge id)kSecAttrKeyType] != nil,
              tag ? NSStringFromClass([tag class]) : @"absent",
              shape[(__bridge id)kSecAttrLabel] != nil);
    }
    return status;
}

static OSStatus MacGeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey) {
    OSStatus status = MCMacGenerateKeyPair(parameters, publicKey, privateKey);
    LogStatus("generate-pair", status);
    return status;
}

static SecKeyRef MacCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    CFErrorRef failure = NULL;
    SecKeyRef key = MCMacCreateRandomKey(parameters, &failure);
    if (!key && failure) LogStatus("generate-key", (OSStatus)CFErrorGetCode(failure));
    if (error) *error = failure;
    else if (failure) CFRelease(failure);
    return key;
}

#define INTERPOSE(replacement, original) \
    __attribute__((used, section("__DATA,__interpose"))) \
    static const struct { const void *newFunction; const void *oldFunction; } \
    interpose_##original = {(const void *)replacement, (const void *)original}

INTERPOSE(MacAdd, SecItemAdd);
INTERPOSE(MacFind, SecItemCopyMatching);
INTERPOSE(MacUpdate, SecItemUpdate);
INTERPOSE(MacDelete, SecItemDelete);
INTERPOSE(MacGeneratePair, SecKeyGeneratePair);
INTERPOSE(MacCreateRandomKey, SecKeyCreateRandomKey);

__attribute__((constructor)) static void MCMacInitialize(void) {
    NSLog(@"[mcmac] encrypted macOS keychain bridge loaded");
    MCMacInstallDisplayMetricsFix();
    MCMacInstallInputFix();
    MCMacInstallTerminationFix();
    MCMacInstallSyntheticMouseBridge();
    MCMacInstallRunLoopPump();
    MCMacInstallSyntheticKeyboardBridge();
    MCMacInstallKeyboardRoutingFix();
    if (getenv("MCMAC_DIAGNOSTICS"))
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ MCMacLogGeometry(); });
}
