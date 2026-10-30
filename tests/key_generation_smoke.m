// Real generation, encrypted persistence, reload, signing, and rollback using
// unique disposable keys. No game credentials or key bytes are printed.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern OSStatus MCMacGenerateKeyPair(CFDictionaryRef, SecKeyRef *, SecKeyRef *);
extern SecKeyRef MCMacCreateRandomKey(CFDictionaryRef, CFErrorRef *);
extern OSStatus MCMacKeyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
#define TID(value) ((__bridge id)(value))

static void Expect(BOOL condition, NSString *reason) {
    if (!condition) @throw [NSException exceptionWithName:@"KeyGenerationTestFailure" reason:reason userInfo:nil];
}

static void Status(OSStatus actual, OSStatus expected, NSString *operation) {
    Expect(actual == expected, [NSString stringWithFormat:@"%@ status=%d expected=%d", operation, (int)actual, (int)expected]);
}

static NSDictionary *Identity(CFStringRef type, NSData *tag, CFStringRef keyClass, NSString *group) {
    return @{TID(kSecClass):TID(kSecClassKey), TID(kSecAttrKeyType):TID(type),
             TID(kSecAttrApplicationTag):tag, TID(kSecAttrKeyClass):TID(keyClass),
             TID(kSecAttrAccessGroup):group};
}

static id Reload(NSDictionary *identity) {
    NSMutableDictionary *query = [identity mutableCopy];
    query[TID(kSecReturnRef)] = @YES;
    CFTypeRef result = NULL;
    Status(MCMacKeyItem((__bridge CFDictionaryRef)query, NULL, &result, 1), errSecSuccess, @"reload generated key");
    Expect(result && CFGetTypeID(result) == SecKeyGetTypeID(), @"reload returns a real SecKey");
    return CFBridgingRelease(result);
}

static void Verify(SecKeyRef privateKey, SecKeyRef publicKey, SecKeyAlgorithm algorithm) {
    NSData *message = [@"disposable generated-key round trip" dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(privateKey, algorithm, (__bridge CFDataRef)message, &error);
    if (error) { CFRelease(error); error = NULL; }
    Expect(signature != NULL, @"sign with generated/reloaded key");
    BOOL valid = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef)message, signature, &error);
    CFRelease(signature);
    if (error) CFRelease(error);
    Expect(valid, @"signature verifies with generated/reloaded public key");
}

static NSData *Tag(NSString *prefix, NSString *suffix) {
    return [[prefix stringByAppendingString:suffix] dataUsingEncoding:NSUTF8StringEncoding];
}

static int Exercise(CFStringRef type, NSNumber *bits, SecKeyAlgorithm algorithm, const char *name) {
    NSString *unique = [@"mcmac-generation-test-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSString *group = [unique stringByAppendingString:@".group"];
    NSString *label = [unique stringByAppendingString:@".pair-label"];
    NSData *privateTag = Tag(unique, @".private"), *publicTag = Tag(unique, @".public");
    NSData *randomTag = Tag(unique, @".random"), *badTag = Tag(unique, @".bad");
    NSData *flatTag = Tag(unique, @".flat");
    NSDictionary *privateIdentity = Identity(type, privateTag, kSecAttrKeyClassPrivate, group);
    NSDictionary *publicIdentity = Identity(type, publicTag, kSecAttrKeyClassPublic, group);
    NSDictionary *randomIdentity = Identity(type, randomTag, kSecAttrKeyClassPrivate, group);
    NSDictionary *badIdentity = Identity(type, badTag, kSecAttrKeyClassPrivate, group);
    NSDictionary *flatPrivateIdentity = Identity(type, flatTag, kSecAttrKeyClassPrivate, group);
    NSDictionary *flatPublicIdentity = Identity(type, flatTag, kSecAttrKeyClassPublic, group);
    NSArray *cleanup = @[privateIdentity, publicIdentity, randomIdentity, badIdentity, flatPrivateIdentity, flatPublicIdentity];
    SecKeyRef privateKey = NULL, publicKey = NULL, randomKey = NULL;
    CFErrorRef error = NULL;
    int code = 0;
    @try {
        // Exact flat XAL request shape, including its otherwise redundant
        // SecItem return-data flag. Both halves share the caller's tag.
        NSDictionary *flatParameters = @{
            TID(kSecAttrKeyType):TID(type), TID(kSecAttrKeySizeInBits):bits,
            TID(kSecAttrIsPermanent):@YES, TID(kSecAttrApplicationTag):flatTag,
            TID(kSecAttrAccessGroup):group, TID(kSecAttrLabel):[unique stringByAppendingString:@".flat-label"],
            TID(kSecAttrAccessible):TID(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            TID(kSecReturnData):@YES
        };
        SecKeyRef flatPrivate = NULL, flatPublic = NULL;
        Status(MCMacGenerateKeyPair((__bridge CFDictionaryRef)flatParameters, &flatPublic, &flatPrivate),
               errSecSuccess, @"flat XAL generation request");
        Expect(flatPrivate && flatPublic, @"flat generation returns both SecKeyRefs");
        Verify((__bridge SecKeyRef)Reload(flatPrivateIdentity), (__bridge SecKeyRef)Reload(flatPublicIdentity), algorithm);
        CFRelease(flatPrivate);
        CFRelease(flatPublic);

        // Top-level attributes are inherited; the public tag is overridden in
        // its nested dictionary, matching the legacy iOS generation contract.
        NSDictionary *parameters = @{
            TID(kSecAttrKeyType):TID(type), TID(kSecAttrKeySizeInBits):bits,
            TID(kSecAttrIsPermanent):@YES, TID(kSecAttrApplicationTag):privateTag,
            TID(kSecAttrAccessGroup):group, TID(kSecAttrLabel):label,
            TID(kSecPublicKeyAttrs):@{TID(kSecAttrApplicationTag):publicTag}
        };
        Status(MCMacGenerateKeyPair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey),
               errSecSuccess, @"generate permanent pair");
        Expect(privateKey && publicKey, @"generation returns both genuine keys");
        Verify(privateKey, publicKey, algorithm);
        id reloadedPrivate = Reload(privateIdentity), reloadedPublic = Reload(publicIdentity);
        Verify((__bridge SecKeyRef)reloadedPrivate, publicKey, algorithm);
        Verify(privateKey, (__bridge SecKeyRef)reloadedPublic, algorithm);

        // XAL locates and removes device keys by label alone, without type/tag.
        NSDictionary *labelIdentity = @{TID(kSecClass):TID(kSecClassKey), TID(kSecAttrLabel):label};
        NSMutableDictionary *labelQuery = [labelIdentity mutableCopy];
        labelQuery[TID(kSecReturnRef)] = @YES;
        labelQuery[TID(kSecMatchLimit)] = TID(kSecMatchLimitAll);
        CFTypeRef labelResult = NULL;
        Status(MCMacKeyItem((__bridge CFDictionaryRef)labelQuery, NULL, &labelResult, 1),
               errSecSuccess, @"label-only lookup without tag/type");
        id labelled = labelResult ? CFBridgingRelease(labelResult) : nil;
        Expect([labelled isKindOfClass:NSArray.class] && [labelled count] == 2,
               @"label-only lookup finds both generated halves");

        SecKeyRef duplicatePrivate = NULL, duplicatePublic = NULL;
        Status(MCMacGenerateKeyPair((__bridge CFDictionaryRef)parameters, &duplicatePublic, &duplicatePrivate),
               errSecDuplicateItem, @"duplicate generation fails");
        Expect(!duplicatePrivate && !duplicatePublic, @"duplicate generation clears outputs");
        Verify((__bridge SecKeyRef)Reload(privateIdentity), publicKey, algorithm);

        // Force a failure on the second save. Only this call's newly inserted
        // private key should be rolled back; the older public key must survive.
        Status(MCMacKeyItem((__bridge CFDictionaryRef)privateIdentity, NULL, NULL, 3),
               errSecSuccess, @"remove first key before partial-failure test");
        Status(MCMacGenerateKeyPair((__bridge CFDictionaryRef)parameters, &duplicatePublic, &duplicatePrivate),
               errSecDuplicateItem, @"second-half duplicate fails");
        Expect(!duplicatePrivate && !duplicatePublic, @"partial failure clears outputs");
        Status(MCMacKeyItem((__bridge CFDictionaryRef)privateIdentity, NULL, NULL, 1),
               errSecItemNotFound, @"rollback removes only the newly created first key");
        Verify(privateKey, (__bridge SecKeyRef)Reload(publicIdentity), algorithm);
        Status(MCMacKeyItem((__bridge CFDictionaryRef)labelIdentity, NULL, NULL, 3),
               errSecSuccess, @"label-only deletion without tag/type");
        Status(MCMacKeyItem((__bridge CFDictionaryRef)publicIdentity, NULL, NULL, 1),
               errSecItemNotFound, @"label-only deletion removed remaining public key");

        // Modern API: nested private metadata and an explicit public permanence
        // override must save only the private half.
        NSDictionary *randomParameters = @{
            TID(kSecAttrKeyType):TID(type), TID(kSecAttrKeySizeInBits):bits,
            TID(kSecAttrIsPermanent):@YES,
            TID(kSecPrivateKeyAttrs):@{TID(kSecAttrApplicationTag):randomTag, TID(kSecAttrAccessGroup):group},
            TID(kSecPublicKeyAttrs):@{TID(kSecAttrIsPermanent):@NO}
        };
        randomKey = MCMacCreateRandomKey((__bridge CFDictionaryRef)randomParameters, &error);
        Expect(randomKey && !error, @"modern generation saves requested private key");
        SecKeyRef randomPublic = SecKeyCopyPublicKey(randomKey);
        Expect(randomPublic != NULL, @"copy generated public key");
        Verify((__bridge SecKeyRef)Reload(randomIdentity), randomPublic, algorithm);
        CFRelease(randomPublic);
        SecKeyRef duplicateRandom = MCMacCreateRandomKey((__bridge CFDictionaryRef)randomParameters, &error);
        Expect(!duplicateRandom && error && CFErrorGetCode(error) == errSecDuplicateItem,
               @"modern duplicate returns matching CFError");
        CFRelease(error); error = NULL;

        NSMutableDictionary *invalidParameters = [randomParameters mutableCopy];
        invalidParameters[TID(kSecAttrKeySizeInBits)] = @0;
        invalidParameters[TID(kSecPrivateKeyAttrs)] = @{TID(kSecAttrApplicationTag):badTag, TID(kSecAttrAccessGroup):group};
        SecKeyRef invalid = MCMacCreateRandomKey((__bridge CFDictionaryRef)invalidParameters, &error);
        Expect(!invalid && error, @"native key-generation failure propagates");
        CFRelease(error); error = NULL;
        Status(MCMacKeyItem((__bridge CFDictionaryRef)badIdentity, NULL, NULL, 1),
               errSecItemNotFound, @"failed generation persists no key");
        printf("%s generation, persistence, reload, signing, duplicate handling, and rollback passed\n", name);
    } @catch (NSException *exception) {
        fprintf(stderr, "%s generation test failed: %s\n", name, exception.reason.UTF8String);
        code = 1;
    } @finally {
        if (error) CFRelease(error);
        if (privateKey) CFRelease(privateKey);
        if (publicKey) CFRelease(publicKey);
        if (randomKey) CFRelease(randomKey);
        for (NSDictionary *identity in cleanup) {
            OSStatus status = MCMacKeyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3);
            if (status != errSecSuccess && status != errSecItemNotFound) {
                fprintf(stderr, "%s disposable-key cleanup failed: status=%d\n", name, (int)status);
                code = 1;
            }
        }
    }
    return code;
}

int main(void) {
    @autoreleasepool {
        int code = Exercise(kSecAttrKeyTypeECSECPrimeRandom, @256,
                            kSecKeyAlgorithmECDSASignatureMessageX962SHA256, "EC");
        code |= Exercise(kSecAttrKeyTypeRSA, @2048,
                         kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, "RSA");
        return code;
    }
}
