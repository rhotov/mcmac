// Exercises the real encrypted key adapter with disposable RSA and EC keys.
// Test tags are unique; all persisted test items are removed in @finally.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern OSStatus MCMacKeyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
#define TEST_ID(value) ((__bridge id)(value))

static void Expect(BOOL condition, NSString *message) {
    if (!condition)
        @throw [NSException exceptionWithName:@"KeyAdapterTestFailure" reason:message userInfo:nil];
}

static void ExpectStatus(OSStatus actual, OSStatus expected, NSString *operation) {
    Expect(actual == expected, [NSString stringWithFormat:@"%@ status=%d, expected=%d",
                                operation, (int)actual, (int)expected]);
}

static void SignAndVerify(id candidate, SecKeyRef publicKey, SecKeyAlgorithm algorithm) {
    Expect(candidate && CFGetTypeID((__bridge CFTypeRef)candidate) == SecKeyGetTypeID(),
           @"returned reference is a genuine SecKey");
    NSData *message = [@"disposable adapter signature test" dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature((__bridge SecKeyRef)candidate, algorithm,
                                                (__bridge CFDataRef)message, &error);
    if (error) { CFRelease(error); error = NULL; }
    Expect(signature != NULL, @"sign using reconstructed private key");
    BOOL valid = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef)message, signature, &error);
    CFRelease(signature);
    if (error) CFRelease(error);
    Expect(valid, @"verify signature against original public key");
}

static int ExerciseType(CFStringRef type, NSNumber *bits, SecKeyAlgorithm algorithm, const char *name) {
    NSString *unique = [@"mcmac-key-smoke-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSData *tag = [unique dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *identity = @{
        TEST_ID(kSecClass):TEST_ID(kSecClassKey),
        TEST_ID(kSecAttrKeyType):TEST_ID(type),
        TEST_ID(kSecAttrApplicationTag):tag
    };
    SecKeyRef original = NULL, publicKey = NULL;
    CFDataRef external = NULL;
    CFTypeRef result = NULL;
    int code = 0;
    @try {
        NSDictionary *generation = @{
            TEST_ID(kSecAttrKeyType):TEST_ID(type),
            TEST_ID(kSecAttrKeySizeInBits):bits,
            TEST_ID(kSecAttrIsPermanent):@NO,
            TEST_ID(kSecPrivateKeyAttrs):@{TEST_ID(kSecAttrIsPermanent):@NO},
            TEST_ID(kSecPublicKeyAttrs):@{TEST_ID(kSecAttrIsPermanent):@NO}
        };
        CFErrorRef error = NULL;
        original = SecKeyCreateRandomKey((__bridge CFDictionaryRef)generation, &error);
        if (error) { CFRelease(error); error = NULL; }
        Expect(original != NULL, @"generate nonpermanent private key");
        publicKey = SecKeyCopyPublicKey(original);
        Expect(publicKey != NULL, @"copy original public key");
        external = SecKeyCopyExternalRepresentation(original, &error);
        if (error) CFRelease(error);
        Expect(external != NULL, @"export private-key data");

        NSMutableDictionary *addition = [identity mutableCopy];
        addition[TEST_ID(kSecValueData)] = (__bridge NSData *)external;
        addition[TEST_ID(kSecReturnPersistentRef)] = @YES;
        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)addition, NULL, &result, 0),
                     errSecSuccess, @"add and return persistent reference");
        id persistent = CFBridgingRelease(result); result = NULL;
        Expect([persistent isKindOfClass:NSData.class] && [persistent length] > 0,
               @"add returns nonempty persistent-reference data");
        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)addition, NULL, NULL, 0),
                     errSecDuplicateItem, @"duplicate key add");

        NSMutableDictionary *query = [identity mutableCopy];
        query[TEST_ID(kSecReturnRef)] = @YES;
        query[TEST_ID(kSecReturnPersistentRef)] = @YES;
        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)query, NULL, &result, 1),
                     errSecSuccess, @"find key and persistent reference");
        id found = CFBridgingRelease(result); result = NULL;
        Expect([found isKindOfClass:NSDictionary.class], @"combined flags return a dictionary");
        Expect([found[TEST_ID(kSecValuePersistentRef)] isEqual:persistent],
               @"lookup returns the same native persistent reference");
        SignAndVerify(found[TEST_ID(kSecValueRef)], publicKey, algorithm);

        NSDictionary *persistentQuery = @{
            TEST_ID(kSecValuePersistentRef):persistent,
            TEST_ID(kSecReturnRef):@YES
        };
        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)persistentQuery, NULL, &result, 1),
                     errSecSuccess, @"persistent-only lookup without class");
        id persistentKey = CFBridgingRelease(result); result = NULL;
        SignAndVerify(persistentKey, publicKey, algorithm);

        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3),
                     errSecSuccess, @"delete test key");
        ExpectStatus(MCMacKeyItem((__bridge CFDictionaryRef)query, NULL, &result, 1),
                     errSecItemNotFound, @"lookup after deletion");
        Expect(result == NULL, @"missing lookup leaves a null result");
        printf("%s key storage, persistent references, and signature verification passed\n", name);
    } @catch (NSException *exception) {
        fprintf(stderr, "%s key adapter test failed: %s\n", name, exception.reason.UTF8String);
        code = 1;
    } @finally {
        if (result) CFRelease(result);
        OSStatus cleanup = MCMacKeyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3);
        if (cleanup != errSecSuccess && cleanup != errSecItemNotFound) {
            fprintf(stderr, "%s test-item cleanup failed: status=%d\n", name, (int)cleanup);
            code = 1;
        }
        if (external) CFRelease(external);
        if (publicKey) CFRelease(publicKey);
        if (original) CFRelease(original);
    }
    return code;
}

int main(void) {
    @autoreleasepool {
        int code = ExerciseType(kSecAttrKeyTypeRSA, @2048,
                                kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, "RSA");
        code |= ExerciseType(kSecAttrKeyTypeECSECPrimeRandom, @256,
                             kSecKeyAlgorithmECDSASignatureMessageX962SHA256, "EC");
        return code;
    }
}
