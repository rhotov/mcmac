// Generate real software keys in memory, then save requested permanent keys
// through the encrypted macOS adapter. No key material or identity is logged.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <os/log.h>

extern OSStatus MCMacKeyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
#define GEN_ID(value) ((__bridge id)(value))

static NSArray *DiagnosticFieldNames(NSDictionary *dictionary) {
    // Never print arbitrary dictionary keys: report only recognized Apple
    // attribute names, not the attribute values or caller-created strings.
    NSDictionary *known = @{
        GEN_ID(kSecAttrKeyType):@"kSecAttrKeyType",
        GEN_ID(kSecAttrKeySizeInBits):@"kSecAttrKeySizeInBits",
        GEN_ID(kSecAttrIsPermanent):@"kSecAttrIsPermanent",
        GEN_ID(kSecAttrApplicationTag):@"kSecAttrApplicationTag",
        GEN_ID(kSecAttrApplicationLabel):@"kSecAttrApplicationLabel",
        GEN_ID(kSecAttrLabel):@"kSecAttrLabel",
        GEN_ID(kSecAttrAccessGroup):@"kSecAttrAccessGroup",
        GEN_ID(kSecAttrAccessible):@"kSecAttrAccessible",
        GEN_ID(kSecUseDataProtectionKeychain):@"kSecUseDataProtectionKeychain",
        GEN_ID(kSecPrivateKeyAttrs):@"kSecPrivateKeyAttrs",
        GEN_ID(kSecPublicKeyAttrs):@"kSecPublicKeyAttrs",
        GEN_ID(kSecAttrTokenID):@"kSecAttrTokenID",
        GEN_ID(kSecAttrAccessControl):@"kSecAttrAccessControl",
        GEN_ID(kSecAttrIsExtractable):@"kSecAttrIsExtractable",
        GEN_ID(kSecAttrIsSensitive):@"kSecAttrIsSensitive",
        GEN_ID(kSecAttrCanEncrypt):@"kSecAttrCanEncrypt",
        GEN_ID(kSecAttrCanDecrypt):@"kSecAttrCanDecrypt",
        GEN_ID(kSecAttrCanDerive):@"kSecAttrCanDerive",
        GEN_ID(kSecAttrCanSign):@"kSecAttrCanSign",
        GEN_ID(kSecAttrCanVerify):@"kSecAttrCanVerify",
        GEN_ID(kSecAttrCanWrap):@"kSecAttrCanWrap",
        GEN_ID(kSecAttrCanUnwrap):@"kSecAttrCanUnwrap",
        GEN_ID(kSecAttrEffectiveKeySize):@"kSecAttrEffectiveKeySize",
        GEN_ID(kSecAttrKeyClass):@"kSecAttrKeyClass",
        GEN_ID(kSecAttrSynchronizable):@"kSecAttrSynchronizable",
        GEN_ID(kSecClass):@"kSecClass",
        GEN_ID(kSecReturnRef):@"kSecReturnRef",
        GEN_ID(kSecReturnData):@"kSecReturnData",
        GEN_ID(kSecReturnAttributes):@"kSecReturnAttributes",
        GEN_ID(kSecReturnPersistentRef):@"kSecReturnPersistentRef",
        GEN_ID(kSecMatchLimit):@"kSecMatchLimit",
        GEN_ID(kSecAttrService):@"kSecAttrService",
        GEN_ID(kSecAttrAccount):@"kSecAttrAccount",
        GEN_ID(kSecAttrGeneric):@"kSecAttrGeneric",
        GEN_ID(kSecValueData):@"kSecValueData",
        GEN_ID(kSecValueRef):@"kSecValueRef",
        GEN_ID(kSecValuePersistentRef):@"kSecValuePersistentRef",
        GEN_ID(kSecAttrDescription):@"kSecAttrDescription",
        GEN_ID(kSecAttrComment):@"kSecAttrComment",
        GEN_ID(kSecAttrCreator):@"kSecAttrCreator",
        GEN_ID(kSecAttrType):@"kSecAttrType",
        GEN_ID(kSecAttrIsInvisible):@"kSecAttrIsInvisible",
        GEN_ID(kSecAttrIsNegative):@"kSecAttrIsNegative",
        GEN_ID(kSecUseAuthenticationUI):@"kSecUseAuthenticationUI",
        GEN_ID(kSecUseOperationPrompt):@"kSecUseOperationPrompt",
        GEN_ID(kSecUseAuthenticationContext):@"kSecUseAuthenticationContext"
    };
    NSMutableArray *names = [NSMutableArray array];
    for (id key in dictionary) [names addObject:known[key] ?: @"<unrecognized field>"];
    return [names sortedArrayUsingSelector:@selector(compare:)];
}

static void LogNativeFallbackFailure(NSString *reason, CFDictionaryRef parameters) {
    NSDictionary *original = parameters && CFGetTypeID(parameters) == CFDictionaryGetTypeID() ?
        (__bridge NSDictionary *)parameters : @{};
    NSString *fields = [DiagnosticFieldNames(original) componentsJoinedByString:@","];
    NSString *tagClass = original[GEN_ID(kSecAttrApplicationTag)] ?
        NSStringFromClass([original[GEN_ID(kSecAttrApplicationTag)] class]) : @"absent";
    os_log_error(OS_LOG_DEFAULT,
                 "[mcmac] key generation native fallback: %{public}s; fields=%{public}s; tagClass=%{public}s",
                 reason.UTF8String, fields.UTF8String, tagClass.UTF8String);
    for (id key in @[GEN_ID(kSecPrivateKeyAttrs), GEN_ID(kSecPublicKeyAttrs)]) {
        id attributes = original[key];
        if ([attributes isKindOfClass:NSDictionary.class]) {
            NSString *nestedFields = [DiagnosticFieldNames(attributes) componentsJoinedByString:@","];
            NSString *nestedTagClass = attributes[GEN_ID(kSecAttrApplicationTag)] ?
                NSStringFromClass([attributes[GEN_ID(kSecAttrApplicationTag)] class]) : @"absent";
            os_log_error(OS_LOG_DEFAULT, "[mcmac] key generation %{public}s fields=%{public}s; tagClass=%{public}s",
                         [key isEqual:GEN_ID(kSecPrivateKeyAttrs)] ? "private" : "public",
                         nestedFields.UTF8String, nestedTagClass.UTF8String);
        }
    }
}

static BOOL RejectGeneration(NSString *reason, NSString **rejectionReason) {
    *rejectionReason = reason;
    return NO;
}

static NSString *GenerationType(id value) {
    if ([value isEqual:GEN_ID(kSecAttrKeyTypeRSA)]) return GEN_ID(kSecAttrKeyTypeRSA);
    if ([value isEqual:GEN_ID(kSecAttrKeyTypeECSECPrimeRandom)] ||
        [value isEqual:GEN_ID(kSecAttrKeyTypeEC)]) return GEN_ID(kSecAttrKeyTypeECSECPrimeRandom);
    return nil;
}

static BOOL SupportedAttributes(NSDictionary *attributes, BOOL topLevel) {
    // Explicit usage restrictions, access-control objects, tokens, synchronization,
    // and other unimplemented semantics must stay with the original Security API.
    NSMutableSet *allowed = [NSMutableSet setWithArray:@[
        GEN_ID(kSecAttrKeyType), GEN_ID(kSecAttrKeySizeInBits),
        GEN_ID(kSecAttrIsPermanent), GEN_ID(kSecAttrApplicationTag),
        GEN_ID(kSecAttrLabel), GEN_ID(kSecAttrAccessGroup),
        GEN_ID(kSecAttrAccessible), GEN_ID(kSecUseDataProtectionKeychain)
    ]];
    // XAL also supplies the SecItem result-request flag to the generation API.
    // Generation still returns SecKeyRefs; this flag changes no key semantics.
    if (topLevel) [allowed addObjectsFromArray:@[
        GEN_ID(kSecPrivateKeyAttrs), GEN_ID(kSecPublicKeyAttrs), GEN_ID(kSecReturnData)
    ]];
    for (id key in attributes) if (![allowed containsObject:key]) return NO;
    for (id key in @[GEN_ID(kSecAttrIsPermanent), GEN_ID(kSecUseDataProtectionKeychain), GEN_ID(kSecReturnData)])
        if (attributes[key] && ![attributes[key] isKindOfClass:NSNumber.class]) return NO;
    for (id key in @[GEN_ID(kSecAttrLabel), GEN_ID(kSecAttrAccessGroup), GEN_ID(kSecAttrAccessible)])
        if (attributes[key] && ![attributes[key] isKindOfClass:NSString.class]) return NO;
    id tag = attributes[GEN_ID(kSecAttrApplicationTag)];
    if (tag && (![tag isKindOfClass:NSData.class] || ![tag length])) return NO;
    return YES;
}

static NSDictionary *KeyIdentity(NSDictionary *effective, NSString *type, CFStringRef keyClass) {
    if (![effective[GEN_ID(kSecAttrIsPermanent)] boolValue]) return nil;
    NSMutableDictionary *identity = [@{
        GEN_ID(kSecClass):GEN_ID(kSecClassKey),
        GEN_ID(kSecAttrKeyType):type,
        GEN_ID(kSecAttrKeyClass):GEN_ID(keyClass),
        GEN_ID(kSecAttrIsPermanent):@YES,
        GEN_ID(kSecAttrApplicationTag):effective[GEN_ID(kSecAttrApplicationTag)]
    } mutableCopy];
    for (id key in @[GEN_ID(kSecAttrAccessGroup), GEN_ID(kSecAttrLabel), GEN_ID(kSecAttrAccessible)])
        if (effective[key]) identity[key] = effective[key];
    return identity;
}

static BOOL GenerationPlan(CFDictionaryRef parameters, NSDictionary **temporary,
                           NSDictionary **privateIdentity, NSDictionary **publicIdentity,
                           NSString **rejectionReason) {
    if (!parameters || CFGetTypeID(parameters) != CFDictionaryGetTypeID())
        return RejectGeneration(@"invalid parameter dictionary", rejectionReason);
    NSDictionary *original = (__bridge NSDictionary *)parameters;
    if (!SupportedAttributes(original, YES)) return RejectGeneration(@"unsupported top-level attributes", rejectionReason);
    NSString *type = GenerationType(original[GEN_ID(kSecAttrKeyType)]);
    id bits = original[GEN_ID(kSecAttrKeySizeInBits)];
    if (!type || (!([bits isKindOfClass:NSNumber.class] || [bits isKindOfClass:NSString.class])))
        return RejectGeneration(@"unsupported key type or size value class", rejectionReason);
    NSMutableDictionary *common = [original mutableCopy];
    [common removeObjectsForKeys:@[GEN_ID(kSecPrivateKeyAttrs), GEN_ID(kSecPublicKeyAttrs)]];
    NSMutableArray *effective = [NSMutableArray arrayWithCapacity:2];
    for (id key in @[GEN_ID(kSecPrivateKeyAttrs), GEN_ID(kSecPublicKeyAttrs)]) {
        id nested = original[key];
        if (nested && (![nested isKindOfClass:NSDictionary.class] || !SupportedAttributes(nested, NO)))
            return RejectGeneration(@"unsupported nested attributes", rejectionReason);
        // Type and size characterize the pair and cannot differ between halves.
        if (nested[GEN_ID(kSecAttrKeyType)] && ![nested[GEN_ID(kSecAttrKeyType)] isEqual:original[GEN_ID(kSecAttrKeyType)]])
            return RejectGeneration(@"nested key type differs", rejectionReason);
        if (nested[GEN_ID(kSecAttrKeySizeInBits)] && ![nested[GEN_ID(kSecAttrKeySizeInBits)] isEqual:bits])
            return RejectGeneration(@"nested key size differs", rejectionReason);
        NSMutableDictionary *attributes = [common mutableCopy];
        if (nested) [attributes addEntriesFromDictionary:nested];
        if ([attributes[GEN_ID(kSecAttrIsPermanent)] boolValue] && !attributes[GEN_ID(kSecAttrApplicationTag)])
            return RejectGeneration(@"permanent key missing application tag", rejectionReason);
        [effective addObject:attributes];
    }
    *privateIdentity = KeyIdentity(effective[0], type, kSecAttrKeyClassPrivate);
    *publicIdentity = KeyIdentity(effective[1], type, kSecAttrKeyClassPublic);
    if (!*privateIdentity && !*publicIdentity)
        return RejectGeneration(@"no permanent key requested", rejectionReason); // Preserve native nonpersistent behavior.
    *temporary = @{
        GEN_ID(kSecAttrKeyType):type,
        GEN_ID(kSecAttrKeySizeInBits):bits,
        GEN_ID(kSecAttrIsPermanent):@NO,
        GEN_ID(kSecPrivateKeyAttrs):@{GEN_ID(kSecAttrIsPermanent):@NO},
        GEN_ID(kSecPublicKeyAttrs):@{GEN_ID(kSecAttrIsPermanent):@NO}
    };
    return YES;
}

static void GenerationError(CFErrorRef *error, OSStatus status) {
    if (error) *error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainOSStatus, status, NULL);
}

static OSStatus PersistGenerated(SecKeyRef key, NSDictionary *identity, NSMutableArray *created) {
    if (!identity) return errSecSuccess;
    NSMutableDictionary *addition = [identity mutableCopy];
    addition[GEN_ID(kSecValueRef)] = (__bridge id)key;
    addition[GEN_ID(kSecReturnPersistentRef)] = @YES;
    CFTypeRef result = NULL;
    OSStatus status = MCMacKeyItem((__bridge CFDictionaryRef)addition, NULL, &result, 0);
    id persistent = result ? CFBridgingRelease(result) : nil;
    if (status) return status;
    // The adapter guarantees a persistent reference for a successful addition.
    // Keep that exact reference so rollback cannot delete an older duplicate.
    NSMutableDictionary *rollback = [identity mutableCopy];
    if ([persistent isKindOfClass:NSData.class] && [persistent length]) {
        rollback[GEN_ID(kSecValuePersistentRef)] = persistent;
    } else {
        [created addObject:rollback];
        return errSecDecode;
    }
    [created addObject:rollback];
    return errSecSuccess;
}

static OSStatus GenerateAndPersist(NSDictionary *temporary, NSDictionary *privateIdentity,
                                   NSDictionary *publicIdentity, SecKeyRef *publicKey,
                                   SecKeyRef *privateKey, CFErrorRef *error) {
    CFErrorRef nativeError = NULL;
    SecKeyRef generatedPrivate = SecKeyCreateRandomKey((__bridge CFDictionaryRef)temporary, &nativeError);
    if (!generatedPrivate) {
        OSStatus status = nativeError ? (OSStatus)CFErrorGetCode(nativeError) : errSecInternalComponent;
        if (error) *error = nativeError; else if (nativeError) CFRelease(nativeError);
        if (error && !*error) GenerationError(error, status);
        return status;
    }
    if (nativeError) CFRelease(nativeError);
    SecKeyRef generatedPublic = SecKeyCopyPublicKey(generatedPrivate);
    if (!generatedPublic) {
        CFRelease(generatedPrivate);
        GenerationError(error, errSecInternalComponent);
        return errSecInternalComponent;
    }
    NSMutableArray *created = [NSMutableArray arrayWithCapacity:2];
    OSStatus status = PersistGenerated(generatedPrivate, privateIdentity, created);
    if (!status) status = PersistGenerated(generatedPublic, publicIdentity, created);
    if (status) {
        for (NSDictionary *identity in created.reverseObjectEnumerator)
            MCMacKeyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3);
        CFRelease(generatedPrivate);
        CFRelease(generatedPublic);
        GenerationError(error, status);
        return status;
    }
    if (privateKey) *privateKey = generatedPrivate; else CFRelease(generatedPrivate);
    if (publicKey) *publicKey = generatedPublic; else CFRelease(generatedPublic);
    return errSecSuccess;
}

OSStatus MCMacGenerateKeyPair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey) {
    if (publicKey) *publicKey = NULL;
    if (privateKey) *privateKey = NULL;
    NSDictionary *temporary = nil, *privateIdentity = nil, *publicIdentity = nil;
    NSString *rejectionReason = nil;
    if (!GenerationPlan(parameters, &temporary, &privateIdentity, &publicIdentity, &rejectionReason)) {
        OSStatus status = SecKeyGeneratePair(parameters, publicKey, privateKey);
        if (status) LogNativeFallbackFailure(rejectionReason, parameters);
        return status;
    }
    return GenerateAndPersist(temporary, privateIdentity, publicIdentity, publicKey, privateKey, NULL);
}

SecKeyRef MCMacCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    if (error) *error = NULL;
    NSDictionary *temporary = nil, *privateIdentity = nil, *publicIdentity = nil;
    NSString *rejectionReason = nil;
    if (!GenerationPlan(parameters, &temporary, &privateIdentity, &publicIdentity, &rejectionReason)) {
        SecKeyRef key = SecKeyCreateRandomKey(parameters, error);
        if (!key) LogNativeFallbackFailure(rejectionReason, parameters);
        return key;
    }
    SecKeyRef privateKey = NULL;
    GenerateAndPersist(temporary, privateIdentity, publicIdentity, NULL, &privateKey, error);
    return privateKey;
}
