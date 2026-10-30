// Persist imported asymmetric keys in the existing encrypted login-keychain
// bridge, and reconstruct genuine SecKey objects for cryptographic operations.
// No DER, application tags, or credentials are logged or written to files.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern OSStatus MCMacLegacyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);
#define KEY_ID(value) ((__bridge id)(value))

static NSString *const KeyServicePrefix = @"mcmac.keys.";

static NSString *CanonicalType(id type) {
    if ([type isEqual:KEY_ID(kSecAttrKeyTypeRSA)]) return KEY_ID(kSecAttrKeyTypeRSA);
    if ([type isEqual:KEY_ID(kSecAttrKeyTypeECSECPrimeRandom)] || [type isEqual:KEY_ID(kSecAttrKeyTypeEC)])
        return KEY_ID(kSecAttrKeyTypeECSECPrimeRandom);
    return nil;
}

static BOOL ValidClass(id value) {
    return !value || [value isEqual:KEY_ID(kSecAttrKeyClassPrivate)] ||
                    [value isEqual:KEY_ID(kSecAttrKeyClassPublic)];
}

static OSStatus ValidateKeys(NSDictionary *query, BOOL updating) {
    NSSet *allowed = updating ? [NSSet setWithArray:@[KEY_ID(kSecValueData), KEY_ID(kSecAttrLabel)]] :
        [NSSet setWithArray:@[
            KEY_ID(kSecClass), KEY_ID(kSecAttrApplicationTag), KEY_ID(kSecAttrKeyType),
            KEY_ID(kSecAttrKeyClass), KEY_ID(kSecAttrLabel), KEY_ID(kSecAttrAccessGroup),
            KEY_ID(kSecAttrAccessible), KEY_ID(kSecAttrIsPermanent), KEY_ID(kSecAttrKeySizeInBits),
            KEY_ID(kSecValueData), KEY_ID(kSecValueRef), KEY_ID(kSecValuePersistentRef),
            KEY_ID(kSecReturnData), KEY_ID(kSecReturnAttributes), KEY_ID(kSecReturnRef),
            KEY_ID(kSecReturnPersistentRef), KEY_ID(kSecMatchLimit), KEY_ID(kSecUseDataProtectionKeychain)
        ]];
    for (id name in query) if (![allowed containsObject:name]) return errSecUnimplemented;
    id tag = query[KEY_ID(kSecAttrApplicationTag)];
    if (tag && (![tag isKindOfClass:NSData.class] || ![tag length])) return errSecParam;
    id type = query[KEY_ID(kSecAttrKeyType)];
    if (type && !CanonicalType(type)) return errSecUnimplemented;
    if (!ValidClass(query[KEY_ID(kSecAttrKeyClass)])) return errSecUnimplemented;
    for (id name in @[KEY_ID(kSecValueData), KEY_ID(kSecValuePersistentRef)])
        if (query[name] && ![query[name] isKindOfClass:NSData.class]) return errSecParam;
    id label = query[KEY_ID(kSecAttrLabel)];
    if (label && ![label isKindOfClass:NSString.class]) return errSecParam;
    id group = query[KEY_ID(kSecAttrAccessGroup)];
    if (group && ![group isKindOfClass:NSString.class]) return errSecParam;
    id limit = query[KEY_ID(kSecMatchLimit)];
    if (limit && ![limit isEqual:KEY_ID(kSecMatchLimitOne)] && ![limit isEqual:KEY_ID(kSecMatchLimitAll)])
        return errSecUnimplemented;
    for (id name in @[KEY_ID(kSecReturnData), KEY_ID(kSecReturnAttributes), KEY_ID(kSecReturnRef),
                     KEY_ID(kSecReturnPersistentRef), KEY_ID(kSecAttrIsPermanent)])
        if (query[name] && ![query[name] isKindOfClass:NSNumber.class]) return errSecParam;
    id bits = query[KEY_ID(kSecAttrKeySizeInBits)];
    if (bits && ![bits isKindOfClass:NSNumber.class]) return errSecParam;
    return errSecSuccess;
}

static id ImportKey(NSData *data, NSString *type, id requestedClass, NSString **actualClass) {
    if (!data.length || !type) return nil;
    NSArray *classes = requestedClass ? @[requestedClass] :
        @[KEY_ID(kSecAttrKeyClassPrivate), KEY_ID(kSecAttrKeyClassPublic)];
    for (NSString *keyClass in classes) {
        NSDictionary *attributes = @{KEY_ID(kSecAttrKeyType):type, KEY_ID(kSecAttrKeyClass):keyClass};
        CFErrorRef error = NULL;
        SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data, (__bridge CFDictionaryRef)attributes, &error);
        if (error) CFRelease(error);
        if (key) {
            if (actualClass) *actualClass = keyClass;
            return CFBridgingRelease(key);
        }
    }
    return nil;
}

static NSString *Account(NSData *tag, NSString *keyClass) {
    return [NSString stringWithFormat:@"%@.%@", [tag base64EncodedStringWithOptions:0], keyClass];
}

static NSMutableDictionary *StorageQuery(NSDictionary *query) {
    NSMutableDictionary *storage = [@{KEY_ID(kSecClass):KEY_ID(kSecClassGenericPassword)} mutableCopy];
    NSString *type = CanonicalType(query[KEY_ID(kSecAttrKeyType)]);
    NSData *tag = query[KEY_ID(kSecAttrApplicationTag)];
    NSString *keyClass = query[KEY_ID(kSecAttrKeyClass)];
    if (type) storage[KEY_ID(kSecAttrService)] = [KeyServicePrefix stringByAppendingString:type];
    if (tag) storage[KEY_ID(kSecAttrGeneric)] = tag;
    if (tag && keyClass) storage[KEY_ID(kSecAttrAccount)] = Account(tag, keyClass);
    for (id name in @[KEY_ID(kSecAttrAccessGroup), KEY_ID(kSecValuePersistentRef), KEY_ID(kSecAttrLabel)])
        if (query[name]) storage[name] = query[name];
    return storage;
}

static BOOL ReadIdentity(NSDictionary *row, NSString **type, NSData **tag, NSString **keyClass) {
    NSString *service = row[KEY_ID(kSecAttrService)];
    if (![service isKindOfClass:NSString.class] || ![service hasPrefix:KeyServicePrefix]) return NO;
    NSString *storedType = CanonicalType([service substringFromIndex:KeyServicePrefix.length]);
    NSData *storedTag = row[KEY_ID(kSecAttrGeneric)];
    NSString *storedClass = row[KEY_ID(kSecAttrComment)];
    if (!storedType || ![storedTag isKindOfClass:NSData.class] || !storedTag.length ||
        !storedClass || !ValidClass(storedClass) ||
        ![row[KEY_ID(kSecAttrAccount)] isEqual:Account(storedTag, storedClass)]) return NO;
    if (type) *type = storedType;
    if (tag) *tag = storedTag;
    if (keyClass) *keyClass = storedClass;
    return YES;
}

static NSDictionary *ItemIdentity(NSDictionary *row) {
    NSMutableDictionary *identity = [@{
        KEY_ID(kSecClass):KEY_ID(kSecClassGenericPassword),
        KEY_ID(kSecAttrService):row[KEY_ID(kSecAttrService)],
        KEY_ID(kSecAttrAccount):row[KEY_ID(kSecAttrAccount)],
        KEY_ID(kSecAttrGeneric):row[KEY_ID(kSecAttrGeneric)]
    } mutableCopy];
    if (row[KEY_ID(kSecAttrAccessGroup)]) identity[KEY_ID(kSecAttrAccessGroup)] = row[KEY_ID(kSecAttrAccessGroup)];
    return identity;
}

static OSStatus MakeResult(NSDictionary *query, id key, NSData *data, NSData *tag,
                           NSString *type, NSString *keyClass, NSString *label,
                           NSData *persistent, id *output) {
    BOOL dataFlag = [query[KEY_ID(kSecReturnData)] boolValue];
    BOOL attributesFlag = [query[KEY_ID(kSecReturnAttributes)] boolValue];
    BOOL referenceFlag = [query[KEY_ID(kSecReturnRef)] boolValue];
    BOOL persistentFlag = [query[KEY_ID(kSecReturnPersistentRef)] boolValue];
    NSUInteger count = dataFlag + attributesFlag + referenceFlag + persistentFlag;
    if (!count) { *output = nil; return errSecSuccess; }
    if ((referenceFlag || attributesFlag) && !key) return errSecDecode;
    if (persistentFlag && !persistent) return errSecDecode;
    if (count == 1 && !attributesFlag) {
        *output = dataFlag ? data : referenceFlag ? key : persistent;
        return errSecSuccess;
    }
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (attributesFlag) {
        CFDictionaryRef actual = SecKeyCopyAttributes((__bridge SecKeyRef)key);
        if (actual) [result addEntriesFromDictionary:CFBridgingRelease(actual)];
        [result removeObjectForKey:KEY_ID(kSecValueData)];
        result[KEY_ID(kSecClass)] = KEY_ID(kSecClassKey);
        result[KEY_ID(kSecAttrKeyType)] = type;
        result[KEY_ID(kSecAttrKeyClass)] = keyClass;
        result[KEY_ID(kSecAttrApplicationTag)] = tag;
        result[KEY_ID(kSecAttrIsPermanent)] = @YES;
        if (label) result[KEY_ID(kSecAttrLabel)] = label;
        if (query[KEY_ID(kSecAttrAccessGroup)]) result[KEY_ID(kSecAttrAccessGroup)] = query[KEY_ID(kSecAttrAccessGroup)];
    }
    if (dataFlag) result[KEY_ID(kSecValueData)] = data;
    if (referenceFlag) result[KEY_ID(kSecValueRef)] = key;
    if (persistentFlag) result[KEY_ID(kSecValuePersistentRef)] = persistent;
    *output = result;
    return errSecSuccess;
}

OSStatus MCMacKeyItem(CFDictionaryRef attributes, CFDictionaryRef changes, CFTypeRef *result, int operation) {
    if (result) *result = NULL;
    if (!attributes || CFGetTypeID(attributes) != CFDictionaryGetTypeID() || operation < 0 || operation > 3)
        return errSecParam;
    NSDictionary *query = (__bridge NSDictionary *)attributes;
    BOOL persistentOnly = !query[KEY_ID(kSecClass)] && query[KEY_ID(kSecValuePersistentRef)];
    if (![query[KEY_ID(kSecClass)] isEqual:KEY_ID(kSecClassKey)] && !persistentOnly) return errSecUnimplemented;
    OSStatus status = ValidateKeys(query, NO);
    if (status) return status;
    NSString *type = CanonicalType(query[KEY_ID(kSecAttrKeyType)]);
    NSData *tag = query[KEY_ID(kSecAttrApplicationTag)];
    // XAL removes its device key by label, without a type or application tag.
    // ReadIdentity below limits this scan to this adapter's stored key rows.
    BOOL labelSelection = operation != 0 && [query[KEY_ID(kSecAttrLabel)] length] > 0;
    if ((!type || !tag) && !query[KEY_ID(kSecValuePersistentRef)] && !labelSelection)
        return errSecUnimplemented;
    if (query[KEY_ID(kSecValueRef)] && operation != 0) return errSecUnimplemented;
    NSMutableDictionary *storage = StorageQuery(query);
    if (operation == 0) {
        if (!type || !tag || query[KEY_ID(kSecValuePersistentRef)]) return errSecParam;
        NSData *data = query[KEY_ID(kSecValueData)];
        id suppliedKey = query[KEY_ID(kSecValueRef)];
        if (!data && suppliedKey) {
            if (CFGetTypeID((__bridge CFTypeRef)suppliedKey) != SecKeyGetTypeID()) return errSecParam;
            CFErrorRef error = NULL;
            CFDataRef exported = SecKeyCopyExternalRepresentation((__bridge SecKeyRef)suppliedKey, &error);
            if (error) CFRelease(error);
            if (!exported) return errSecParam;
            data = CFBridgingRelease(exported);
        }
        NSString *keyClass = nil;
        id key = ImportKey(data, type, query[KEY_ID(kSecAttrKeyClass)], &keyClass);
        if (!key) return errSecDecode;
        storage[KEY_ID(kSecAttrAccount)] = Account(tag, keyClass);
        storage[KEY_ID(kSecAttrComment)] = keyClass;
        storage[KEY_ID(kSecAttrLabel)] = query[KEY_ID(kSecAttrLabel)] ?: @"Minecraft cryptographic key";
        storage[KEY_ID(kSecValueData)] = data;
        BOOL persistentFlag = [query[KEY_ID(kSecReturnPersistentRef)] boolValue] && result;
        if (persistentFlag) storage[KEY_ID(kSecReturnPersistentRef)] = @YES;
        CFTypeRef storedResult = NULL;
        status = MCMacLegacyItem((__bridge CFDictionaryRef)storage, NULL,
                                persistentFlag ? &storedResult : NULL, 0);
        NSData *persistent = storedResult ? CFBridgingRelease(storedResult) : nil;
        if (status) return status;
        if (result) {
            id value = nil;
            status = MakeResult(query, key, data, tag, type, keyClass, query[KEY_ID(kSecAttrLabel)], persistent, &value);
            if (!status && value) *result = CFBridgingRetain(value);
        }
        return status;
    }
    NSDictionary *update = nil;
    if (operation == 2) {
        if (!changes || CFGetTypeID(changes) != CFDictionaryGetTypeID()) return errSecParam;
        update = (__bridge NSDictionary *)changes;
        status = ValidateKeys(update, YES);
        if (status) return status;
    }
    storage[KEY_ID(kSecReturnAttributes)] = @YES;
    if (operation == 1) storage[KEY_ID(kSecReturnData)] = @YES;
    if (operation == 1 && [query[KEY_ID(kSecReturnPersistentRef)] boolValue])
        storage[KEY_ID(kSecReturnPersistentRef)] = @YES;
    storage[KEY_ID(kSecMatchLimit)] = KEY_ID(kSecMatchLimitAll);
    CFTypeRef found = NULL;
    status = MCMacLegacyItem((__bridge CFDictionaryRef)storage, NULL, &found, 1);
    if (status) return status;
    id rows = CFBridgingRelease(found);
    if (![rows isKindOfClass:NSArray.class]) return errSecDecode;
    NSMutableArray *results = [NSMutableArray array];
    NSUInteger matched = 0;
    BOOL all = [query[KEY_ID(kSecMatchLimit)] isEqual:KEY_ID(kSecMatchLimitAll)];
    for (id row in rows) {
        if (![row isKindOfClass:NSDictionary.class]) return errSecDecode;
        NSString *storedType = nil, *storedClass = nil;
        NSData *storedTag = nil;
        if (!ReadIdentity(row, &storedType, &storedTag, &storedClass)) continue;
        if (type && ![type isEqual:storedType]) continue;
        if (tag && ![tag isEqual:storedTag]) continue;
        if (query[KEY_ID(kSecAttrKeyClass)] && ![query[KEY_ID(kSecAttrKeyClass)] isEqual:storedClass]) continue;
        if (query[KEY_ID(kSecAttrLabel)] && ![query[KEY_ID(kSecAttrLabel)] isEqual:row[KEY_ID(kSecAttrLabel)]]) continue;
        ++matched;
        if (operation == 1) {
            NSData *data = row[KEY_ID(kSecValueData)];
            id key = ImportKey(data, storedType, storedClass, NULL);
            if (!key) return errSecDecode;
            id value = nil;
            status = MakeResult(query, key, data, storedTag, storedType, storedClass,
                                row[KEY_ID(kSecAttrLabel)], row[KEY_ID(kSecValuePersistentRef)], &value);
            if (status) return status;
            if (value) [results addObject:value];
            if (!all) break;
        } else if (operation == 2) {
            NSData *data = update[KEY_ID(kSecValueData)];
            if (data && !ImportKey(data, storedType, storedClass, NULL)) return errSecDecode;
            NSDictionary *identity = ItemIdentity(row);
            status = MCMacLegacyItem((__bridge CFDictionaryRef)identity, (__bridge CFDictionaryRef)update, NULL, 2);
            if (status) return status;
        } else {
            NSDictionary *identity = ItemIdentity(row);
            status = MCMacLegacyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3);
            if (status) return status;
        }
    }
    if (!matched) return persistentOnly ? errSecUnimplemented : errSecItemNotFound;
    if (operation == 1 && result && results.count)
        *result = CFBridgingRetain(all ? (id)results : results.firstObject);
    return errSecSuccess;
}
