// Generic-password compatibility through the encrypted macOS login keychain.
// This file never logs attributes or stores credentials outside Security.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <limits.h>

#define KC_TAG(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(uint32_t)(d))
#define KC_ID(value) ((__bridge id)(value))

// ABI-compatible declarations avoid using APIs marked unavailable to Catalyst.
typedef struct { UInt32 tag, length; void *data; } KCAttribute;
typedef struct { UInt32 count; KCAttribute *attr; } KCAttributeList;
typedef struct { UInt32 count; UInt32 *tag, *format; } KCAttributeInfo;
typedef OSStatus (*KCCreate)(UInt32, KCAttributeList *, UInt32, const void *, CFTypeRef, CFTypeRef, CFTypeRef *);
typedef OSStatus (*KCSearchCreate)(CFTypeRef, UInt32, const KCAttributeList *, CFTypeRef *);
typedef OSStatus (*KCSearchNext)(CFTypeRef, CFTypeRef *);
typedef OSStatus (*KCCopy)(CFTypeRef, KCAttributeInfo *, UInt32 *, KCAttributeList **, UInt32 *, void **);
typedef OSStatus (*KCFree)(KCAttributeList *, void *);
typedef OSStatus (*KCModify)(CFTypeRef, const KCAttributeList *, UInt32, const void *);
typedef OSStatus (*KCDelete)(CFTypeRef);
typedef OSStatus (*KCPersistent)(CFTypeRef, CFDataRef *);
typedef OSStatus (*KCFromPersistent)(CFDataRef, CFTypeRef *);
typedef CFTypeID (*KCTypeID)(void);

typedef struct {
    KCCreate create; KCSearchCreate search; KCSearchNext next; KCCopy copy;
    KCFree free; KCModify modify; KCDelete remove;
    KCPersistent persistent; KCFromPersistent fromPersistent; KCTypeID typeID;
} KCApi;

static KCApi API(void) {
    static KCApi api;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        api.create = (KCCreate)dlsym(RTLD_DEFAULT, "SecKeychainItemCreateFromContent");
        api.search = (KCSearchCreate)dlsym(RTLD_DEFAULT, "SecKeychainSearchCreateFromAttributes");
        api.next = (KCSearchNext)dlsym(RTLD_DEFAULT, "SecKeychainSearchCopyNext");
        api.copy = (KCCopy)dlsym(RTLD_DEFAULT, "SecKeychainItemCopyAttributesAndData");
        api.free = (KCFree)dlsym(RTLD_DEFAULT, "SecKeychainItemFreeAttributesAndData");
        api.modify = (KCModify)dlsym(RTLD_DEFAULT, "SecKeychainItemModifyAttributesAndData");
        api.remove = (KCDelete)dlsym(RTLD_DEFAULT, "SecKeychainItemDelete");
        api.persistent = (KCPersistent)dlsym(RTLD_DEFAULT, "SecKeychainItemCreatePersistentReference");
        api.fromPersistent = (KCFromPersistent)dlsym(RTLD_DEFAULT, "SecKeychainItemCopyFromPersistentReference");
        api.typeID = (KCTypeID)dlsym(RTLD_DEFAULT, "SecKeychainItemGetTypeID");
    });
    return api;
}

typedef struct { CFStringRef key; UInt32 tag, format; int kind; } KCField;
// kind: 0 UTF-8 string, 1 data, 2 UInt32, 3 boolean, 4 date.
static NSUInteger Fields(KCField *fields) {
    KCField values[] = {
        {kSecAttrService, KC_TAG('s','v','c','e'), 0, 0},
        {kSecAttrAccount, KC_TAG('a','c','c','t'), 0, 0},
        {kSecAttrGeneric, KC_TAG('g','e','n','a'), 6, 1},
        {kSecAttrLabel, KC_TAG('l','a','b','l'), 0, 0},
        {kSecAttrDescription, KC_TAG('d','e','s','c'), 0, 0},
        {kSecAttrComment, KC_TAG('i','c','m','t'), 0, 0},
        {kSecAttrCreator, KC_TAG('c','r','t','r'), 2, 2},
        {kSecAttrType, KC_TAG('t','y','p','e'), 2, 2},
        {kSecAttrIsInvisible, KC_TAG('i','n','v','i'), 2, 3},
        {kSecAttrIsNegative, KC_TAG('n','e','g','a'), 2, 3},
        {kSecAttrCreationDate, KC_TAG('c','d','a','t'), 5, 4},
        {kSecAttrModificationDate, KC_TAG('m','d','a','t'), 5, 4},
    };
    memcpy(fields, values, sizeof(values));
    return sizeof(values) / sizeof(values[0]);
}

static NSString *const Prefix = @"mcmac.v2/";

static NSString *NamespaceService(NSString *service, NSString *group) {
    return [NSString stringWithFormat:@"%@%@/%@", Prefix, group ?: @"default", service];
}

static BOOL DecodeService(NSString *stored, NSString **service, NSString **group) {
    if (![stored hasPrefix:Prefix]) return NO;
    NSString *tail = [stored substringFromIndex:Prefix.length];
    NSRange delimiter = [tail rangeOfString:@"/"];
    if (delimiter.location == NSNotFound) return NO;
    NSString *storedGroup = [tail substringToIndex:delimiter.location];
    if (!storedGroup.length) return NO;
    if (service) *service = [tail substringFromIndex:delimiter.location + 1];
    if (group) *group = [storedGroup isEqual:@"default"] ? nil : storedGroup;
    return YES;
}

static OSStatus Validate(NSDictionary *dictionary, BOOL changes) {
    if (![dictionary isKindOfClass:NSDictionary.class]) return errSecParam;
    KCField fields[16]; NSUInteger count = Fields(fields);
    NSMutableSet *allowed = [NSMutableSet set];
    for (NSUInteger i = 0; i < count; ++i) [allowed addObject:KC_ID(fields[i].key)];
    [allowed addObjectsFromArray:@[
        KC_ID(kSecClass), KC_ID(kSecAttrAccessGroup), KC_ID(kSecAttrAccessible),
        KC_ID(kSecAttrSynchronizable), KC_ID(kSecValueData), KC_ID(kSecValueRef),
        KC_ID(kSecValuePersistentRef), KC_ID(kSecReturnData), KC_ID(kSecReturnAttributes),
        KC_ID(kSecReturnRef), KC_ID(kSecReturnPersistentRef), KC_ID(kSecMatchLimit),
        KC_ID(kSecUseDataProtectionKeychain)
    ]];
    for (id key in dictionary) if (![allowed containsObject:key]) return errSecUnimplemented;
    id group = dictionary[KC_ID(kSecAttrAccessGroup)];
    if (group && (![group isKindOfClass:NSString.class] || ![group length] || [group containsString:@"/"]))
        return errSecParam;
    if (changes && (dictionary[KC_ID(kSecClass)] || dictionary[KC_ID(kSecAttrAccessGroup)] ||
                    dictionary[KC_ID(kSecValueRef)] || dictionary[KC_ID(kSecValuePersistentRef)]))
        return errSecUnimplemented;
    id sync = dictionary[KC_ID(kSecAttrSynchronizable)];
    if (sync && ![sync isEqual:KC_ID(kSecAttrSynchronizableAny)] && [sync respondsToSelector:@selector(boolValue)] && [sync boolValue])
        return errSecUnimplemented; // Legacy login-keychain items are local, never synchronized.
    id data = dictionary[KC_ID(kSecValueData)];
    if (data && (![data isKindOfClass:NSData.class] || [data length] > UINT32_MAX)) return errSecParam;
    id limit = dictionary[KC_ID(kSecMatchLimit)];
    if (limit && ![limit isEqual:KC_ID(kSecMatchLimitOne)] && ![limit isEqual:KC_ID(kSecMatchLimitAll)])
        return errSecUnimplemented;
    for (NSUInteger i = 0; i < count; ++i) {
        id value = dictionary[KC_ID(fields[i].key)];
        if (!value) continue;
        if (fields[i].kind == 0 && ![value isKindOfClass:NSString.class]) return errSecParam;
        if (fields[i].kind == 1 && ![value isKindOfClass:NSData.class]) return errSecParam;
        if ((fields[i].kind == 2 || fields[i].kind == 3) && ![value isKindOfClass:NSNumber.class]) return errSecParam;
        if (fields[i].kind == 4) return errSecUnimplemented;
    }
    return errSecSuccess;
}

// Holds backing NSData objects until the synchronous Security call returns.
static OSStatus Attributes(NSDictionary *values, NSString *group, BOOL adding, BOOL searching,
                           KCAttribute *storage, KCAttributeList *list, NSMutableArray *backing) {
    KCField fields[16]; NSUInteger count = Fields(fields);
    list->count = 0; list->attr = storage;
    for (NSUInteger i = 0; i < count; ++i) {
        if (fields[i].kind == 4) continue;
        id value = values[KC_ID(fields[i].key)];
        BOOL service = CFEqual(fields[i].key, kSecAttrService);
        if (searching) {
            // Legacy keychains distinguish absent and empty descriptive
            // attributes. iOS wrappers round-trip empty defaults in queries.
            BOOL identity = service || CFEqual(fields[i].key, kSecAttrAccount) || CFEqual(fields[i].key, kSecAttrGeneric);
            if (!identity || ([value respondsToSelector:@selector(length)] && [value length] == 0)) continue;
        }
        if (service && searching && !group) continue; // Filter original service after namespace decoding.
        if (!value && adding && (service || CFEqual(fields[i].key, kSecAttrAccount))) value = @"";
        if (!value && adding && CFEqual(fields[i].key, kSecAttrLabel))
            value = values[KC_ID(kSecAttrService)] ?: @"Minecraft";
        if (!value) continue;
        NSData *bytes;
        if (fields[i].kind == 0) {
            if (service) value = NamespaceService(value, group);
            bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
        } else if (fields[i].kind == 1) bytes = value;
        else {
            UInt32 number = fields[i].kind == 3 ? (UInt32)[value boolValue] : [value unsignedIntValue];
            bytes = [NSData dataWithBytes:&number length:sizeof(number)];
        }
        if (!bytes || bytes.length > UINT32_MAX) return errSecParam;
        [backing addObject:bytes];
        storage[list->count++] = (KCAttribute){fields[i].tag, (UInt32)bytes.length, (void *)bytes.bytes};
    }
    return errSecSuccess;
}

static NSDate *DecodeDate(NSData *bytes) {
    NSString *text = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
    if (!text) return nil;
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    formatter.dateFormat = @"yyyyMMddHHmmss'Z'";
    return [formatter dateFromString:text];
}

static OSStatus ReadItem(KCApi api, CFTypeRef item, BOOL wantData,
                         NSMutableDictionary **metadata, NSData **secret) {
    KCField fields[16]; NSUInteger count = Fields(fields);
    UInt32 tags[16], formats[16];
    for (NSUInteger i = 0; i < count; ++i) { tags[i] = fields[i].tag; formats[i] = fields[i].format; }
    KCAttributeInfo info = {(UInt32)count, tags, formats};
    KCAttributeList *attributes = NULL;
    UInt32 itemClass = 0, dataLength = 0;
    void *data = NULL;
    OSStatus status = api.copy(item, &info, &itemClass, &attributes,
                               wantData ? &dataLength : NULL, wantData ? &data : NULL);
    if (status != errSecSuccess) return status;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (itemClass != KC_TAG('g','e','n','p')) status = errSecItemNotFound;
    if (attributes) for (UInt32 i = 0; i < attributes->count; ++i) {
        KCAttribute attr = attributes->attr[i];
        if (attr.length && !attr.data) { status = errSecDecode; break; }
        for (NSUInteger j = 0; j < count; ++j) if (fields[j].tag == attr.tag) {
            NSData *bytes = attr.length ? [NSData dataWithBytes:attr.data length:attr.length] : [NSData data];
            id value = nil;
            if (fields[j].kind == 0) value = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
            else if (fields[j].kind == 1) value = bytes;
            else if (fields[j].kind == 4) value = DecodeDate(bytes);
            else if (attr.length) {
                UInt32 number = 0;
                memcpy(&number, attr.data, MIN((size_t)attr.length, sizeof(number)));
                value = fields[j].kind == 3 ? @((BOOL)(number != 0)) : @(number);
            }
            if (value) result[KC_ID(fields[j].key)] = value;
            break;
        }
    }
    if (wantData && secret && status == errSecSuccess)
        *secret = dataLength ? [NSData dataWithBytes:data length:dataLength] : [NSData data];
    api.free(attributes, data);
    if (status != errSecSuccess) return status;
    NSString *service = nil, *group = nil;
    if (!DecodeService(result[KC_ID(kSecAttrService)], &service, &group)) return errSecItemNotFound;
    result[KC_ID(kSecClass)] = KC_ID(kSecClassGenericPassword);
    result[KC_ID(kSecAttrService)] = service;
    if (group) result[KC_ID(kSecAttrAccessGroup)] = group;
    if (metadata) *metadata = result;
    return errSecSuccess;
}

static BOOL Matches(NSDictionary *query, NSDictionary *item) {
    KCField fields[16]; NSUInteger count = Fields(fields);
    for (NSUInteger i = 0; i < count; ++i) {
        id wanted = query[KC_ID(fields[i].key)];
        id actual = item[KC_ID(fields[i].key)];
        if ([wanted isKindOfClass:NSString.class] && [wanted length] == 0 && !actual) continue;
        if (wanted && ![wanted isEqual:actual]) return NO;
    }
    id group = query[KC_ID(kSecAttrAccessGroup)];
    return !group || [group isEqual:item[KC_ID(kSecAttrAccessGroup)]];
}

static OSStatus Result(KCApi api, CFTypeRef item, NSDictionary *query,
                       NSMutableDictionary *metadata, id *output) {
    BOOL dataFlag = [query[KC_ID(kSecReturnData)] boolValue];
    BOOL attrFlag = [query[KC_ID(kSecReturnAttributes)] boolValue];
    BOOL refFlag = [query[KC_ID(kSecReturnRef)] boolValue];
    BOOL persistentFlag = [query[KC_ID(kSecReturnPersistentRef)] boolValue];
    NSUInteger count = dataFlag + attrFlag + refFlag + persistentFlag;
    if (!count) { *output = nil; return errSecSuccess; }
    NSData *secret = nil;
    if (dataFlag) {
        OSStatus status = ReadItem(api, item, YES, NULL, &secret);
        if (status) return status;
    }
    id persistent = nil;
    if (persistentFlag) {
        if (!api.persistent) return errSecUnimplemented;
        CFDataRef value = NULL;
        OSStatus status = api.persistent(item, &value);
        if (status) return status;
        persistent = CFBridgingRelease(value);
    }
    if (count == 1 && !attrFlag) {
        *output = dataFlag ? secret : refFlag ? KC_ID(item) : persistent;
    } else {
        NSMutableDictionary *value = attrFlag ? [metadata mutableCopy] : [NSMutableDictionary dictionary];
        if (dataFlag) value[KC_ID(kSecValueData)] = secret;
        if (refFlag) value[KC_ID(kSecValueRef)] = KC_ID(item);
        if (persistentFlag) value[KC_ID(kSecValuePersistentRef)] = persistent;
        *output = value;
    }
    return errSecSuccess;
}

// Operations: 0 SecItemAdd, 1 SecItemCopyMatching, 2 SecItemUpdate, 3 SecItemDelete.
// Internet passwords and unsupported query semantics are deliberately delegated
// to the caller. Accessible classes cannot map to legacy keychain lock policy;
// the system login keychain's encryption, locking and ACLs protect these items.
OSStatus MCMacLegacyItem(CFDictionaryRef attributes, CFDictionaryRef changes,
                        CFTypeRef *result, int operation) {
    if (result) *result = NULL;
    if (!attributes || CFGetTypeID(attributes) != CFDictionaryGetTypeID() || operation < 0 || operation > 3)
        return errSecParam;
    NSDictionary *query = (__bridge NSDictionary *)attributes;
    if (!query[KC_ID(kSecClass)] && query[KC_ID(kSecValuePersistentRef)]) {
        NSMutableDictionary *normalized = [query mutableCopy];
        normalized[KC_ID(kSecClass)] = KC_ID(kSecClassGenericPassword);
        query = normalized;
    }
    // This client supplies kSecAttrGeneric as NSString (also accepted by its
    // iOS keychain wrapper). Legacy Security requires its raw UTF-8 bytes.
    if ([query[KC_ID(kSecAttrGeneric)] isKindOfClass:NSString.class]) {
        NSMutableDictionary *normalized = [query mutableCopy];
        normalized[KC_ID(kSecAttrGeneric)] = [query[KC_ID(kSecAttrGeneric)] dataUsingEncoding:NSUTF8StringEncoding];
        query = normalized;
    }
    if (![query[KC_ID(kSecClass)] isEqual:KC_ID(kSecClassGenericPassword)]) return errSecUnimplemented;
    OSStatus status = Validate(query, NO);
    if (status) return status;
    NSDictionary *update = changes ? (__bridge NSDictionary *)changes : nil;
    if (operation == 2) {
        if (!changes || CFGetTypeID(changes) != CFDictionaryGetTypeID()) return errSecParam;
        if ([update[KC_ID(kSecAttrGeneric)] isKindOfClass:NSString.class]) {
            NSMutableDictionary *normalized = [update mutableCopy];
            normalized[KC_ID(kSecAttrGeneric)] = [update[KC_ID(kSecAttrGeneric)] dataUsingEncoding:NSUTF8StringEncoding];
            update = normalized;
        }
        status = Validate(update, YES);
        if (status) return status;
    }
    KCApi api = API();
    if (!api.create || !api.search || !api.next || !api.copy || !api.free || !api.modify || !api.remove)
        return errSecUnimplemented;
    if (operation == 0) {
        if (query[KC_ID(kSecValueRef)] || query[KC_ID(kSecValuePersistentRef)]) return errSecUnimplemented;
        KCAttribute storage[16]; KCAttributeList list;
        NSMutableArray *backing = [NSMutableArray array];
        status = Attributes(query, query[KC_ID(kSecAttrAccessGroup)], YES, NO, storage, &list, backing);
        if (status) return status;
        NSData *data = query[KC_ID(kSecValueData)] ?: [NSData data];
        CFTypeRef item = NULL;
        status = api.create(KC_TAG('g','e','n','p'), &list, (UInt32)data.length, data.bytes, NULL, NULL, &item);
        if (status) return status;
        if (result) {
            NSMutableDictionary *metadata = nil;
            status = ReadItem(api, item, NO, &metadata, NULL);
            id value = nil;
            if (!status) status = Result(api, item, query, metadata, &value);
            if (!status && value) *result = CFBridgingRetain(value);
        }
        if (item) CFRelease(item);
        return status;
    }
    NSMutableArray *items = [NSMutableArray array];
    id persistent = query[KC_ID(kSecValuePersistentRef)];
    id reference = query[KC_ID(kSecValueRef)];
    if (persistent || reference) {
        CFTypeRef item = NULL;
        if (persistent) {
            if (![persistent isKindOfClass:NSData.class] || !api.fromPersistent) return errSecUnimplemented;
            status = api.fromPersistent((__bridge CFDataRef)persistent, &item);
            if (status) return status;
        } else {
            if (!api.typeID || CFGetTypeID((__bridge CFTypeRef)reference) != api.typeID()) return errSecUnimplemented;
            item = CFRetain((__bridge CFTypeRef)reference);
        }
        [items addObject:CFBridgingRelease(item)];
    } else {
        KCAttribute storage[16]; KCAttributeList list;
        NSMutableArray *backing = [NSMutableArray array];
        status = Attributes(query, query[KC_ID(kSecAttrAccessGroup)], NO, YES, storage, &list, backing);
        if (status) return status;
        CFTypeRef search = NULL;
        status = api.search(NULL, KC_TAG('g','e','n','p'), &list, &search);
        if (status) return status;
        for (;;) {
            CFTypeRef item = NULL;
            status = api.next(search, &item);
            if (status == errSecItemNotFound) { status = errSecSuccess; break; }
            if (status) break;
            [items addObject:CFBridgingRelease(item)];
        }
        CFRelease(search);
        if (status) return status;
    }
    NSMutableArray *results = [NSMutableArray array];
    BOOL all = [query[KC_ID(kSecMatchLimit)] isEqual:KC_ID(kSecMatchLimitAll)];
    NSUInteger matched = 0;
    for (id object in items) {
        CFTypeRef item = (__bridge CFTypeRef)object;
        NSMutableDictionary *metadata = nil;
        status = ReadItem(api, item, NO, &metadata, NULL);
        if (status == errSecItemNotFound) continue; // Not in this bridge's namespace.
        if (status) return status;
        if (!Matches(query, metadata)) continue;
        ++matched;
        if (operation == 1) {
            if (result) {
                id value = nil;
                status = Result(api, item, query, metadata, &value);
                if (status) return status;
                if (value) [results addObject:value];
            }
            if (!all) break;
        } else if (operation == 2) {
            KCAttribute storage[16]; KCAttributeList list;
            NSMutableArray *backing = [NSMutableArray array];
            status = Attributes(update, metadata[KC_ID(kSecAttrAccessGroup)], NO, NO, storage, &list, backing);
            if (status) return status;
            NSData *data = update[KC_ID(kSecValueData)];
            static const char empty = 0;
            const void *bytes = data ? (data.length ? data.bytes : &empty) : NULL;
            status = api.modify(item, list.count ? &list : NULL, (UInt32)data.length, bytes);
            if (status) return status;
        } else {
            status = api.remove(item);
            if (status) return status;
        }
    }
    if (!matched) return errSecItemNotFound;
    if (operation == 1 && result && results.count)
        *result = CFBridgingRetain(all ? (id)results : results.firstObject);
    return errSecSuccess;
}
