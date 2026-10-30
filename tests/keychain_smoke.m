// Exercises actual encrypted macOS keychain storage with disposable test data.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern OSStatus MCMacLegacyItem(CFDictionaryRef, CFDictionaryRef, CFTypeRef *, int);

static void Expect(BOOL condition, NSString *message) {
    if (!condition) @throw [NSException exceptionWithName:@"TestFailure" reason:message userInfo:nil];
}

int main(int argc, const char *argv[]) {
    (void)argv;
    @autoreleasepool {
        NSString *service = [@"mcmac-smoke-" stringByAppendingString:NSUUID.UUID.UUIDString];
        NSData *tag = [service dataUsingEncoding:NSUTF8StringEncoding];
        id generic = argc > 1 ? (id)service : (id)tag;
        NSData *first = [@"disposable-value-1" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *second = [@"disposable-value-2" dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *identity = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                                   (__bridge id)kSecAttrService:service,
                                   (__bridge id)kSecAttrAccount:@"temporary-test-account",
                                   (__bridge id)kSecAttrAccessGroup:@"mcmac-smoke-tests"};
        NSMutableDictionary *item = [identity mutableCopy];
        item[(__bridge id)kSecAttrGeneric] = generic;
        item[(__bridge id)kSecValueData] = first;
        int code = 0;
        CFTypeRef result = NULL;
        @try {
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)item, NULL, NULL, 0) == errSecSuccess, @"add");
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)item, NULL, NULL, 0) == errSecDuplicateItem, @"duplicate");
            NSMutableDictionary *query = [@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                                            (__bridge id)kSecAttrGeneric:generic,
                                            (__bridge id)kSecAttrAccessGroup:@"mcmac-smoke-tests",
                                            (__bridge id)kSecReturnAttributes:@YES,
                                            (__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitOne} mutableCopy];
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)query, NULL, &result, 1) == errSecSuccess, @"generic-only lookup");
            NSDictionary *found = CFBridgingRelease(result); result = NULL;
            Expect([found[(__bridge id)kSecAttrService] isEqual:service], @"service attributes");
            Expect([found[(__bridge id)kSecAttrGeneric] isEqual:tag], @"generic attributes");
            NSMutableDictionary *roundTrip = [found mutableCopy];
            roundTrip[(__bridge id)kSecReturnData] = @YES;
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)roundTrip, NULL, &result, 1) == errSecSuccess, @"full attributes round trip");
            NSData *roundTripData = CFBridgingRelease(result); result = NULL;
            Expect([roundTripData isEqual:first], @"round trip data");
            query[(__bridge id)kSecReturnData] = @YES;
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)query, NULL, &result, 1) == errSecSuccess, @"attributes and data lookup");
            found = CFBridgingRelease(result); result = NULL;
            Expect([found[(__bridge id)kSecValueData] isEqual:first], @"data matches");
            NSDictionary *changes = @{(__bridge id)kSecValueData:second};
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)identity, (__bridge CFDictionaryRef)changes, NULL, 2) == errSecSuccess, @"update");
            [query removeObjectForKey:(__bridge id)kSecReturnAttributes];
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)query, NULL, &result, 1) == errSecSuccess, @"data-only lookup");
            NSData *data = CFBridgingRelease(result); result = NULL;
            Expect([data isEqual:second], @"updated data matches");
            query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)query, NULL, &result, 1) == errSecSuccess, @"match all");
            NSArray *all = CFBridgingRelease(result); result = NULL;
            Expect([all isKindOfClass:NSArray.class] && all.count == 1 && [all.firstObject isEqual:second], @"match all shape");
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3) == errSecSuccess, @"delete");
            Expect(MCMacLegacyItem((__bridge CFDictionaryRef)query, NULL, &result, 1) == errSecItemNotFound, @"not found after delete");
            puts("Keychain CRUD and generic-only queries passed");
        } @catch (NSException *exception) {
            fprintf(stderr, "Keychain test failed: %s\n", exception.reason.UTF8String);
            code = 1;
        } @finally {
            if (result) CFRelease(result);
            MCMacLegacyItem((__bridge CFDictionaryRef)identity, NULL, NULL, 3);
        }
        return code;
    }
}
