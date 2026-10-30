// A per-instance overlay for synthetic button events. No hardware state or
// private ivars are changed; clearing the overlay restores the original getters.
#import <Foundation/Foundation.h>
#import <GameController/GameController.h>
#import <objc/runtime.h>

static char SyntheticButtonValueKey;

static Method OwnMethod(Class cls, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = NULL;
    for (unsigned int i = 0; i < count; ++i) {
        if (method_getName(methods[i]) == selector) {
            found = methods[i];
            break;
        }
    }
    free(methods);
    return found;
}

// Caller serializes installation. Capture each original IMP in its own block;
// an inherited overlay remains safe when a subclass is subsequently installed.
static BOOL InstallGetter(Class cls, SEL selector, BOOL floatingPoint) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 2) return NO;
    char *returnType = method_copyReturnType(method);
    BOOL compatible = returnType &&
        (floatingPoint ? returnType[0] == 'f' : (returnType[0] == 'B' || returnType[0] == 'c'));
    free(returnType);
    if (!compatible) return NO;
    IMP original = method_getImplementation(method);
    if (!original) return NO;
    IMP replacement;
    if (floatingPoint) {
        replacement = imp_implementationWithBlock(^float(id receiver) {
            NSNumber *overlay = objc_getAssociatedObject(receiver, &SyntheticButtonValueKey);
            if (overlay) return overlay.floatValue;
            return ((float (*)(id, SEL))original)(receiver, selector);
        });
    } else {
        replacement = imp_implementationWithBlock(^BOOL(id receiver) {
            NSNumber *overlay = objc_getAssociatedObject(receiver, &SyntheticButtonValueKey);
            if (overlay) return overlay.boolValue;
            return ((BOOL (*)(id, SEL))original)(receiver, selector);
        });
    }
    if (!replacement) return NO;
    // An inherited Method must never be passed to method_setImplementation:
    // adding to the concrete class first avoids modifying its superclass.
    if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method))) {
        Method own = OwnMethod(cls, selector);
        if (!own) {
            imp_removeBlock(replacement);
            return NO;
        }
        method_setImplementation(own, replacement);
    }
    return YES;
}

static BOOL InstallButtonGetters(Class cls) {
    static NSObject *installationLock;
    static NSMutableDictionary<NSValue *, NSNumber *> *installed;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        installationLock = [NSObject new];
        installed = [NSMutableDictionary dictionary];
    });
    @synchronized (installationLock) {
        NSValue *identity = [NSValue valueWithPointer:(__bridge const void *)cls];
        NSUInteger mask = installed[identity].unsignedIntegerValue;
        if (!(mask & 1) && InstallGetter(cls, @selector(value), YES)) mask |= 1;
        if (!(mask & 2) && InstallGetter(cls, @selector(isPressed), NO)) mask |= 2;
        if (!(mask & 4) && InstallGetter(cls, @selector(isTouched), NO)) mask |= 4;
        installed[identity] = @(mask);
        return mask == 7;
    }
}

void MCMacSetSyntheticButtonState(GCControllerButtonInput *button, BOOL pressed) {
    if (!button) return;
    Class cls = object_getClass(button);
    if (!cls || class_isMetaClass(cls) || !InstallButtonGetters(cls)) return;
    // Atomic association policy keeps concurrent getter reads retained safely.
    objc_setAssociatedObject(button, &SyntheticButtonValueKey,
                             pressed ? @1.0f : @0.0f, OBJC_ASSOCIATION_RETAIN);
}

void MCMacClearSyntheticButtonState(GCControllerButtonInput *button) {
    if (!button) return;
    objc_setAssociatedObject(button, &SyntheticButtonValueKey, nil, OBJC_ASSOCIATION_RETAIN);
}
