// Optional input initialization repair for Minecraft's iOS client on Mac.
// Call MCMacInstallInputFix before the game registers its input observers.
#import <Foundation/Foundation.h>
#import <GameController/GameController.h>
#import <objc/runtime.h>

typedef void (*MCMacConnectIMP)(id, SEL, NSNotification *);
typedef void (*MCMacObserveIMP)(id, SEL, id, SEL, NSNotificationName, id);
typedef GCMouse *(*MCMacCurrentMouseIMP)(id, SEL);

static Class inputClass;
static MCMacConnectIMP originalMouseConnect;
static MCMacConnectIMP originalKeyboardConnect;
static MCMacObserveIMP originalAddObserver;
static MCMacCurrentMouseIMP originalCurrentMouse;
// Observer state and retry scheduling are confined to the main queue.
static __weak id inputObserver;
static BOOL repairQueued;
static BOOL repairing;
static NSMutableArray<id> *notificationTokens;
// An override must not change what unrelated threads see as their current mouse.
static _Thread_local void *mouseOverride;
static _Thread_local unsigned connectionDepth;

static GCMouse *MCMacCurrentMouse(id receiver, SEL selector) {
    if (mouseOverride) return (__bridge GCMouse *)mouseOverride;
    return originalCurrentMouse ? originalCurrentMouse(receiver, selector) : nil;
}

static void MCMacCallMouse(id observer, NSNotification *notification) {
    if (!originalMouseConnect) return;
    GCMouse *mouse = [notification.object isKindOfClass:GCMouse.class] ? notification.object : nil;
    void *previous = mouseOverride;
    if (mouse) mouseOverride = (__bridge void *)mouse;
    connectionDepth++;
    @try {
        originalMouseConnect(observer, sel_registerName("onConnectMouse:"), notification);
    } @finally {
        connectionDepth--;
        mouseOverride = previous;
    }
}

static void MCMacCallKeyboard(id observer, NSNotification *notification) {
    if (!originalKeyboardConnect) return;
    connectionDepth++;
    @try {
        originalKeyboardConnect(observer, sel_registerName("onConnectKeyboard:"), notification);
    } @finally {
        connectionDepth--;
    }
}

static void MCMacRepairInput(void) {
    if (!NSThread.isMainThread || repairing) return;
    id observer = inputObserver;
    if (!observer || ![observer isKindOfClass:inputClass]) return;
    repairing = YES;
    NSUInteger miceRetried = 0;
    BOOL keyboardRetried = NO;
    @try {
        for (GCMouse *mouse in GCMouse.mice) {
            if (!mouse.mouseInput || mouse.mouseInput.leftButton.valueChangedHandler) continue;
            MCMacCallMouse(observer, [NSNotification notificationWithName:GCMouseDidConnectNotification
                                                                    object:mouse]);
            miceRetried++;
        }
        GCKeyboard *keyboard = GCKeyboard.coalescedKeyboard;
        if (keyboard.keyboardInput && !keyboard.keyboardInput.keyChangedHandler) {
            MCMacCallKeyboard(observer, [NSNotification notificationWithName:GCKeyboardDidConnectNotification
                                                                        object:keyboard]);
            keyboardRetried = YES;
        }
    } @finally {
        repairing = NO;
    }
    if (miceRetried || keyboardRetried) {
        NSLog(@"[mcmac] input setup retried: mice=%lu keyboard=%d",
              (unsigned long)miceRetried, keyboardRetried);
    }
}

static void MCMacQueueInputRepair(id observer) {
    // A connection callback may itself register notifications. Do not turn
    // that registration into an unbounded sequence of repair attempts.
    if (connectionDepth) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (observer && [observer isKindOfClass:inputClass]) inputObserver = observer;
        if (repairQueued) return;
        repairQueued = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            repairQueued = NO;
            MCMacRepairInput();
        });
    });
}

static void MCMacMouseConnected(id observer, SEL selector, NSNotification *notification) {
    (void)selector;
    MCMacCallMouse(observer, notification);
    MCMacQueueInputRepair(observer);
}

static void MCMacKeyboardConnected(id observer, SEL selector, NSNotification *notification) {
    (void)selector;
    MCMacCallKeyboard(observer, notification);
    MCMacQueueInputRepair(observer);
}

static void MCMacAddObserver(id center, SEL command, id observer, SEL selector,
                             NSNotificationName name, id object) {
    if (originalAddObserver) originalAddObserver(center, command, observer, selector, name, object);
    if ((selector == sel_registerName("onConnectMouse:") ||
         selector == sel_registerName("onConnectKeyboard:")) &&
        [observer isKindOfClass:inputClass]) {
        MCMacQueueInputRepair(observer);
    }
}

static IMP MCMacReplaceMethod(Class cls, SEL selector, IMP replacement) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NULL;
    IMP original = method_getImplementation(method);
    // Add an override when the method is inherited, instead of modifying the
    // superclass implementation used by unrelated classes.
    if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method))) {
        original = method_setImplementation(class_getInstanceMethod(cls, selector), replacement);
    }
    return original;
}

void MCMacInstallInputFix(void) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacInstallInputFix(); });
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        inputClass = objc_lookUpClass("KeyboardAndMouseHandler_apple");
        Class mouseMeta = object_getClass(GCMouse.class);
        SEL mouseSelector = sel_registerName("onConnectMouse:");
        SEL keyboardSelector = sel_registerName("onConnectKeyboard:");
        SEL addSelector = @selector(addObserver:selector:name:object:);
        Method mouseMethod = inputClass ? class_getInstanceMethod(inputClass, mouseSelector) : NULL;
        Method keyboardMethod = inputClass ? class_getInstanceMethod(inputClass, keyboardSelector) : NULL;
        Method addMethod = class_getInstanceMethod(NSNotificationCenter.class, addSelector);
        Method currentMethod = class_getInstanceMethod(mouseMeta, @selector(current));
        // Check all entry points before installing any replacements.
        if (!mouseMethod || !keyboardMethod || !addMethod || !currentMethod ||
            method_getNumberOfArguments(mouseMethod) != 3 ||
            method_getNumberOfArguments(keyboardMethod) != 3 ||
            method_getNumberOfArguments(addMethod) != 6 ||
            method_getNumberOfArguments(currentMethod) != 2) {
            NSLog(@"[mcmac] input repair unavailable: expected methods not found");
            return;
        }
        // Seed the saved implementations before publishing the first hook,
        // so a concurrent callback always has an implementation to forward to.
        originalCurrentMouse = (MCMacCurrentMouseIMP)method_getImplementation(currentMethod);
        originalMouseConnect = (MCMacConnectIMP)method_getImplementation(mouseMethod);
        originalKeyboardConnect = (MCMacConnectIMP)method_getImplementation(keyboardMethod);
        originalAddObserver = (MCMacObserveIMP)method_getImplementation(addMethod);
        originalCurrentMouse = (MCMacCurrentMouseIMP)MCMacReplaceMethod(mouseMeta, @selector(current),
                                                                     (IMP)MCMacCurrentMouse);
        originalMouseConnect = (MCMacConnectIMP)MCMacReplaceMethod(inputClass, mouseSelector,
                                                                (IMP)MCMacMouseConnected);
        originalKeyboardConnect = (MCMacConnectIMP)MCMacReplaceMethod(inputClass, keyboardSelector,
                                                                   (IMP)MCMacKeyboardConnected);
        originalAddObserver = (MCMacObserveIMP)MCMacReplaceMethod(NSNotificationCenter.class, addSelector,
                                                               (IMP)MCMacAddObserver);
        notificationTokens = [NSMutableArray array];
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        for (NSNotificationName name in @[GCMouseDidConnectNotification, GCMouseDidBecomeCurrentNotification,
                                           GCKeyboardDidConnectNotification, @"UIApplicationDidBecomeActiveNotification"]) {
            id token = [center addObserverForName:name object:nil queue:NSOperationQueue.mainQueue
                                      usingBlock:^(NSNotification *note) {
                (void)note;
                MCMacQueueInputRepair(nil);
            }];
            if (token) [notificationTokens addObject:token];
        }
        for (NSNumber *delay in @[@0.5, @2, @5]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ MCMacQueueInputRepair(nil); });
        }
        NSLog(@"[mcmac] input initialization repair installed");
    });
}
