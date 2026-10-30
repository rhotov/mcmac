// Optional bridge for process-posted mouse clicks that reach AppKit but not
// GameController's HID callbacks. It leaves the original NSEvent untouched.
#import <Foundation/Foundation.h>
#import <GameController/GameController.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdint.h>
#import <string.h>
#import <math.h>
#import <CoreGraphics/CGGeometry.h>

typedef int64_t (*MCMacEventIntegerField)(const void *, uint32_t);
static MCMacEventIntegerField eventIntegerField;
static id localMouseMonitor;
static NSMutableArray<id> *activationMonitors;
static CFTimeInterval lastDownTime[3];
extern void MCMacSetSyntheticButtonState(GCControllerButtonInput *, BOOL);
extern void MCMacClearSyntheticButtonState(GCControllerButtonInput *);

@interface MCMacPointerRequest : NSObject
@property(nonatomic) CGPoint location;
@end
@implementation MCMacPointerRequest
@end

static UIViewController *MCMacFindGameController(UIViewController *controller) {
    if (!controller) return nil;
    Class gameClass = objc_lookUpClass("minecraftpeViewControllerBase");
    if (gameClass && [controller isKindOfClass:gameClass]) return controller;
    for (UIViewController *child in controller.childViewControllers) {
        UIViewController *found = MCMacFindGameController(child);
        if (found) return found;
    }
    return MCMacFindGameController(controller.presentedViewController);
}

static BOOL MCMacUsablePointerBounds(CGRect bounds) {
    return isfinite(bounds.origin.x) && isfinite(bounds.origin.y) &&
           isfinite(bounds.size.width) && isfinite(bounds.size.height) &&
           bounds.size.width > 0 && bounds.size.height > 0;
}

static BOOL MCMacPointerInController(UIViewController *controller, CGPoint normalized,
                                     UIViewController **target, CGPoint *position) {
    UIView *view = controller.viewIfLoaded;
    UIWindow *uiWindow = view.window;
    SEL pointerSelector = sel_registerName("pointerInteraction:regionForRequest:defaultRegion:");
    if (!uiWindow || ![controller respondsToSelector:pointerSelector]) return NO;
    CGRect bounds = uiWindow.bounds;
    if (!MCMacUsablePointerBounds(bounds)) return NO;
    // Catalyst may scale UIKit points relative to AppKit's content view.
    // Map through the actual window bounds rather than assuming equal units.
    CGPoint inWindow = CGPointMake(bounds.origin.x + normalized.x * bounds.size.width,
                                   bounds.origin.y + normalized.y * bounds.size.height);
    if (!isfinite(inWindow.x) || !isfinite(inWindow.y)) return NO;
    CGPoint inView = [view convertPoint:inWindow fromView:uiWindow];
    if (!isfinite(inView.x) || !isfinite(inView.y)) return NO;
    *target = controller;
    *position = inView;
    return YES;
}

static BOOL MCMacPointerForEvent(id event, UIViewController **target, CGPoint *position) {
    id window = ((id (*)(id, SEL))objc_msgSend)(event, sel_registerName("window"));
    if (!window) return NO;
    id contentView = ((id (*)(id, SEL))objc_msgSend)(window, sel_registerName("contentView"));
    if (!contentView) return NO;
    CGPoint point = ((CGPoint (*)(id, SEL))objc_msgSend)(event, sel_registerName("locationInWindow"));
    point = ((CGPoint (*)(id, SEL, CGPoint, id))objc_msgSend)(contentView, sel_registerName("convertPoint:fromView:"), point, nil);
    CGRect bounds = ((CGRect (*)(id, SEL))objc_msgSend)(contentView, sel_registerName("bounds"));
    if (!MCMacUsablePointerBounds(bounds) || !isfinite(point.x) || !isfinite(point.y)) return NO;
    if (!((BOOL (*)(id, SEL))objc_msgSend)(contentView, sel_registerName("isFlipped")))
        point.y = bounds.origin.y + bounds.size.height - (point.y - bounds.origin.y);
    if (!CGRectContainsPoint(bounds, point)) return NO;
    CGPoint normalized = CGPointMake((point.x - bounds.origin.x) / bounds.size.width,
                                     (point.y - bounds.origin.y) / bounds.size.height);
    if (!isfinite(normalized.x) || !isfinite(normalized.y)) return NO;
    id delegate = UIApplication.sharedApplication.delegate;
    SEL controllerSelector = sel_registerName("viewController");
    UIViewController *direct = [delegate respondsToSelector:controllerSelector] ?
        ((id (*)(id, SEL))objc_msgSend)(delegate, controllerSelector) : nil;
    if (MCMacPointerInController(direct, normalized, target, position)) return YES;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *uiWindow in ((UIWindowScene *)scene).windows) {
            UIViewController *controller = MCMacFindGameController(uiWindow.rootViewController);
            if (MCMacPointerInController(controller, normalized, target, position)) return YES;
        }
    }
    return NO;
}

static void MCMacMoveGamePointer(UIViewController *controller, CGPoint position) {
    if (!controller.view.window) return;
    MCMacPointerRequest *request = [MCMacPointerRequest new];
    request.location = position;
    ((id (*)(id, SEL, id, id, id))objc_msgSend)(controller,
        sel_registerName("pointerInteraction:regionForRequest:defaultRegion:"), nil, request, nil);
}

// NSEventType values are stable ABI; AppKit headers are unavailable to a
// Catalyst target. OtherMouseDown/Up are accepted only for button number 2.
enum {
    MCMacLeftDown = 1, MCMacLeftUp = 2,
    MCMacRightDown = 3, MCMacRightUp = 4,
    MCMacOtherDown = 25, MCMacOtherUp = 26,
    MCMacSourceUnixProcessID = 41,
};

static GCControllerButtonInput *MCMacMouseButton(GCMouse *mouse, NSUInteger number) {
    GCMouseInput *input = mouse.mouseInput;
    if (number == 0) return input.leftButton;
    if (number == 1) return input.rightButton;
    if (number == 2) return input.middleButton;
    return nil;
}

static BOOL MCMacCallbackImage(GCControllerButtonValueChangedHandler callback,
                               const char **basename, uintptr_t *offset) {
    if (basename) *basename = "unknown";
    if (offset) *offset = 0;
    if (!callback) return NO;
    // Apple Blocks ABI on 64-bit: isa(8), flags(4), reserved(4), invoke(8).
    // Inspect the invoke address; never call it with a guessed signature.
    _Static_assert(sizeof(void *) == 8, "This bridge requires the 64-bit Blocks ABI");
    const void *invoke = NULL;
    const unsigned char *blockBytes = (__bridge const void *)callback;
    memcpy(&invoke, blockBytes + 16, sizeof(invoke));
    Dl_info image = {0};
    if (!invoke || !dladdr(invoke, &image) || !image.dli_fname || !image.dli_fbase) return NO;
    const char *name = strrchr(image.dli_fname, '/');
    name = name ? name + 1 : image.dli_fname;
    if (basename) *basename = name;
    if (offset && (uintptr_t)invoke >= (uintptr_t)image.dli_fbase) {
        *offset = (uintptr_t)invoke - (uintptr_t)image.dli_fbase;
    }
    return strcmp(name, "minecraftpe") == 0;
}

static void MCMacForwardSyntheticMouse(id event) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacForwardSyntheticMouse(event); });
        return;
    }
    SEL typeSelector = sel_registerName("type");
    SEL cgEventSelector = sel_registerName("CGEvent");
    if (!eventIntegerField || ![event respondsToSelector:typeSelector] ||
        ![event respondsToSelector:cgEventSelector]) return;
    NSUInteger type = ((NSUInteger (*)(id, SEL))objc_msgSend)(event, typeSelector);
    NSUInteger number;
    BOOL pressed;
    switch (type) {
        case MCMacLeftDown: number = 0; pressed = YES; break;
        case MCMacLeftUp: number = 0; pressed = NO; break;
        case MCMacRightDown: number = 1; pressed = YES; break;
        case MCMacRightUp: number = 1; pressed = NO; break;
        case MCMacOtherDown:
        case MCMacOtherUp: {
            SEL buttonSelector = sel_registerName("buttonNumber");
            if (![event respondsToSelector:buttonSelector] ||
                ((NSInteger (*)(id, SEL))objc_msgSend)(event, buttonSelector) != 2) return;
            number = 2;
            pressed = type == MCMacOtherDown;
            break;
        }
        default: return;
    }
    const void *cgEvent = ((const void *(*)(id, SEL))objc_msgSend)(event, cgEventSelector);
    if (!cgEvent) return;
    int64_t sourcePID = eventIntegerField(cgEvent, MCMacSourceUnixProcessID);
    // Do not duplicate physical mouse input, which already arrives via HID.
    if (sourcePID <= 0) return;
    GCControllerButtonInput *button = MCMacMouseButton(GCMouse.current, number);
    GCControllerButtonValueChangedHandler callback = button.valueChangedHandler;
    if (!MCMacCallbackImage(callback, NULL, NULL)) {
        // UIKit may have replaced the current device's callback. Prefer a
        // callback whose block invoke is in the actual game executable.
        for (GCMouse *mouse in GCMouse.mice) {
            GCControllerButtonInput *candidate = MCMacMouseButton(mouse, number);
            GCControllerButtonValueChangedHandler candidateCallback = candidate.valueChangedHandler;
            if (MCMacCallbackImage(candidateCallback, NULL, NULL)) {
                button = candidate;
                callback = candidateCallback;
                break;
            }
            // Preserve the previous fallback: current mouse when possible,
            // otherwise the first device with a callback.
            if (!callback && candidateCallback) {
                button = candidate;
                callback = candidateCallback;
            }
        }
    }
    if (!callback) return;
    UIViewController *controller = nil;
    CGPoint position = CGPointZero;
    if (!MCMacPointerForEvent(event, &controller, &position)) {
        NSLog(@"[mcmac] synthetic mouse position mapping unavailable");
        return;
    }
    // Process-posted clicks can arrive before UIKit's hover update. Give the
    // game's UI a complete frame at the correct position before pressing.
    // Physical mouse input never takes this path.
    CFTimeInterval now = CACurrentMediaTime();
    if (pressed) {
        lastDownTime[number] = now;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        MCMacMoveGamePointer(controller, position);
    });
    CFTimeInterval when = pressed ? now + 0.060 : MAX(now + 0.060, lastDownTime[number] + 0.120);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((when - now) * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (controller.view.window) {
            MCMacSetSyntheticButtonState(button, pressed);
            callback(button, pressed ? 1.0f : 0.0f, pressed);
            if (!pressed) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                if (!button.isPressed) MCMacClearSyntheticButtonState(button);
            });
        }
    });
}

static void MCMacTryInstallSyntheticMouse(void) {
    if (localMouseMonitor || !NSThread.isMainThread) return;
    Class nsEvent = objc_lookUpClass("NSEvent");
    SEL addMonitor = sel_registerName("addLocalMonitorForEventsMatchingMask:handler:");
    if (!nsEvent || ![nsEvent respondsToSelector:addMonitor]) return;
    eventIntegerField = (MCMacEventIntegerField)dlsym(RTLD_DEFAULT, "CGEventGetIntegerValueField");
    if (!eventIntegerField) return;
    NSUInteger mask = ((NSUInteger)1 << MCMacLeftDown) | ((NSUInteger)1 << MCMacLeftUp) |
                      ((NSUInteger)1 << MCMacRightDown) | ((NSUInteger)1 << MCMacRightUp) |
                      ((NSUInteger)1 << MCMacOtherDown) | ((NSUInteger)1 << MCMacOtherUp);
    id (^handler)(id) = ^id(id event) {
        MCMacForwardSyntheticMouse(event);
        return event;
    };
    localMouseMonitor = ((id (*)(id, SEL, NSUInteger, id))objc_msgSend)(nsEvent, addMonitor, mask, handler);
}

void MCMacInstallSyntheticMouseBridge(void) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacInstallSyntheticMouseBridge(); });
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // AppKit may not yet be loaded from a dylib constructor. Install on
        // the next turn, on activation, and after short startup delays.
        activationMonitors = [NSMutableArray array];
        for (NSNotificationName name in @[@"NSApplicationDidBecomeActiveNotification",
                                           @"UIApplicationDidBecomeActiveNotification"]) {
            id token = [NSNotificationCenter.defaultCenter addObserverForName:name object:nil
                                                                       queue:NSOperationQueue.mainQueue
                                                                  usingBlock:^(NSNotification *note) {
                (void)note;
                MCMacTryInstallSyntheticMouse();
            }];
            if (token) [activationMonitors addObject:token];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacTryInstallSyntheticMouse(); });
        for (NSNumber *delay in @[@0.5, @2]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ MCMacTryInstallSyntheticMouse(); });
        }
    });
}
