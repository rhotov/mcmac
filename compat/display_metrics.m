// Window-local metrics for the original iOS controller's desktop presentation.
// The renderer owns drawable resizing, together with its cached resolution.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <limits.h>
#import <float.h>
#import <math.h>
#import <stdlib.h>

extern void MCMacLogGeometry(void);

@interface MCMacDisplayResizeState : NSObject {
@public
    BOOL ready;
    BOOL scheduled;
    BOOL resizing;
    NSUInteger initDepth;
    CGSize lastSize;
    BOOL failedAttempt;
    CGSize lastAttemptSize;
}
@end
@implementation MCMacDisplayResizeState
@end

static char DisplayResizeStateKey;
static void ScheduleDisplayResize(id receiver);

static MCMacDisplayResizeState *DisplayState(id receiver, BOOL create) {
    MCMacDisplayResizeState *state = objc_getAssociatedObject(receiver, &DisplayResizeStateKey);
    if (state || !create) return state;
    @synchronized (receiver) {
        state = objc_getAssociatedObject(receiver, &DisplayResizeStateKey);
        if (!state) {
            state = [MCMacDisplayResizeState new];
            objc_setAssociatedObject(receiver, &DisplayResizeStateKey, state, OBJC_ASSOCIATION_RETAIN);
        }
    }
    return state;
}

static BOOL WindowPixels(id receiver, BOOL horizontal, long double *pixels) {
    if (![receiver isKindOfClass:UIViewController.class]) return NO;
    UIView *view = [(UIViewController *)receiver viewIfLoaded];
    if (!view) return NO;
    CGRect bounds = view.bounds;
    CGFloat scale = view.contentScaleFactor;
    if (!isfinite(bounds.size.width) || !isfinite(bounds.size.height) ||
        !isfinite(scale) || bounds.size.width <= 0 || bounds.size.height <= 0 || scale <= 0)
        return NO;
    long double dimension = horizontal ? bounds.size.width : bounds.size.height;
    long double value = dimension * (long double)scale;
    if (!isfinite(value) || value <= 0) return NO;
    *pixels = fmaxl(1.0L, ceill(value));
    return YES;
}

static BOOL WindowPixelSize(id receiver, CGSize *size) {
    long double width, height;
    if (!WindowPixels(receiver, YES, &width) || !WindowPixels(receiver, NO, &height)) return NO;
    *size = CGSizeMake((CGFloat)width, (CGFloat)height);
    return isfinite(size->width) && isfinite(size->height);
}

static void ConfigureRendererOwnedDrawable(id receiver) {
    if (![receiver isKindOfClass:UIViewController.class]) return;
    UIView *view = [(UIViewController *)receiver viewIfLoaded];
    Class metalView = NSClassFromString(@"MTKView");
    SEL setter = NSSelectorFromString(@"setAutoResizeDrawable:");
    if (!metalView || ![view isKindOfClass:metalView] || ![view respondsToSelector:setter]) return;
    // bgfx checks CAMetalLayer.drawableSize against its own resolution at
    // frame submission. Changing the layer before it consumes setRenderingSize
    // triggers Fatal::DeviceLost ("Swapchain mismatches initialized resolution")
    // and a destructive texture/font reload. MTKView's automatic resize has the
    // same race. Let the game's normal swapchain resize update both together;
    // MTKView's separate cached drawableSize is not the renderer's authority.
    ((void (*)(id, SEL, BOOL))objc_msgSend)(view, setter, NO);
}

static Method OwnDisplayMethod(Class cls, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = NULL;
    for (unsigned int i = 0; i < count; ++i)
        if (method_getName(methods[i]) == selector) { found = methods[i]; break; }
    free(methods);
    return found;
}

static BOOL PutDisplayMethod(Class cls, SEL selector, Method originalMethod, IMP replacement) {
    if (!replacement) return NO;
    if (class_addMethod(cls, selector, replacement, method_getTypeEncoding(originalMethod))) return YES;
    Method own = OwnDisplayMethod(cls, selector);
    if (!own) { imp_removeBlock(replacement); return NO; }
    method_setImplementation(own, replacement);
    return YES;
}

// Separate blocks retain a correctly typed original IMP for every selector.
// Saturating before casting also handles unusually large, but finite bounds.
#define DISPLAY_METRIC_BLOCK(Type, Maximum) \
    imp_implementationWithBlock(^Type(id receiver) { \
        long double pixels; \
        if (WindowPixels(receiver, horizontal, &pixels)) { \
            if (pixels >= (long double)(Maximum)) return (Type)(Maximum); \
            return (Type)pixels; \
        } \
        return ((Type (*)(id, SEL))original)(receiver, selector); \
    })

static BOOL InstallMetric(Class cls, SEL selector, BOOL horizontal) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 2) return NO;
    char *encoding = method_copyReturnType(method);
    if (!encoding) return NO;
    const char *type = encoding;
    while (*type && strchr("rnNoORV", *type)) ++type;
    char kind = *type;
    free(encoding);
    IMP original = method_getImplementation(method);
    if (!original) return NO;
    IMP replacement = NULL;
    switch (kind) {
        case 'i': replacement = DISPLAY_METRIC_BLOCK(int, INT_MAX); break;
        case 'I': replacement = DISPLAY_METRIC_BLOCK(unsigned int, UINT_MAX); break;
        case 'q': replacement = DISPLAY_METRIC_BLOCK(long long, LLONG_MAX); break;
        case 'Q': replacement = DISPLAY_METRIC_BLOCK(unsigned long long, ULLONG_MAX); break;
        case 'f': replacement = DISPLAY_METRIC_BLOCK(float, FLT_MAX); break;
        case 'd': replacement = DISPLAY_METRIC_BLOCK(double, DBL_MAX); break;
        default: return NO;
    }
    return PutDisplayMethod(cls, selector, method, replacement);
}

#undef DISPLAY_METRIC_BLOCK

static char BooleanReturnType(Method method) {
    if (!method || method_getNumberOfArguments(method) != 2) return 0;
    char *encoding = method_copyReturnType(method);
    if (!encoding) return 0;
    const char *type = encoding;
    while (*type && strchr("rnNoORV", *type)) ++type;
    char kind = (*type == 'B' || *type == 'c') ? *type : 0;
    free(encoding);
    return kind;
}

static BOOL PerformOriginalInitView(id receiver, SEL selector, IMP original, char kind) {
    MCMacDisplayResizeState *state = DisplayState(receiver, YES);
    CGSize oldSize;
    @synchronized (state) {
        oldSize = state->lastSize;
        ++state->initDepth;
    }
    BOOL success = NO;
    // Record the dimensions requested at entry. A fullscreen transition can
    // advance during the original call; its later size is not proof that the
    // game has already applied that later size to its own caches.
    CGSize appliedSize = CGSizeZero, latestSize = CGSizeZero;
    BOOL validApplied = WindowPixelSize(receiver, &appliedSize);
    BOOL validLatest = NO;
    @try {
        ConfigureRendererOwnedDrawable(receiver);
        success = kind == 'c' ? ((signed char (*)(id, SEL))original)(receiver, selector) != 0 :
                               ((BOOL (*)(id, SEL))original)(receiver, selector);
        validLatest = WindowPixelSize(receiver, &latestSize);
    } @finally {
        @synchronized (state) {
            --state->initDepth;
            if (success && validApplied) {
                state->ready = YES;
                state->lastSize = appliedSize;
                state->failedAttempt = NO;
            } else if (validApplied) {
                // Do not retry a failed target on every layout/frame. A new
                // size or an explicit successful initView allows another try.
                state->failedAttempt = YES;
                state->lastAttemptSize = appliedSize;
            }
        }
    }
    if (getenv("MCMAC_DIAGNOSTICS"))
        NSLog(@"[mcmac] display resize %.0fx%.0f -> %.0fx%.0f initView=%s",
              oldSize.width, oldSize.height, appliedSize.width, appliedSize.height, success ? "yes" : "no");
    if (success && validLatest && (!validApplied || !CGSizeEqualToSize(appliedSize, latestSize)))
        ScheduleDisplayResize(receiver);
    if (success && getenv("MCMAC_DIAGNOSTICS"))
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacLogGeometry(); });
    return success;
}

static BOOL InstallInitView(Class cls) {
    SEL selector = NSSelectorFromString(@"initView");
    Method method = class_getInstanceMethod(cls, selector);
    char kind = BooleanReturnType(method);
    if (!kind) return NO;
    IMP original = method_getImplementation(method);
    if (!original) return NO;
    IMP replacement = kind == 'c' ?
        imp_implementationWithBlock(^signed char(id receiver) {
            return PerformOriginalInitView(receiver, selector, original, kind) ? 1 : 0;
        }) :
        imp_implementationWithBlock(^BOOL(id receiver) {
            return PerformOriginalInitView(receiver, selector, original, kind);
        });
    return PutDisplayMethod(cls, selector, method, replacement);
}

static void ScheduleDisplayResize(id receiver) {
    if (!NSThread.isMainThread || ![(UIViewController *)receiver viewIfLoaded].window) return;
    MCMacDisplayResizeState *state = DisplayState(receiver, NO);
    if (!state) return; // Initial setup belongs exclusively to the original game.
    CGSize requested;
    if (!WindowPixelSize(receiver, &requested)) return;
    @synchronized (state) {
        if (!state->ready || state->initDepth || state->resizing || state->scheduled ||
            CGSizeEqualToSize(requested, state->lastSize) ||
            (state->failedAttempt && CGSizeEqualToSize(requested, state->lastAttemptSize))) return;
        state->scheduled = YES;
    }
    __weak id weakReceiver = receiver;
    dispatch_async(dispatch_get_main_queue(), ^{
        // The queued work must not keep a closing window/controller alive.
        id target = weakReceiver;
        if (!target) return;
        MCMacDisplayResizeState *current = DisplayState(target, NO);
        if (!current) return;
        CGSize latest;
        BOOL valid = WindowPixelSize(target, &latest);
        valid = valid && [(UIViewController *)target viewIfLoaded].window != nil;
        @synchronized (current) {
            current->scheduled = NO;
            if (!valid || !current->ready || current->initDepth || current->resizing ||
                CGSizeEqualToSize(latest, current->lastSize) ||
                (current->failedAttempt && CGSizeEqualToSize(latest, current->lastAttemptSize))) return;
            current->resizing = YES;
        }
        @try {
            SEL selector = NSSelectorFromString(@"initView");
            // Validate the currently dispatched method, including a possible
            // subclass override, before choosing the exact BOOL ABI.
            char kind = BooleanReturnType(class_getInstanceMethod(object_getClass(target), selector));
            if (kind == 'c') ((signed char (*)(id, SEL))objc_msgSend)(target, selector);
            else if (kind == 'B') ((BOOL (*)(id, SEL))objc_msgSend)(target, selector);
            else {
                @synchronized (current) {
                    current->failedAttempt = YES;
                    current->lastAttemptSize = latest;
                }
            }
        } @finally {
            @synchronized (current) { current->resizing = NO; }
        }
        // An initView already in progress suppresses nested scheduling. Retry
        // once it has returned if the final window size differs from its input.
        ScheduleDisplayResize(target);
    });
}

static BOOL InstallPointerLayout(Class cls) {
    SEL selector = @selector(viewDidLayoutSubviews);
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 2) return NO;
    char *returnType = method_copyReturnType(method);
    BOOL returnsVoid = returnType && returnType[0] == 'v';
    free(returnType);
    if (!returnsVoid) return NO;
    Ivar pointerIvar = class_getInstanceVariable(cls, "_pointerView");
    const char *ivarType = pointerIvar ? ivar_getTypeEncoding(pointerIvar) : NULL;
    if (!pointerIvar || !ivarType || ivarType[0] != '@') return NO;
    IMP original = method_getImplementation(method);
    if (!original) return NO;
    IMP replacement = imp_implementationWithBlock(^void(id receiver) {
        // Keep the policy established by initView when layout is notified.
        ConfigureRendererOwnedDrawable(receiver);
        ((void (*)(id, SEL))original)(receiver, selector);
        if (![receiver isKindOfClass:UIViewController.class]) return;
        UIView *view = [(UIViewController *)receiver viewIfLoaded];
        id candidate = object_getIvar(receiver, pointerIvar);
        if (!view) return;
        CGRect bounds = view.bounds;
        if (!isfinite(bounds.origin.x) || !isfinite(bounds.origin.y) ||
            !isfinite(bounds.size.width) || !isfinite(bounds.size.height) ||
            bounds.size.width <= 0 || bounds.size.height <= 0) return;
        if ([candidate isKindOfClass:UIView.class] && candidate != view) {
            UIView *pointer = candidate;
            pointer.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            if (!CGRectEqualToRect(pointer.frame, bounds)) pointer.frame = bounds;
        }
        // Refresh the game's dimensions; its render thread owns the layer.
        ScheduleDisplayResize(receiver);
    });
    return PutDisplayMethod(cls, selector, method, replacement);
}

void MCMacInstallDisplayMetricsFix(void) {
    static NSObject *installationLock;
    static NSUInteger installed;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ installationLock = [NSObject new]; });
    @synchronized (installationLock) {
        Class cls = objc_getClass("minecraftpeViewControllerBase");
        if (!cls) return; // A subsequent call may retry after the class is loaded.
        if (!(installed & 1) && InstallMetric(cls, @selector(width), YES)) installed |= 1;
        if (!(installed & 2) && InstallMetric(cls, @selector(height), NO)) installed |= 2;
        if (!(installed & 4) && InstallMetric(cls, NSSelectorFromString(@"nativeWidth"), YES)) installed |= 4;
        if (!(installed & 8) && InstallMetric(cls, NSSelectorFromString(@"nativeHeight"), NO)) installed |= 8;
        if (!(installed & 32) && InstallInitView(cls)) installed |= 32;
        if (!(installed & 16) && InstallPointerLayout(cls)) installed |= 16;
    }
}
