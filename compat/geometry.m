// Opt-in layout diagnostics; records geometry only, never view text.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>

static void ViewGeometry(UIView *view, unsigned depth) {
    if (!view || depth > 4) return;
    NSLog(@"[mcmac] geometry depth=%u class=%@ frame=%@ bounds=%@ scale=%.2f layer=%@ layerframe=%@ gravity=%@", depth,
        NSStringFromClass(view.class), NSStringFromCGRect(view.frame), NSStringFromCGRect(view.bounds),
        view.contentScaleFactor, NSStringFromClass(view.layer.class), NSStringFromCGRect(view.layer.frame), view.layer.contentsGravity);
    if ([view.layer respondsToSelector:sel_registerName("drawableSize")]) {
        CGSize size = ((CGSize (*)(id, SEL))objc_msgSend)(view.layer, sel_registerName("drawableSize"));
        NSLog(@"[mcmac] geometry layer drawable=%@", NSStringFromCGSize(size));
    }
    if ([view respondsToSelector:sel_registerName("drawableSize")]) {
        CGSize size = ((CGSize (*)(id, SEL))objc_msgSend)(view, sel_registerName("drawableSize"));
        NSLog(@"[mcmac] geometry view drawable=%@", NSStringFromCGSize(size));
    }
    for (UIView *child in view.subviews) ViewGeometry(child, depth + 1);
}

void MCMacLogGeometry(void) {
    id delegate = UIApplication.sharedApplication.delegate;
    SEL getController = sel_registerName("viewController");
    UIViewController *controller = [delegate respondsToSelector:getController] ? ((id (*)(id, SEL))objc_msgSend)(delegate, getController) : nil;
    if (!controller) return;
    Class appClass = objc_lookUpClass("NSApplication");
    SEL sharedApp = sel_registerName("sharedApplication");
    if ([appClass respondsToSelector:sharedApp]) {
        id app = ((id (*)(id, SEL))objc_msgSend)(appClass, sharedApp);
        id window = ((id (*)(id, SEL))objc_msgSend)(app, sel_registerName("keyWindow"));
        id content = ((id (*)(id, SEL))objc_msgSend)(window, sel_registerName("contentView"));
        CGRect frame = ((CGRect (*)(id, SEL))objc_msgSend)(window, sel_registerName("frame"));
        CGRect bounds = ((CGRect (*)(id, SEL))objc_msgSend)(content, sel_registerName("bounds"));
        NSLog(@"[mcmac] geometry AppKit window=%@ content=%@", NSStringFromCGRect(frame), NSStringFromCGRect(bounds));
    }
    NSLog(@"[mcmac] geometry controller=%@ window=%@ key=%d idiom=%ld screen=%@ native=%@", NSStringFromClass(controller.class),
        NSStringFromCGRect(controller.view.window.bounds), controller.view.window.isKeyWindow,
        (long)UIDevice.currentDevice.userInterfaceIdiom, NSStringFromCGRect(UIScreen.mainScreen.bounds), NSStringFromCGRect(UIScreen.mainScreen.nativeBounds));
    for (NSString *name in @[@"width", @"height", @"nativeWidth", @"nativeHeight"]) {
        SEL selector = NSSelectorFromString(name);
        Method method = class_getInstanceMethod(controller.class, selector);
        if (!method) continue;
        char *type = method_copyReturnType(method);
        if (type && type[0] == 'i') NSLog(@"[mcmac] geometry %@=%d", name, ((int (*)(id, SEL))objc_msgSend)(controller, selector));
        if (type && (type[0] == 'q' || type[0] == 'Q')) NSLog(@"[mcmac] geometry %@=%llu", name, ((unsigned long long (*)(id, SEL))objc_msgSend)(controller, selector));
        if (type && type[0] == 'f') NSLog(@"[mcmac] geometry %@=%.2f", name, (double)((float (*)(id, SEL))objc_msgSend)(controller, selector));
        if (type && type[0] == 'd') NSLog(@"[mcmac] geometry %@=%.2f", name, ((double (*)(id, SEL))objc_msgSend)(controller, selector));
        free(type);
    }
    Ivar pointer = class_getInstanceVariable(controller.class, "_pointerView");
    UIView *pointerView = pointer ? object_getIvar(controller, pointer) : nil;
    NSLog(@"[mcmac] geometry pointerView=%@ frame=%@ bounds=%@", NSStringFromClass(pointerView.class), NSStringFromCGRect(pointerView.frame), NSStringFromCGRect(pointerView.bounds));
    ViewGeometry(controller.view, 0);
}
