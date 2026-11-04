// GameController delivers gameplay keys independently of UIKit's responder
// chain. Consume their otherwise-unhandled UIKit copies at the game controller
// so Catalyst does not forward them to AppKit's no-responder system beep.
#import <UIKit/UIKit.h>
#import <GameController/GameController.h>
#import <objc/runtime.h>

typedef void (*MCMacPressesIMP)(id, SEL, NSSet<UIPress *> *, UIPressesEvent *);
static MCMacPressesIMP originalPressesBegan;

static BOOL MCMacHasTextFocus(UIView *view) {
    if (view.isFirstResponder && [view conformsToProtocol:@protocol(UIKeyInput)]) return YES;
    for (UIView *child in view.subviews)
        if (MCMacHasTextFocus(child)) return YES;
    return NO;
}

static NSSet<UIPress *> *MCMacUnhandledPresses(UIViewController *controller,
                                             NSSet<UIPress *> *presses,
                                             GCKeyboardInput *input) {
    UIWindow *window = controller.viewIfLoaded.window;
    // Leave text/IME input, presented UI and inactive windows on the normal
    // responder path. Never consume a key unless the game's GC handler exists.
    if (!NSThread.isMainThread || !window.isKeyWindow || controller.presentedViewController ||
        MCMacHasTextFocus(window) || !input.keyChangedHandler) return presses;
    NSMutableSet<UIPress *> *unhandled = [presses mutableCopy];
    for (UIPress *press in presses) {
        UIKey *key = press.key;
        if (key && !(key.modifierFlags & UIKeyModifierCommand) &&
            [input buttonForKeyCode:(GCKeyCode)key.keyCode]) {
            [unhandled removeObject:press];
        }
    }
    return unhandled;
}

static void MCMacPressesBegan(id receiver, SEL selector, NSSet<UIPress *> *presses,
                             UIPressesEvent *event) {
    NSSet<UIPress *> *unhandled = MCMacUnhandledPresses(receiver, presses,
                                                       GCKeyboard.coalescedKeyboard.keyboardInput);
    // Do not call the GC callback here: hardware and the synthetic bridge
    // already deliver it. Key-up/cancellation still follow their original path.
    if (unhandled.count) originalPressesBegan(receiver, selector, unhandled, event);
}

void MCMacInstallKeyboardRoutingFix(void) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacInstallKeyboardRoutingFix(); });
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class controller = objc_lookUpClass("minecraftpeViewControllerBase");
        SEL selector = @selector(pressesBegan:withEvent:);
        Method method = controller ? class_getInstanceMethod(controller, selector) : NULL;
        Method fallback = class_getInstanceMethod(UIResponder.class, selector);
        // Only replace the inherited fallback observed in this game version;
        // never overwrite a future game implementation or UIKit's superclass.
        if (!method || !fallback || method_getNumberOfArguments(method) != 4 ||
            method_getImplementation(method) != method_getImplementation(fallback)) {
            NSLog(@"[mcmac] keyboard routing unavailable: expected responder fallback not found");
            return;
        }
        originalPressesBegan = (MCMacPressesIMP)method_getImplementation(method);
        if (class_addMethod(controller, selector, (IMP)MCMacPressesBegan, method_getTypeEncoding(method)))
            NSLog(@"[mcmac] gameplay keyboard responder routing installed");
    });
}
