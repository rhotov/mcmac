// Focused routing contract tests, without launching a game or generating input.
#import "../compat/keyboard_routing.m"

// Duck-typed UIKit/GC fixtures keep the test independent of windows and hardware.
@interface RoutingFixture : NSObject
@property(nonatomic, strong) id window, viewIfLoaded, presentedViewController, key;
@property(nonatomic, copy) NSArray *subviews;
@property(nonatomic) BOOL isKeyWindow, isFirstResponder, textInput;
@property(nonatomic) UIKeyModifierFlags modifierFlags;
@property(nonatomic) UIKeyboardHIDUsage keyCode;
@property(nonatomic, copy) GCKeyboardValueChangedHandler keyChangedHandler;
@end
@implementation RoutingFixture
- (BOOL)conformsToProtocol:(Protocol *)protocol {
    return (self.textInput && protocol_isEqual(protocol, @protocol(UIKeyInput))) ||
           [super conformsToProtocol:protocol];
}
- (id)buttonForKeyCode:(GCKeyCode)code {
    return code == GCKeyCodeKeyW ? self : nil;
}
@end

static void Expect(BOOL condition, NSString *reason) {
    if (!condition) @throw [NSException exceptionWithName:@"KeyboardRoutingFailure" reason:reason userInfo:nil];
}

int main(void) {
    @autoreleasepool {
        RoutingFixture *window = [RoutingFixture new], *view = [RoutingFixture new];
        RoutingFixture *controller = [RoutingFixture new], *input = [RoutingFixture new];
        view.window = window;
        controller.viewIfLoaded = view;
        window.isKeyWindow = YES;
        __block NSUInteger callbacks = 0;
        input.keyChangedHandler = ^(GCKeyboardInput *i, GCControllerButtonInput *b, GCKeyCode c, BOOL p) {
            (void)i; (void)b; (void)c; (void)p;
            callbacks++;
        };
        RoutingFixture *key = [RoutingFixture new], *press = [RoutingFixture new];
        key.keyCode = UIKeyboardHIDUsageKeyboardW;
        press.key = key;
        NSSet *keys = [NSSet setWithObject:press];
        NSSet *(^route)(NSSet *) = ^NSSet *(NSSet *set) {
            return MCMacUnhandledPresses((id)controller, set, (id)input);
        };
        Expect(route(keys).count == 0, @"gameplay W is consumed");
        Expect(route(keys).count == 0, @"repeated gameplay press is consumed");
        Expect(callbacks == 0, @"routing never duplicates GameController delivery");

        key.modifierFlags = UIKeyModifierCommand;
        Expect([route(keys) isEqual:keys], @"Command shortcut reaches system responders");
        key.modifierFlags = 0;
        RoutingFixture *unknown = [RoutingFixture new], *nonKeyboard = [RoutingFixture new];
        unknown.key = [RoutingFixture new];
        NSSet *mixed = [NSSet setWithArray:@[press, unknown, nonKeyboard]];
        Expect([route(mixed) isEqual:[NSSet setWithArray:@[unknown, nonKeyboard]]],
               @"mixed event retains unsupported keys and nonkeyboard presses");

        RoutingFixture *field = [RoutingFixture new], *container = [RoutingFixture new];
        field.textInput = YES;
        field.isFirstResponder = YES;
        container.subviews = @[field];
        window.subviews = @[container];
        Expect([route(keys) isEqual:keys], @"nested text/IME first responder keeps keyboard input");
        field.isFirstResponder = NO;
        Expect(route(keys).count == 0, @"unfocused text field does not block gameplay");
        controller.presentedViewController = [NSObject new];
        Expect([route(keys) isEqual:keys], @"modal UI keeps keyboard input");
        controller.presentedViewController = nil;
        window.isKeyWindow = NO;
        Expect([route(keys) isEqual:keys], @"inactive window keeps original routing");
        window.isKeyWindow = YES;
        view.window = nil;
        Expect([route(keys) isEqual:keys], @"detached controller keeps original routing");
        view.window = window;
        input.keyChangedHandler = nil;
        Expect([route(keys) isEqual:keys], @"missing game handler never swallows input");
        Expect([MCMacUnhandledPresses((id)controller, keys, nil) isEqual:keys],
               @"missing keyboard never swallows input");
        puts("Keyboard routing smoke checks passed.");
    }
    return 0;
}
