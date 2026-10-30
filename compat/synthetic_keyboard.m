// Optional process-posted key-event bridge. No event text is read or logged.
#import <Foundation/Foundation.h>
#import <GameController/GameController.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdint.h>

typedef int64_t (*MCMacKeyboardEventIntegerField)(const void *, uint32_t);
static MCMacKeyboardEventIntegerField keyboardEventIntegerField;
static id localKeyboardMonitor;
static NSMutableArray<id> *keyboardActivationMonitors;
extern void MCMacSetSyntheticButtonState(GCControllerButtonInput *, BOOL);
extern void MCMacClearSyntheticButtonState(GCControllerButtonInput *);

// macOS virtual key positions to USB HID keyboard usages (GCKeyCode).
// Unmapped positions remain zero and are never passed to the game.
static const uint16_t macVirtualToHID[128] = {
    [0] = 0x04,  // A
    [1] = 0x16,  // S
    [2] = 0x07,  // D
    [3] = 0x09,  // F
    [4] = 0x0b,  // H
    [5] = 0x0a,  // G
    [6] = 0x1d,  // Z
    [7] = 0x1b,  // X
    [8] = 0x06,  // C
    [9] = 0x19,  // V
    [10] = 0x64, // ISO non-US backslash
    [11] = 0x05, // B
    [12] = 0x14, // Q
    [13] = 0x1a, // W
    [14] = 0x08, // E
    [15] = 0x15, // R
    [16] = 0x1c, // Y
    [17] = 0x17, // T
    [18] = 0x1e, [19] = 0x1f, [20] = 0x20, [21] = 0x21, // 1 2 3 4
    [22] = 0x23, [23] = 0x22, // 6 5
    [24] = 0x2e, // equals
    [25] = 0x26, [26] = 0x24, // 9 7
    [27] = 0x2d, // minus
    [28] = 0x25, [29] = 0x27, // 8 0
    [30] = 0x30, // right bracket
    [31] = 0x12, // O
    [32] = 0x18, // U
    [33] = 0x2f, // left bracket
    [34] = 0x0c, // I
    [35] = 0x13, // P
    [36] = 0x28, // Return
    [37] = 0x0f, // L
    [38] = 0x0d, // J
    [39] = 0x34, // quote
    [40] = 0x0e, // K
    [41] = 0x33, // semicolon
    [42] = 0x31, // backslash
    [43] = 0x36, // comma
    [44] = 0x38, // slash
    [45] = 0x11, // N
    [46] = 0x10, // M
    [47] = 0x37, // period
    [48] = 0x2b, // Tab
    [49] = 0x2c, // Space
    [50] = 0x35, // grave
    [51] = 0x2a, // Backspace
    [53] = 0x29, // Escape
    [64] = 0x6c, // F17
    [65] = 0x63, // keypad decimal
    [67] = 0x55, // keypad multiply
    [69] = 0x57, // keypad plus
    [71] = 0x53, // keypad clear / Num Lock
    [75] = 0x54, // keypad divide
    [76] = 0x58, // keypad Enter
    [78] = 0x56, // keypad minus
    [79] = 0x6d, [80] = 0x6e, // F18 F19
    [81] = 0x67, // keypad equals
    [82] = 0x62, // keypad 0
    [83] = 0x59, [84] = 0x5a, [85] = 0x5b, // keypad 1 2 3
    [86] = 0x5c, [87] = 0x5d, [88] = 0x5e, // keypad 4 5 6
    [89] = 0x5f, [91] = 0x60, [92] = 0x61, // keypad 7 8 9
    [90] = 0x6f, // F20
    [96] = 0x3e, [97] = 0x3f, [98] = 0x40, // F5 F6 F7
    [99] = 0x3c, [100] = 0x41, [101] = 0x42, // F3 F8 F9
    [103] = 0x44, // F11
    [105] = 0x68, [106] = 0x6b, [107] = 0x69, // F13 F16 F14
    [109] = 0x43, [111] = 0x45, [113] = 0x6a, // F10 F12 F15
    [114] = 0x49, // Insert / Help
    [115] = 0x4a, [116] = 0x4b, [117] = 0x4c, // Home PageUp Delete
    [118] = 0x3d, [119] = 0x4d, [120] = 0x3b, // F4 End F2
    [121] = 0x4e, [122] = 0x3a, // PageDown F1
    [123] = 0x50, [124] = 0x4f, [125] = 0x51, [126] = 0x52, // left right down up
};

static void MCMacForwardSyntheticKeyboard(id event) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacForwardSyntheticKeyboard(event); });
        return;
    }
    SEL typeSelector = sel_registerName("type");
    SEL flagsSelector = sel_registerName("modifierFlags");
    SEL keySelector = sel_registerName("keyCode");
    SEL cgEventSelector = sel_registerName("CGEvent");
    if (!keyboardEventIntegerField || ![event respondsToSelector:typeSelector] ||
        ![event respondsToSelector:flagsSelector] || ![event respondsToSelector:keySelector] ||
        ![event respondsToSelector:cgEventSelector]) return;
    NSUInteger type = ((NSUInteger (*)(id, SEL))objc_msgSend)(event, typeSelector);
    if (type != 10 && type != 11) return; // NSEventTypeKeyDown / KeyUp
    NSUInteger flags = ((NSUInteger (*)(id, SEL))objc_msgSend)(event, flagsSelector);
    if (flags & ((NSUInteger)1 << 20)) return; // preserve Command shortcuts
    const void *cgEvent = ((const void *(*)(id, SEL))objc_msgSend)(event, cgEventSelector);
    if (!cgEvent || keyboardEventIntegerField(cgEvent, 41) <= 0) return;
    unsigned short virtualCode = ((unsigned short (*)(id, SEL))objc_msgSend)(event, keySelector);
    if (virtualCode >= 128 || !macVirtualToHID[virtualCode]) return;
    GCKeyboardInput *input = GCKeyboard.coalescedKeyboard.keyboardInput;
    GCKeyboardValueChangedHandler callback = input.keyChangedHandler;
    if (!callback) return;
    GCKeyCode code = (GCKeyCode)macVirtualToHID[virtualCode];
    GCControllerButtonInput *button = [input buttonForKeyCode:code];
    if (!button) return;
    BOOL pressed = type == 10;
    MCMacSetSyntheticButtonState(button, pressed);
    callback(input, button, code, pressed);
    if (!pressed) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        if (!button.isPressed) MCMacClearSyntheticButtonState(button);
    });
}

static void MCMacTryInstallSyntheticKeyboard(void) {
    if (localKeyboardMonitor || !NSThread.isMainThread) return;
    Class nsEvent = objc_lookUpClass("NSEvent");
    SEL addMonitor = sel_registerName("addLocalMonitorForEventsMatchingMask:handler:");
    if (!nsEvent || ![nsEvent respondsToSelector:addMonitor]) return;
    keyboardEventIntegerField = (MCMacKeyboardEventIntegerField)dlsym(RTLD_DEFAULT, "CGEventGetIntegerValueField");
    if (!keyboardEventIntegerField) return;
    NSUInteger mask = ((NSUInteger)1 << 10) | ((NSUInteger)1 << 11);
    id (^handler)(id) = ^id(id event) {
        MCMacForwardSyntheticKeyboard(event);
        return event;
    };
    localKeyboardMonitor = ((id (*)(id, SEL, NSUInteger, id))objc_msgSend)(nsEvent, addMonitor, mask, handler);
}

void MCMacInstallSyntheticKeyboardBridge(void) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacInstallSyntheticKeyboardBridge(); });
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keyboardActivationMonitors = [NSMutableArray array];
        for (NSNotificationName name in @[@"NSApplicationDidBecomeActiveNotification",
                                           @"UIApplicationDidBecomeActiveNotification"]) {
            id token = [NSNotificationCenter.defaultCenter addObserverForName:name object:nil
                                                                       queue:NSOperationQueue.mainQueue
                                                                  usingBlock:^(NSNotification *note) {
                (void)note;
                MCMacTryInstallSyntheticKeyboard();
            }];
            if (token) [keyboardActivationMonitors addObject:token];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacTryInstallSyntheticKeyboard(); });
        for (NSNumber *delay in @[@0.5, @2]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ MCMacTryInstallSyntheticKeyboard(); });
        }
    });
}
