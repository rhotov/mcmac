// Keep UIKit's save/termination callbacks, then avoid the game's stuck C++
// static destructors after the last window has closed.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <stdatomic.h>
#import <stdlib.h>
#import <unistd.h>

static atomic_bool terminating;
static void (*originalTerminate)(id, SEL, int);

static void MCMacTerminate(id application, SEL selector, int status) {
    atomic_store(&terminating, true);
    originalTerminate(application, selector, status);
    _exit(status);
}

static void MCMacExit(int status) {
    if (atomic_load(&terminating)) _exit(status);
    exit(status);
}

__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } exitBridge = {
    (const void *)MCMacExit, (const void *)exit
};

void MCMacInstallTerminationFix(void) {
    Class application = objc_lookUpClass("UIApplication");
    SEL selector = sel_registerName("_terminateWithStatus:");
    Method method = application ? class_getInstanceMethod(application, selector) : NULL;
    if (method && method_getNumberOfArguments(method) == 3) {
        originalTerminate = (void (*)(id, SEL, int))method_setImplementation(method, (IMP)MCMacTerminate);
        NSLog(@"[mcmac] termination compatibility installed");
    }
}
