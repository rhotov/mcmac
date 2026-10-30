// Optional main-queue pump matching the input support used by PlayTools.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <dlfcn.h>

typedef void (*MCMacDrainMainQueue)(void *);
static MCMacDrainMainQueue drainMainQueue;
static BOOL drainingMainQueue;

@interface MCMacRunLoopPump : NSObject
- (void)tick:(CADisplayLink *)link;
@end

@implementation MCMacRunLoopPump
- (void)tick:(CADisplayLink *)link {
    (void)link;
    if (!NSThread.isMainThread || !drainMainQueue || drainingMainQueue) return;
    // Drained work can reenter the run loop; only suppress our own nested tick.
    drainingMainQueue = YES;
    @try {
        drainMainQueue(NULL);
    } @finally {
        drainingMainQueue = NO;
    }
}
@end

static MCMacRunLoopPump *pumpTarget;
static CADisplayLink *pumpDisplayLink;

void MCMacInstallRunLoopPump(void) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ MCMacInstallRunLoopPump(); });
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        drainMainQueue = (MCMacDrainMainQueue)dlsym(RTLD_DEFAULT, "_dispatch_main_queue_callback_4CF");
        if (!drainMainQueue) return;
        pumpTarget = [MCMacRunLoopPump new];
        pumpDisplayLink = [CADisplayLink displayLinkWithTarget:pumpTarget selector:@selector(tick:)];
        [pumpDisplayLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
    });
}
