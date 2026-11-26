#import <ScreenSaver/ScreenSaver.h>
extern void *ta_saver_new(void);
extern const unsigned char *ta_saver_frame(void *session);
extern void ta_saver_drop(void *session);
extern uint32_t ta_saver_fit_window(void *session, uint32_t width, uint32_t height);

extern void ta_saver_set_intel(void *, void *);
typedef size_t (*AtlasKeyFn)(const char *, unsigned char *, size_t, void *);
extern void *ta_saver_worker_start(const char *, const char *, AtlasKeyFn, void *);
extern void ta_saver_worker_reload(void *);
extern void *ta_saver_worker_osint(void *);
extern void ta_saver_worker_stop(void *);

// The saver never reads the Keychain: it runs inside Apple's shared screen saver host, where an access prompt
// would appear over the saver and an "Always Allow" would extend to other savers. Keyed sources stay off here.

@interface ThreatAtlasSOCView : ScreenSaverView
@property(nonatomic) void *session;
@property(nonatomic) void *worker;
@property(nonatomic) NSTimeInterval lastIntel;
@property(nonatomic) NSTimeInterval lastReload;
@property(nonatomic, strong) NSPanel *options;
@property(nonatomic, strong) NSTimer *fallbackTimer;
@end
@implementation ThreatAtlasSOCView
- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)preview {
    self=[super initWithFrame:frame isPreview:preview];
    if (self) {self.animationTimeInterval=preview ? 1.0/10.0 : 1.0/20.0;[self openSession];}
    return self;
}
- (void)dealloc {[_fallbackTimer invalidate];if (_worker) ta_saver_worker_stop(_worker);if (_session) ta_saver_drop(_session);}
- (void)openSession {
    if (self.session) return;
    self.session=ta_saver_new();
    if (!self.session) return;
    NSURL *support=[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    if (support) {
        // Separate writable cache: the app and saver never write each other's OSINT state.
        NSURL *cache=[support URLByAppendingPathComponent:@"ThreatAtlasSaver/osint" isDirectory:YES];
        NSURL *settings=[support URLByAppendingPathComponent:@"ThreatAtlasPrivateRadar/settings.json"];
        self.worker=ta_saver_worker_start(cache.fileSystemRepresentation,settings.fileSystemRepresentation,NULL,NULL);
    }
    self.lastIntel=0;self.lastReload=0;
}
- (void)ensureRendering {
    if (!self.session) [self openSession];
    if (!self.fallbackTimer && self.window) {
        __weak ThreatAtlasSOCView *weakSelf=self;
        self.fallbackTimer=[NSTimer timerWithTimeInterval:self.animationTimeInterval repeats:YES block:^(NSTimer *timer){
            ThreatAtlasSOCView *view=weakSelf;
            if (!view || !view.window) {[timer invalidate];return;}
            [view setNeedsDisplay:YES];
        }];
        [NSRunLoop.mainRunLoop addTimer:self.fallbackTimer forMode:NSRunLoopCommonModes];
    }
    [self setNeedsDisplay:YES];
}
- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    // Some macOS Settings/legacy hosts attach the view without calling startAnimation.
    if (self.window) {[self ensureRendering];}
    else {[self stopAnimation];}
}
- (void)startAnimation {[super startAnimation];[self ensureRendering];}
- (void)stopAnimation {[self.fallbackTimer invalidate];self.fallbackTimer=nil;if (self.worker) {ta_saver_worker_stop(self.worker);self.worker=NULL;}if (self.session) {ta_saver_drop(self.session);self.session=NULL;}[super stopAnimation];}
- (void)animateOneFrame {[self setNeedsDisplay:YES];}
- (void)drawRect:(NSRect)dirty {
    [[NSColor colorWithCalibratedRed:6.0/255 green:12.0/255 blue:20.0/255 alpha:1] setFill];NSRectFill(self.bounds);
    if (!self.session) {
        [@"Threat Atlas is starting…" drawAtPoint:NSMakePoint(20,20) withAttributes:@{NSForegroundColorAttributeName:NSColor.whiteColor}];
        return;
    }
    NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
    if (self.worker && now-self.lastReload>=10) {ta_saver_worker_reload(self.worker);self.lastReload=now;}
    if (self.worker && now-self.lastIntel>=1) {ta_saver_set_intel(self.session,ta_saver_worker_osint(self.worker));self.lastIntel=now;}
    NSRect pixels=[self convertRectToBacking:self.bounds];
    if (pixels.size.width<=0 || pixels.size.height<=0) return;
    size_t w=ta_saver_fit_window(self.session,(uint32_t)MIN(pixels.size.width,UINT32_MAX),(uint32_t)MIN(pixels.size.height,UINT32_MAX)),h=900;
    if (!w) return;
    const unsigned char *bytes=ta_saver_frame(self.session);if (!bytes) return;
    CGColorSpaceRef space=CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef provider=CGDataProviderCreateWithData(NULL,bytes,w*h*4,NULL);
    CGImageRef image=CGImageCreate(w,h,8,32,w*4,space,kCGImageAlphaPremultipliedLast|kCGBitmapByteOrder32Big,provider,NULL,false,kCGRenderingIntentDefault);
    CGFloat scale=MIN(self.bounds.size.width/w,self.bounds.size.height/h);
    CGFloat dw=w*scale,dh=h*scale;
    CGContextRef context=NSGraphicsContext.currentContext.CGContext;
    CGContextSaveGState(context);
    CGContextTranslateCTM(context,(self.bounds.size.width-dw)/2,(self.bounds.size.height-dh)/2);
    CGContextSetInterpolationQuality(context,kCGInterpolationHigh);
    CGContextDrawImage(context,CGRectMake(0,0,dw,dh),image);
    CGContextRestoreGState(context);
    CGImageRelease(image);CGDataProviderRelease(provider);CGColorSpaceRelease(space);
}
- (BOOL)hasConfigureSheet {return YES;}
- (NSWindow *)configureSheet {
    self.options=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,520,240) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
    self.options.title=[NSString stringWithFormat:@"Threat Atlas SOC %@", [NSBundle bundleForClass:self.class].infoDictionary[@"CFBundleShortVersionString"]];
    NSTextField *text=[NSTextField wrappingLabelWithString:@"Threat Atlas screensaver • shared AtlasSOC view\n\nGreyNoise records and rotating country focus. Optional OSINT sources are off unless the screensaver can read your AtlasSOC Settings. Sources that need an API key stay off, and the screensaver never reads your Keychain.\n\nLIVE means records arrived within 10 seconds. Source cards show their own freshness. Cloudflare Radar is not included in the screensaver. Disconnections trigger automatic retry. The header shows UTC and system local time. Observation times are receipt times in UTC; the provider supplies no event timestamps.\n\nUse macOS settings for idle time and password requirements."];
    text.frame=NSMakeRect(20,55,480,170);[self.options.contentView addSubview:text];
    NSButton *done=[NSButton buttonWithTitle:@"Done" target:self action:@selector(closeOptions:)];done.frame=NSMakeRect(405,15,95,32);[self.options.contentView addSubview:done];return self.options;
}
- (void)closeOptions:(id)sender {[self.options.sheetParent endSheet:self.options];}
@end
