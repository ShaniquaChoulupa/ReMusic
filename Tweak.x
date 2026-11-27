// ReMusic v0.0.2 - experiment: get Google sign-in working in old YouTube Music (3.47.4, iOS 10).
// Idea borrowed from TubeReplacer (GPLv3, (c) Preloading): load Google's "lite" sign-in page,
// hide the browser-upgrade box, and present a different User-Agent.
// Everything it sees is appended to Documents/ReMusic-log.txt as it happens.
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

static NSString *const kRMUserAgent =
    @"Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/603.1.30 "
    @"(KHTML, like Gecko) Version/10.0 Mobile/14E277 Safari/602.1";

// the exact lite sign-in page TubeReplacer uses for YouTube
static NSString *const kRMLiteURL =
    @"https://accounts.google.com/ServiceLogin?service=youtube&uilel=3&passive=true"
    @"&continue=https://www.youtube.com/ytscframe&app=m&hl=en&next=%2F&flowName=WebLiteSignIn";

static NSString *RMDocs(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void RMNote(NSString *line) {
    NSLog(@"[ReMusic] %@", line);
    @synchronized ([NSProcessInfo processInfo]) {
        NSString *path = [RMDocs() stringByAppendingPathComponent:@"ReMusic-log.txt"];
        NSString *stamped = [NSString stringWithFormat:@"%@  %@\n", [NSDate date], line];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) { [stamped writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; return; }
        [fh seekToEndOfFile];
        [fh writeData:[stamped dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

// Any Google account page that is not already the lite flow becomes the lite flow.
static NSURLRequest *RMFix(NSURLRequest *request) {
    NSURL *url = request.URL;
    if (![url.host isEqualToString:@"accounts.google.com"]) return request;
    NSString *abs = url.absoluteString;
    RMNote([NSString stringWithFormat:@"accounts.google.com request: %@", abs]);

    NSMutableURLRequest *r = [request mutableCopy];
    if ([abs rangeOfString:@"WebLiteSignIn"].location == NSNotFound) {
        NSURL *lite = [NSURL URLWithString:kRMLiteURL];
        if (lite) { r.URL = lite; RMNote(@"replaced with the lite sign-in page"); }
    }
    NSString *old = [r valueForHTTPHeaderField:@"Cookie"];
    [r setValue:(old.length ? [old stringByAppendingString:@"; hideBrowserUpgradeBox=true"] : @"hideBrowserUpgradeBox=true")
        forHTTPHeaderField:@"Cookie"];
    [r setValue:kRMUserAgent forHTTPHeaderField:@"User-Agent"];
    return r;
}

%hook UIWebView
- (void)loadRequest:(NSURLRequest *)request {
    NSURLRequest *r = RMFix(request);
    if (![request.URL.host isEqualToString:@"accounts.google.com"])
        RMNote([NSString stringWithFormat:@"UIWebView request: %@", request.URL.host]);
    %orig(r);
    if ([r.URL.host isEqualToString:@"accounts.google.com"]) {
        UIWebView *wv = self;
        // 8 seconds later, look at what the page actually shows (this includes any error text)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSString *info = [wv stringByEvaluatingJavaScriptFromString:
                @"navigator.userAgent + ' || ' + location.href + ' || ' + document.title + ' || ' + "
                @"(document.body ? document.body.innerText.substring(0, 300) : 'no body')"];
            RMNote([NSString stringWithFormat:@"page after 8s: %@", info]);
        });
    }
}
- (void)loadHTMLString:(NSString *)string baseURL:(NSURL *)baseURL {
    RMNote([NSString stringWithFormat:@"UIWebView loadHTMLString baseURL=%@", baseURL]);
    %orig;
}
%end

%hook WKWebView
- (id)loadRequest:(NSURLRequest *)request {
    RMNote([NSString stringWithFormat:@"WKWebView request: %@", request.URL.host]);
    return %orig(RMFix(request));
}
%end

%hook UIApplication
- (BOOL)openURL:(NSURL *)url {
    RMNote([NSString stringWithFormat:@"openURL: %@", url.host]);
    return %orig;
}
%end

// ---- write the app's class names + sign-in related methods to a file ----
static void RMDumpClasses(void) {
    NSMutableString *out = [NSMutableString string];
    NSString *exe = [[NSBundle mainBundle] executablePath];
    unsigned int count = 0;
    const char **names = objc_copyClassNamesForImage([exe UTF8String], &count);
    NSMutableArray *list = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) [list addObject:[NSString stringWithUTF8String:names[i]]];
    free(names);
    [list sortUsingSelector:@selector(compare:)];

    [out appendFormat:@"# ReMusic class dump, app %@ (%@)\n",
        [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"],
        [[NSBundle mainBundle] bundleIdentifier]];
    [out appendFormat:@"# %u classes\n\n", count];

    NSArray *keys = @[@"SSO", @"GTMOAuth2", @"GIPSign", @"Gaia", @"GAIA", @"Login", @"SignIn", @"Signin", @"Auth", @"Account", @"Identity"];
    [out appendString:@"## sign-in related classes (with methods)\n"];
    for (NSString *name in list) {
        BOOL match = NO;
        for (NSString *k in keys) if ([name rangeOfString:k].location != NSNotFound) { match = YES; break; }
        if (!match) continue;
        [out appendFormat:@"\n@interface %@\n", name];
        Class c = NSClassFromString(name);
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        for (unsigned int i = 0; i < mc; i++) [out appendFormat:@"- %@\n", NSStringFromSelector(method_getName(ms[i]))];
        free(ms);
    }
    [out appendString:@"\n## all classes in the app\n"];
    for (NSString *name in list) [out appendFormat:@"%@\n", name];

    NSString *path = [RMDocs() stringByAppendingPathComponent:@"ReMusic-classes.txt"];
    NSError *err = nil;
    BOOL ok = [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
    RMNote([NSString stringWithFormat:@"class list %@ at %@ (%@)", ok ? @"saved" : @"NOT saved", path, err]);
}

%ctor {
    [[NSUserDefaults standardUserDefaults] registerDefaults:@{@"UserAgent": kRMUserAgent}];
    RMNote(@"ReMusic 0.0.2 loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RMDumpClasses();
        dispatch_async(dispatch_get_main_queue(), ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            UIAlertView *a = [[UIAlertView alloc] initWithTitle:@"ReMusic 0.0.2 loaded"
                message:[NSString stringWithFormat:@"Log and class list are in:\n%@", RMDocs()]
                delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
            [a show];
#pragma clang diagnostic pop
        });
    });
}
