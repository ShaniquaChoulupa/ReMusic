// ReMusicDiag.m
// ReMusic 0.1.2 - diagnostics for finding out how YouTube Music 3.47.4 sends its requests.
//
// Writes two files into the app's Documents folder (next to TubeReplacer.log):
//   ReMusic-methods.txt  - method + ivar list of the networking classes (written ~6s after launch)
//   ReMusic-diag.log     - every network request the app makes, plus a trace of calls into the
//                          InnerTube / gRPC request classes (overwritten on every launch)
//
// Cookies and Authorization header values are never written, only their names.
// Nothing here changes how the app behaves except wrapping a few calls so they can be logged.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <dispatch/dispatch.h>

// ---------------------------------------------------------------------------------------------
// Log file
// ---------------------------------------------------------------------------------------------

static NSString *gRMDocs = nil;
static NSFileHandle *gRMLogFH = nil;
static NSObject *gRMLogLock = nil;
static unsigned long long gRMLogBytes = 0;
static const unsigned long long kRMLogCap = 2500000ULL;
static pthread_key_t gRMBusyKey;

static void RMDiagLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void RMDiagLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    @try {
        if (gRMLogLock) {
            @synchronized (gRMLogLock) {
                if (gRMLogFH && gRMLogBytes < kRMLogCap) {
                    static NSDateFormatter *df = nil;
                    if (!df) {
                        df = [[NSDateFormatter alloc] init];
                        [df setDateFormat:@"HH:mm:ss.SSS"];
                    }
                    NSString *line = [NSString stringWithFormat:@"%@ %@ %@\n", [df stringFromDate:[NSDate date]],
                                      [NSThread isMainThread] ? @"M" : @"B", msg];
                    NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
                    [gRMLogFH writeData:d];
                    gRMLogBytes += [d length];
                    if (gRMLogBytes >= kRMLogCap) {
                        [gRMLogFH writeData:[@"-- log is full, nothing more is written --\n" dataUsingEncoding:NSUTF8StringEncoding]];
                    }
                }
            }
        }
    } @catch (NSException *e) {
    }
    [msg release];
}

static void RMSetupLog(void) {
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    gRMDocs = [([docs count] ? [docs objectAtIndex:0] : NSTemporaryDirectory()) retain];
    gRMLogLock = [[NSObject alloc] init];
    NSString *p = [gRMDocs stringByAppendingPathComponent:@"ReMusic-diag.log"];
    [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil];
    gRMLogFH = [[NSFileHandle fileHandleForWritingAtPath:p] retain];
}

// ---------------------------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------------------------

static NSString *RMClip(NSString *s, NSUInteger n) {
    if (![s isKindOfClass:[NSString class]]) return @"";
    if ([s length] <= n) return s;
    return [[s substringToIndex:n] stringByAppendingString:@"..."];
}

static NSString *RMBytes(NSData *d, NSUInteger n) {
    if (![d isKindOfClass:[NSData class]]) return @"nil";
    NSUInteger len = [d length];
    NSUInteger m = len < n ? len : n;
    if (m > 1024) m = 1024;
    const unsigned char *b = (const unsigned char *)[d bytes];
    char *buf = (char *)malloc(m + 1);
    if (!buf) return @"";
    for (NSUInteger i = 0; i < m; i++) {
        unsigned char c = b[i];
        buf[i] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    buf[m] = 0;
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    return s ?: @"";
}

static NSString *RMHex(NSData *d, NSUInteger n) {
    if (![d isKindOfClass:[NSData class]]) return @"nil";
    NSUInteger len = [d length];
    NSUInteger m = len < n ? len : n;
    const unsigned char *b = (const unsigned char *)[d bytes];
    NSMutableString *s = [NSMutableString stringWithCapacity:m * 2];
    for (NSUInteger i = 0; i < m; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static BOOL RMNoisyURL(NSURL *u) {
    NSString *h = [[u host] lowercaseString];
    if (!h) return NO;
    return [h hasSuffix:@"ggpht.com"] || [h hasSuffix:@"ytimg.com"] || [h hasSuffix:@"googleusercontent.com"] ||
           [h hasSuffix:@"gstatic.com"];
}

static NSString *RMReqSummary(NSURLRequest *r) {
    if (![r isKindOfClass:[NSURLRequest class]]) return @"(not a request)";
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"%@ %@", [r HTTPMethod] ?: @"GET", [[r URL] absoluteString]];
    NSDictionary *h = [r allHTTPHeaderFields];
    for (NSString *k in h) {
        NSString *v = [h objectForKey:k];
        NSString *lk = [k lowercaseString];
        if ([lk isEqualToString:@"cookie"]) {
            NSMutableArray *names = [NSMutableArray array];
            for (NSString *part in [v componentsSeparatedByString:@";"]) {
                NSRange eq = [part rangeOfString:@"="];
                NSString *nm = eq.location == NSNotFound ? part : [part substringToIndex:eq.location];
                nm = [nm stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                if ([nm length]) [names addObject:nm];
            }
            [s appendFormat:@"\n    %@: <cookie names: %@>", k, [names componentsJoinedByString:@","]];
        } else if ([lk isEqualToString:@"authorization"]) {
            NSRange sp = [v rangeOfString:@" "];
            [s appendFormat:@"\n    %@: <%@ ... %lu chars>", k,
             sp.location == NSNotFound ? @"?" : [v substringToIndex:sp.location], (unsigned long)[v length]];
        } else {
            [s appendFormat:@"\n    %@: %@", k, RMClip(v, 200)];
        }
    }
    NSData *body = [r HTTPBody];
    if (body) {
        [s appendFormat:@"\n    body %lu bytes: %@\n    body hex: %@", (unsigned long)[body length], RMBytes(body, 400),
         RMHex(body, 48)];
    } else if ([r HTTPBodyStream]) {
        [s appendString:@"\n    body: <stream>"];
    }
    return s;
}

static NSString *RMRespSummary(NSURLResponse *r, NSData *d, NSError *e) {
    NSMutableString *s = [NSMutableString string];
    if ([r isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *h = (NSHTTPURLResponse *)r;
        [s appendFormat:@"HTTP %ld %@", (long)[h statusCode], [[h allHeaderFields] objectForKey:@"Content-Type"] ?: @""];
    } else if (r) {
        [s appendFormat:@"%s", object_getClassName(r)];
    } else {
        [s appendString:@"(no response object)"];
    }
    if (e) {
        [s appendFormat:@" error=%@ %ld %@", [e domain], (long)[e code], RMClip([e localizedDescription], 160)];
    }
    [s appendFormat:@" data=%lu bytes", (unsigned long)[d length]];
    if ([d length]) {
        [s appendFormat:@"\n    %@\n    hex: %@", RMBytes(d, 400), RMHex(d, 32)];
    }
    return s;
}

static void RMLogReq(NSString *tag, NSURLRequest *r) {
    @try {
        if (RMNoisyURL([r URL])) return;
        RMDiagLog(@"%@ %@", tag, RMReqSummary(r));
    } @catch (NSException *e) {
    }
}

static void RMLogResp(NSString *tag, NSURLRequest *r, NSURLResponse *resp, NSData *d, NSError *e) {
    @try {
        if (RMNoisyURL([r URL]) || RMNoisyURL([resp URL])) return;
        RMDiagLog(@"%@ done %@\n    %@", tag, [[r URL] absoluteString] ?: [[resp URL] absoluteString], RMRespSummary(resp, d, e));
    } @catch (NSException *ex) {
    }
}

// ---------------------------------------------------------------------------------------------
// Hook helpers
// ---------------------------------------------------------------------------------------------

static BOOL RMReplace(Class cls, SEL sel, IMP imp, IMP *orig) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    *orig = method_getImplementation(m);
    class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
    return YES;
}

static BOOL RMReplaceClassMethod(Class cls, SEL sel, IMP imp, IMP *orig) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    *orig = method_getImplementation(m);
    class_replaceMethod(object_getClass(cls), sel, imp, method_getTypeEncoding(m));
    return YES;
}

// ---------------------------------------------------------------------------------------------
// GTMSessionFetcher (the Google fetcher the old apps use)
// ---------------------------------------------------------------------------------------------

static IMP rm_o_gtm_begin = NULL;
static IMP rm_o_gtm_begin_delegate = NULL;

static void rm_gtm_begin(id self, SEL _cmd, id handler) {
    id wrapped = handler;
    @try {
        NSURLRequest *req = [self respondsToSelector:@selector(request)] ? [self performSelector:@selector(request)] : nil;
        RMLogReq(@"GTMSessionFetcher begin", req);
        if (handler) {
            void (^orig)(NSData *, NSError *) = (void (^)(NSData *, NSError *))handler;
            __block id fetcher = self;
            wrapped = [[^(NSData *data, NSError *error) {
                @try {
                    NSURLResponse *resp = [fetcher respondsToSelector:@selector(response)] ? [fetcher performSelector:@selector(response)] : nil;
                    NSURLRequest *r2 = [fetcher respondsToSelector:@selector(request)] ? [fetcher performSelector:@selector(request)] : nil;
                    RMLogResp(@"GTMSessionFetcher", r2, resp, data, error);
                } @catch (NSException *e) {
                }
                orig(data, error);
            } copy] autorelease];
        }
    } @catch (NSException *e) {
        wrapped = handler;
    }
    ((void (*)(id, SEL, id))rm_o_gtm_begin)(self, _cmd, wrapped);
}

static void rm_gtm_begin_delegate(id self, SEL _cmd, id delegate, SEL sel) {
    @try {
        NSURLRequest *req = [self respondsToSelector:@selector(request)] ? [self performSelector:@selector(request)] : nil;
        RMLogReq(@"GTMSessionFetcher begin(delegate)", req);
    } @catch (NSException *e) {
    }
    ((void (*)(id, SEL, id, SEL))rm_o_gtm_begin_delegate)(self, _cmd, delegate, sel);
}

// ---------------------------------------------------------------------------------------------
// NSURLSession / NSURLConnection
// ---------------------------------------------------------------------------------------------

static IMP rm_o_dtr = NULL, rm_o_dtrh = NULL, rm_o_utr = NULL, rm_o_utrh = NULL;
static IMP rm_o_conn_async = NULL, rm_o_conn_init = NULL;

static id rm_dtr(id self, SEL _cmd, NSURLRequest *r) {
    RMLogReq(@"NSURLSession dataTask", r);
    return ((id (*)(id, SEL, id))rm_o_dtr)(self, _cmd, r);
}

static id rm_dtrh(id self, SEL _cmd, NSURLRequest *r, id h) {
    RMLogReq(@"NSURLSession dataTask(handler)", r);
    id w = h;
    if (h) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) = (void (^)(NSData *, NSURLResponse *, NSError *))h;
        NSURLRequest *rr = r;
        w = [[^(NSData *d, NSURLResponse *resp, NSError *e) {
            RMLogResp(@"NSURLSession", rr, resp, d, e);
            orig(d, resp, e);
        } copy] autorelease];
    }
    return ((id (*)(id, SEL, id, id))rm_o_dtrh)(self, _cmd, r, w);
}

static id rm_utr(id self, SEL _cmd, NSURLRequest *r, NSData *data) {
    RMLogReq(@"NSURLSession uploadTask", r);
    @try {
        if (!RMNoisyURL([r URL])) RMDiagLog(@"    upload body %lu bytes: %@\n    hex: %@", (unsigned long)[data length], RMBytes(data, 400), RMHex(data, 48));
    } @catch (NSException *e) {
    }
    return ((id (*)(id, SEL, id, id))rm_o_utr)(self, _cmd, r, data);
}

static id rm_utrh(id self, SEL _cmd, NSURLRequest *r, NSData *data, id h) {
    RMLogReq(@"NSURLSession uploadTask(handler)", r);
    @try {
        if (!RMNoisyURL([r URL])) RMDiagLog(@"    upload body %lu bytes: %@\n    hex: %@", (unsigned long)[data length], RMBytes(data, 400), RMHex(data, 48));
    } @catch (NSException *e) {
    }
    id w = h;
    if (h) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) = (void (^)(NSData *, NSURLResponse *, NSError *))h;
        NSURLRequest *rr = r;
        w = [[^(NSData *d, NSURLResponse *resp, NSError *e) {
            RMLogResp(@"NSURLSession", rr, resp, d, e);
            orig(d, resp, e);
        } copy] autorelease];
    }
    return ((id (*)(id, SEL, id, id, id))rm_o_utrh)(self, _cmd, r, data, w);
}

static void rm_conn_async(id self, SEL _cmd, NSURLRequest *r, NSOperationQueue *q, id h) {
    RMLogReq(@"NSURLConnection async", r);
    id w = h;
    if (h) {
        void (^orig)(NSURLResponse *, NSData *, NSError *) = (void (^)(NSURLResponse *, NSData *, NSError *))h;
        NSURLRequest *rr = r;
        w = [[^(NSURLResponse *resp, NSData *d, NSError *e) {
            RMLogResp(@"NSURLConnection", rr, resp, d, e);
            orig(resp, d, e);
        } copy] autorelease];
    }
    ((void (*)(id, SEL, id, id, id))rm_o_conn_async)(self, _cmd, r, q, w);
}

static id rm_conn_init(id self, SEL _cmd, NSURLRequest *r, id delegate, BOOL start) {
    RMLogReq(@"NSURLConnection init", r);
    return ((id (*)(id, SEL, id, id, BOOL))rm_o_conn_init)(self, _cmd, r, delegate, start);
}

static Class RMSessionTarget(SEL sel) {
    Class base = NSClassFromString(@"NSURLSession");
    Class local = NSClassFromString(@"__NSURLSessionLocal");
    if (base && local && class_getInstanceMethod(local, sel) != class_getInstanceMethod(base, sel)) return local;
    return base;
}

static void RMHookNetwork(void) {
    Class gtm = NSClassFromString(@"GTMSessionFetcher");
    RMDiagLog(@"hook GTMSessionFetcher beginFetchWithCompletionHandler: %d",
              RMReplace(gtm, @selector(beginFetchWithCompletionHandler:), (IMP)rm_gtm_begin, &rm_o_gtm_begin));
    RMDiagLog(@"hook GTMSessionFetcher beginFetchWithDelegate:didFinishSelector: %d",
              RMReplace(gtm, @selector(beginFetchWithDelegate:didFinishSelector:), (IMP)rm_gtm_begin_delegate, &rm_o_gtm_begin_delegate));

    SEL s1 = @selector(dataTaskWithRequest:);
    SEL s2 = @selector(dataTaskWithRequest:completionHandler:);
    SEL s3 = @selector(uploadTaskWithRequest:fromData:);
    SEL s4 = @selector(uploadTaskWithRequest:fromData:completionHandler:);
    RMDiagLog(@"hook NSURLSession dataTaskWithRequest: %d", RMReplace(RMSessionTarget(s1), s1, (IMP)rm_dtr, &rm_o_dtr));
    RMDiagLog(@"hook NSURLSession dataTaskWithRequest:completionHandler: %d", RMReplace(RMSessionTarget(s2), s2, (IMP)rm_dtrh, &rm_o_dtrh));
    RMDiagLog(@"hook NSURLSession uploadTaskWithRequest:fromData: %d", RMReplace(RMSessionTarget(s3), s3, (IMP)rm_utr, &rm_o_utr));
    RMDiagLog(@"hook NSURLSession uploadTaskWithRequest:fromData:completionHandler: %d", RMReplace(RMSessionTarget(s4), s4, (IMP)rm_utrh, &rm_o_utrh));

    Class conn = NSClassFromString(@"NSURLConnection");
    RMDiagLog(@"hook NSURLConnection sendAsynchronousRequest: %d",
              RMReplaceClassMethod(conn, @selector(sendAsynchronousRequest:queue:completionHandler:), (IMP)rm_conn_async, &rm_o_conn_async));
    RMDiagLog(@"hook NSURLConnection initWithRequest:delegate:startImmediately: %d",
              RMReplace(conn, @selector(initWithRequest:delegate:startImmediately:), (IMP)rm_conn_init, &rm_o_conn_init));
}

// ---------------------------------------------------------------------------------------------
// Call tracer for the InnerTube / gRPC request classes
// ---------------------------------------------------------------------------------------------

typedef struct {
    const char *cls;
    SEL sel;
    IMP orig;
    int nargs;
    char kinds[8];
    char isBlock[8];
    char retKind;
    int count;
} RMTrace;

static int gRMTraceTotal = 0;
static const int kRMTracePerSel = 10;
static const int kRMTraceMax = 2500;

static NSString *RMDescribe(id o) {
    if (!o) return @"nil";
    uintptr_t p = (uintptr_t)o;
    if (p < 0x1000 || (p & 3)) return [NSString stringWithFormat:@"<bad %p>", o];
    @try {
        if ([o isKindOfClass:[NSString class]]) return [NSString stringWithFormat:@"\"%@\"", RMClip(o, 240)];
        if ([o isKindOfClass:[NSURL class]]) return [NSString stringWithFormat:@"URL(%@)", RMClip([o absoluteString], 240)];
        if ([o isKindOfClass:[NSURLRequest class]]) return [NSString stringWithFormat:@"REQUEST(%@)", RMReqSummary(o)];
        if ([o isKindOfClass:[NSNumber class]]) return [NSString stringWithFormat:@"%@", o];
        if ([o isKindOfClass:[NSData class]])
            return [NSString stringWithFormat:@"NSData(%lu bytes: %@)", (unsigned long)[o length], RMBytes(o, 160)];
        if ([o isKindOfClass:[NSDictionary class]]) {
            NSArray *keys = [o allKeys];
            NSMutableArray *ks = [NSMutableArray array];
            for (id k in keys) {
                if ([ks count] >= 12) break;
                [ks addObject:[NSString stringWithFormat:@"%@", k]];
            }
            return [NSString stringWithFormat:@"NSDictionary(%lu keys: %@)", (unsigned long)[o count], [ks componentsJoinedByString:@","]];
        }
        if ([o isKindOfClass:[NSArray class]]) return [NSString stringWithFormat:@"NSArray(%lu)", (unsigned long)[o count]];
        if ([o isKindOfClass:[NSError class]])
            return [NSString stringWithFormat:@"NSError(%@ %ld %@)", [o domain], (long)[o code], RMClip([o localizedDescription], 160)];
        Class gpb = NSClassFromString(@"GPBMessage");
        if (gpb && [o isKindOfClass:gpb]) {
            NSData *d = [o performSelector:@selector(data)];
            return [NSString stringWithFormat:@"%s(proto %lu bytes: %@ | hex %@)", object_getClassName(o),
                    (unsigned long)[d length], RMBytes(d, 200), RMHex(d, 40)];
        }
        return [NSString stringWithFormat:@"<%s %p>", object_getClassName(o), o];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"<%s %p (describe failed)>", object_getClassName(o), o];
    }
}

static NSString *RMArg(char kind, char blk, uintptr_t v) {
    switch (kind) {
        case '@':
            if (blk) return v ? @"<block>" : @"nil";
            return RMDescribe((id)v);
        case '#':
            return v ? [NSString stringWithFormat:@"%s", class_getName((Class)v)] : @"Nil";
        case ':':
            return v ? [NSString stringWithFormat:@"@selector(%s)", sel_getName((SEL)v)] : @"NULL";
        case 'B':
        case 'c':
        case 'C':
            return [NSString stringWithFormat:@"%d", (int)(v & 0xff)];
        case 's':
            return [NSString stringWithFormat:@"%d", (int)(short)(v & 0xffff)];
        case 'S':
            return [NSString stringWithFormat:@"%u", (unsigned)(v & 0xffff)];
        case 'i':
        case 'l':
            return [NSString stringWithFormat:@"%d", (int)v];
        case 'I':
        case 'L':
            return [NSString stringWithFormat:@"%u", (unsigned)v];
        default:
            return [NSString stringWithFormat:@"%p", (void *)v];
    }
}

static void RMLogCall(RMTrace *t, id self_, uintptr_t *a) {
    NSMutableString *s = [NSMutableString stringWithFormat:@"CALL -[%s %s]", t->cls, sel_getName(t->sel)];
    [s appendFormat:@"\n    self=<%s %p>", object_getClassName(self_), self_];
    for (int i = 0; i < t->nargs && i < 6; i++) {
        [s appendFormat:@"\n    arg%d(%c%s)=%@", i + 1, t->kinds[i], t->isBlock[i] ? "?" : "", RMArg(t->kinds[i], t->isBlock[i], a[i])];
    }
    RMDiagLog(@"%@", s);
}

static BOOL RMKindOK(const char *enc, BOOL allowVoid) {
    while (*enc && strchr("rnNoORV", *enc)) enc++;
    if (!*enc) return NO;
    if (allowVoid && *enc == 'v') return YES;
    return strchr("@#:BcCiIlLsS^*", *enc) != NULL;
}

static char RMKindChar(const char *enc) {
    while (*enc && strchr("rnNoORV", *enc)) enc++;
    return *enc;
}

static BOOL RMSkipName(const char *n) {
    static const char *skip[] = {"dealloc", ".cxx_destruct", "retain", "release", "autorelease", "retainCount", "description",
                                 "debugDescription", "hash", "isEqual:", "class", "init", "copyWithZone:", "mutableCopyWithZone:",
                                 "respondsToSelector:", "forwardingTargetForSelector:", "methodSignatureForSelector:",
                                 "forwardInvocation:", "doesNotRecognizeSelector:", "superclass", "isKindOfClass:", NULL};
    for (int i = 0; skip[i]; i++)
        if (strcmp(n, skip[i]) == 0) return YES;
    return NO;
}

static BOOL RMZeroArgInteresting(const char *n) {
    static const char *words[] = {"equest", "etch", "erform", "tart", "egin", "xecute", "uthoriz", "oken", "URL", "eader", "ancel", NULL};
    for (int i = 0; words[i]; i++)
        if (strstr(n, words[i])) return YES;
    return NO;
}

static void RMTraceClass(Class cls) {
    unsigned int count = 0;
    Method *list = class_copyMethodList(cls, &count);
    int hooked = 0;
    for (unsigned int i = 0; i < count; i++) {
        Method m = list[i];
        SEL sel = method_getName(m);
        const char *name = sel_getName(sel);
        if (RMSkipName(name)) continue;
        int na = (int)method_getNumberOfArguments(m) - 2;
        if (na < 0 || na > 6) continue;
        // property setters are noise
        if (na == 1 && strncmp(name, "set", 3) == 0 && name[3] >= 'A' && name[3] <= 'Z') continue;
        if (na == 0 && !RMZeroArgInteresting(name)) continue;

        char rt[32];
        method_getReturnType(m, rt, sizeof(rt));
        if (!RMKindOK(rt, YES)) continue;

        BOOL ok = YES;
        RMTrace *t = (RMTrace *)calloc(1, sizeof(RMTrace));
        if (!t) break;
        for (int a = 0; a < na; a++) {
            char *at = method_copyArgumentType(m, (unsigned int)a + 2);
            if (!at || !RMKindOK(at, NO)) {
                ok = NO;
                if (at) free(at);
                break;
            }
            t->kinds[a] = RMKindChar(at);
            const char *q = at;
            while (*q && strchr("rnNoORV", *q)) q++;
            t->isBlock[a] = (q[0] == '@' && q[1] == '?') ? 1 : 0;
            free(at);
        }
        if (!ok) {
            free(t);
            continue;
        }
        t->cls = class_getName(cls);
        t->sel = sel;
        t->orig = method_getImplementation(m);
        t->nargs = na;
        t->retKind = RMKindChar(rt);

        id (^blk)(id, id, id, id, id, id, id) = ^id(id s, id a1, id a2, id a3, id a4, id a5, id a6) {
            if (t->count < kRMTracePerSel && gRMTraceTotal < kRMTraceMax && !pthread_getspecific(gRMBusyKey)) {
                pthread_setspecific(gRMBusyKey, (void *)1);
                @try {
                    uintptr_t args[6] = {(uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5, (uintptr_t)a6};
                    RMLogCall(t, s, args);
                } @catch (NSException *e) {
                }
                pthread_setspecific(gRMBusyKey, NULL);
                t->count++;
                gRMTraceTotal++;
            }
            return ((id (*)(id, SEL, id, id, id, id, id, id))t->orig)(s, t->sel, a1, a2, a3, a4, a5, a6);
        };
        IMP imp = imp_implementationWithBlock(blk);
        method_setImplementation(m, imp);
        hooked++;
    }
    if (list) free(list);
    RMDiagLog(@"trace: %s hooked %d of %u methods", class_getName(cls), hooked, count);
}

static NSString *RMPath(NSString *name) {
    return [gRMDocs stringByAppendingPathComponent:name];
}

static void RMInstallTracer(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *disabled = RMPath(@"ReMusic-trace.disabled");
    NSString *pending = RMPath(@"ReMusic-trace.pending");
    NSString *ok = RMPath(@"ReMusic-trace.ok");
    if ([fm fileExistsAtPath:disabled]) {
        RMDiagLog(@"trace: OFF (ReMusic-trace.disabled exists - delete that file to turn it back on)");
        return;
    }
    if ([fm fileExistsAtPath:pending] && ![fm fileExistsAtPath:ok]) {
        [fm createFileAtPath:disabled contents:nil attributes:nil];
        RMDiagLog(@"trace: OFF - the last launch with tracing did not get through its first 10 seconds, so tracing is switched off. Delete ReMusic-trace.disabled and ReMusic-trace.pending to try again.");
        return;
    }
    [fm removeItemAtPath:ok error:nil];
    [fm createFileAtPath:pending contents:nil attributes:nil];

    static const char *names[] = {
        "YTInnerTubeRequestor", "YTMInnerTubeRequestor", "YTInnerTubeRequestorFactory", "YTMInnerTubeRequestorFactory",
        "YTInnerTubeRequestorRegistry", "YTInnerTubeRequestFactory", "YTInnerTubeRequest", "YTInnerTubeRequestState",
        "YTInnerTubeStreamRequestState", "YTInnerTubeURLBuilderGRPC", "YTInnerTubeURLBuilderStubby", "YTInnerTubeResponseWrapper",
        "YTInnerTubeMultipleService", "YTInnerTubeChannelAuthenticator", "YTInnerTubeContextFactory", "YTMInnerTubeContextDecorator",
        "YTBaseInnerTubeService", "YTBaseInnerTubeRequestService", "YTBaseInnerTubeRequestState", "YTBaseNetworkService",
        "YTMBrowseService", "YTMWatchNextService", "YTMSuggestService", "YTMMusicEntityBrowseService", "YTMMusicSearchLibraryService",
        "YTSearchService", "YTPlayerService", "YTBrowseService", "YTHotSwappableFetcherServiceAndURLBuilder",
        "YTFetcherTaskConfiguration", "GTMSessionFetcherService", "YTGRPCFetcherService", "YTGRPCFetcherTask",
        "GRPCProtoMethod", "GRPCUnaryProtoCall", "GRPCStreamingProtoCall", "GRPCProtoCall", "YTApiaryDeviceAuthenticator",
        "YTAuthorizedUrlHandler", NULL};
    for (int i = 0; names[i]; i++) {
        Class c = objc_getClass(names[i]);
        if (!c) {
            RMDiagLog(@"trace: class %s not present", names[i]);
            continue;
        }
        RMTraceClass(c);
    }
    RMDiagLog(@"trace: ON");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC), dispatch_get_global_queue(0, 0), ^{
        [[NSFileManager defaultManager] createFileAtPath:RMPath(@"ReMusic-trace.ok") contents:nil attributes:nil];
        RMDiagLog(@"trace: survived 10s, marker written");
    });
}

// ---------------------------------------------------------------------------------------------
// Method dump
// ---------------------------------------------------------------------------------------------

static BOOL RMHas(const char *n, const char *x) { return strstr(n, x) != NULL; }
static BOOL RMEnds(const char *n, const char *x) {
    size_t a = strlen(n), b = strlen(x);
    return a >= b && strcmp(n + a - b, x) == 0;
}
static BOOL RMStarts(const char *n, const char *x) { return strncmp(n, x, strlen(x)) == 0; }

static BOOL RMWantDump(const char *n) {
    if (RMHas(n, "InnerTube") && !RMHas(n, "Cell") && !RMHas(n, "CollectionView")) return YES;
    if (RMStarts(n, "YTBase")) return YES;
    if (RMStarts(n, "YTM") && (RMEnds(n, "Service") || RMEnds(n, "Requestor") || RMEnds(n, "Coordinator") || RMEnds(n, "Fetcher"))) return YES;
    if (RMStarts(n, "YT") && RMEnds(n, "Service")) return YES;
    if (RMStarts(n, "YTGRPC") || RMStarts(n, "YTApiary") || RMStarts(n, "YTAuthorized")) return YES;
    static const char *exact[] = {
        "GTMSessionFetcher", "GTMSessionFetcherService", "YTFetcherTaskConfiguration", "YTHotSwappableFetcherServiceAndURLBuilder",
        "YTHotConfig", "YTIBrowseRequest", "YTIBrowseResponse", "YTISearchRequest", "YTISearchResponse", "YTIPlayerRequest",
        "YTIPlayerResponse", "YTIConfigRequest", "YTIConfigResponse", "YTIGuideRequest", "YTIGuideResponse", "GRPCProtoCall",
        "GRPCUnaryProtoCall", "GRPCStreamingProtoCall", "GRPCCall2", "GRPCCallOptions", "GRPCRequestOptions", "GRPCProtoMethod",
        "GRPCTransportManager", "YTIdentity", "YTIdentityRetriever", "YTIdentityController", "SSOService", NULL};
    for (int i = 0; exact[i]; i++)
        if (strcmp(n, exact[i]) == 0) return YES;
    return NO;
}

static void RMDumpClass(NSMutableString *out, Class c) {
    const char *name = class_getName(c);
    Class sup = class_getSuperclass(c);
    [out appendFormat:@"\n@interface %s : %s\n", name, sup ? class_getName(sup) : "nil"];
    unsigned int n = 0;
    Ivar *ivars = class_copyIvarList(c, &n);
    for (unsigned int i = 0; i < n; i++) {
        const char *iv = ivar_getName(ivars[i]);
        const char *te = ivar_getTypeEncoding(ivars[i]);
        [out appendFormat:@"  ivar %s  %s\n", iv ?: "?", te ?: "?"];
    }
    if (ivars) free(ivars);
    Method *cm = class_copyMethodList(object_getClass(c), &n);
    for (unsigned int i = 0; i < n; i++) {
        [out appendFormat:@"  + %s  %s\n", sel_getName(method_getName(cm[i])), method_getTypeEncoding(cm[i]) ?: ""];
    }
    if (cm) free(cm);
    Method *im = class_copyMethodList(c, &n);
    for (unsigned int i = 0; i < n; i++) {
        [out appendFormat:@"  - %s  %s\n", sel_getName(method_getName(im[i])), method_getTypeEncoding(im[i]) ?: ""];
    }
    if (im) free(im);
}

static BOOL RMInherits(Class c, const char *ancestor) {
    for (Class s = class_getSuperclass(c); s; s = class_getSuperclass(s)) {
        if (strcmp(class_getName(s), ancestor) == 0) return YES;
    }
    return NO;
}

static void RMWriteMethodDump(void) {
    @try {
        int total = objc_getClassList(NULL, 0);
        Class *all = (Class *)malloc(sizeof(Class) * (size_t)(total + 16));
        if (!all) return;
        total = objc_getClassList(all, total);

        NSMutableDictionary *byName = [NSMutableDictionary dictionary];
        for (int i = 0; i < total; i++) {
            const char *n = class_getName(all[i]);
            if (n && RMWantDump(n)) [byName setObject:[NSValue valueWithPointer:(const void *)all[i]] forKey:[NSString stringWithUTF8String:n]];
        }
        NSArray *sorted = [[byName allKeys] sortedArrayUsingSelector:@selector(compare:)];

        NSMutableString *out = [NSMutableString stringWithCapacity:600000];
        NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
        [out appendFormat:@"ReMusic 0.1.2 method dump\napp %@ (%@)  iOS %@  %d classes loaded, %lu dumped\n",
         [info objectForKey:@"CFBundleShortVersionString"], [info objectForKey:@"CFBundleIdentifier"],
         [[NSProcessInfo processInfo] operatingSystemVersionString], total, (unsigned long)[sorted count]];

        // who inherits from the base service classes
        static const char *roots[] = {"YTBaseService", "YTBaseInnerTubeService", "YTBaseInnerTubeRequestService", "YTInnerTubeRequestor",
                                      "YTInnerTubeRequestState", NULL};
        for (int r = 0; roots[r]; r++) {
            NSMutableArray *subs = [NSMutableArray array];
            for (int i = 0; i < total; i++) {
                const char *n = class_getName(all[i]);
                if (n && RMInherits(all[i], roots[r])) [subs addObject:[NSString stringWithUTF8String:n]];
            }
            [subs sortUsingSelector:@selector(compare:)];
            [out appendFormat:@"\nSUBCLASSES of %s (%lu): %@\n", roots[r], (unsigned long)[subs count], [subs componentsJoinedByString:@" "]];
        }

        for (NSString *nm in sorted) {
            if ([out length] > 3500000) {
                [out appendString:@"\n-- dump cut off at 3.5 MB --\n"];
                break;
            }
            Class c = (Class)[[byName objectForKey:nm] pointerValue];
            RMDumpClass(out, c);
        }
        free(all);
        NSError *err = nil;
        [out writeToFile:RMPath(@"ReMusic-methods.txt") atomically:YES encoding:NSUTF8StringEncoding error:&err];
        RMDiagLog(@"method dump written: %lu classes, %lu chars, err=%@", (unsigned long)[sorted count], (unsigned long)[out length], err);
    } @catch (NSException *e) {
        RMDiagLog(@"method dump failed: %@", e);
    }
}

// ---------------------------------------------------------------------------------------------
// Fresh-install reset
//
// iOS keeps an app's keychain items when the app is deleted, so after reinstalling Music the old
// (now unusable) sign-in is still there while the app's own data is gone, and the app flashes sign-in
// errors forever. When Music's Documents folder has no ReMusic-session.marker (fresh install, or the
// manual file ReMusic-reset exists), the stored accounts are forgotten once so you can sign in cleanly.
// ---------------------------------------------------------------------------------------------

static BOOL gRMFresh = NO;
static id gRMService = nil;
static IMP rm_o_sso_init = NULL;
static BOOL gRMResetScheduled = NO;

static void RMRunReset(void) {
    id svc = gRMService;
    @try {
        if (!svc) {
            RMDiagLog(@"reset: SSOService was never created, nothing to do");
            return;
        }
        NSArray *ids = [svc respondsToSelector:@selector(allIdentities)] ? [svc performSelector:@selector(allIdentities)] : nil;
        RMDiagLog(@"reset: %lu stored account(s) found", (unsigned long)[ids count]);
        SEL f3 = NSSelectorFromString(@"forgetIdentity:revokeToken:callback:");
        SEL f2 = NSSelectorFromString(@"forgetIdentity:callback:");
        for (id ident in [NSArray arrayWithArray:ids]) {
            id cb = [[^(id a, id b) {
                RMDiagLog(@"reset: forget callback %@", a);
            } copy] autorelease];
            if ([svc respondsToSelector:f3]) {
                ((void (*)(id, SEL, id, BOOL, id))objc_msgSend)(svc, f3, ident, NO, cb);
                RMDiagLog(@"reset: forgot an account (forgetIdentity:revokeToken:callback:)");
            } else if ([svc respondsToSelector:f2]) {
                ((void (*)(id, SEL, id, id))objc_msgSend)(svc, f2, ident, cb);
                RMDiagLog(@"reset: forgot an account (forgetIdentity:callback:)");
            } else {
                RMDiagLog(@"reset: no forget method found");
            }
        }
        NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        NSUInteger nc = 0;
        for (NSHTTPCookie *c in [NSArray arrayWithArray:[cs cookies]]) {
            [cs deleteCookie:c];
            nc++;
        }
        RMDiagLog(@"reset: removed %lu cookies", (unsigned long)nc);
    } @catch (NSException *e) {
        RMDiagLog(@"reset: exception %@", e);
    }
    // check again a moment later, then write the marker so this only happens once
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        @try {
            id s2 = gRMService;
            NSArray *left = [s2 respondsToSelector:@selector(allIdentities)] ? [s2 performSelector:@selector(allIdentities)] : nil;
            RMDiagLog(@"reset: %lu account(s) left after reset", (unsigned long)[left count]);
        } @catch (NSException *e) {
        }
        [[NSFileManager defaultManager] removeItemAtPath:RMPath(@"ReMusic-reset") error:nil];
        [[NSFileManager defaultManager] createFileAtPath:RMPath(@"ReMusic-session.marker") contents:nil attributes:nil];
        RMDiagLog(@"reset: done, marker written. Sign in again now.");
    });
}

static id rm_sso_init(id self, SEL _cmd, id config) {
    id r = ((id (*)(id, SEL, id))rm_o_sso_init)(self, _cmd, config);
    if (r && gRMFresh && !gRMResetScheduled) {
        gRMResetScheduled = YES;
        gRMService = [r retain];
        RMDiagLog(@"reset: captured SSOService, resetting in 2s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            RMRunReset();
        });
    }
    return r;
}

static void RMInstallReset(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL haveMarker = [fm fileExistsAtPath:RMPath(@"ReMusic-session.marker")];
    BOOL manual = [fm fileExistsAtPath:RMPath(@"ReMusic-reset")];
    gRMFresh = !haveMarker || manual;
    RMDiagLog(@"reset: marker %@, manual flag %@ -> %@", haveMarker ? @"present" : @"missing", manual ? @"present" : @"no",
              gRMFresh ? @"will reset stored accounts" : @"leaving accounts alone");
    if (!gRMFresh) return;
    Class sso = NSClassFromString(@"SSOService");
    BOOL ok = RMReplace(sso, @selector(initWithConfiguration:), (IMP)rm_sso_init, &rm_o_sso_init);
    RMDiagLog(@"reset: hook SSOService initWithConfiguration: %d", ok);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (!gRMResetScheduled) RMDiagLog(@"reset: SSOService was not created within 12s, no reset done");
    });
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

__attribute__((constructor)) static void RMDiagInit(void) {
    @autoreleasepool {
        @try {
            pthread_key_create(&gRMBusyKey, NULL);
            RMSetupLog();
            NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
            RMDiagLog(@"ReMusic 0.1.2 diagnostics start. app %@ bundle %@", [info objectForKey:@"CFBundleShortVersionString"],
                      [info objectForKey:@"CFBundleIdentifier"]);
            static const char *key[] = {"YTInnerTubeRequestor", "YTMInnerTubeRequestor", "YTBaseInnerTubeService", "YTGRPCFetcherService",
                                        "YTGRPCFetcherTask", "GTMSessionFetcher", "Cronet", "GRPCCall2", "YTInnerTubeURLBuilderGRPC",
                                        "YTInnerTubeURLBuilderStubby", "GPBMessage", NULL};
            for (int i = 0; key[i]; i++) RMDiagLog(@"class %s: %@", key[i], objc_getClass(key[i]) ? @"present" : @"missing");
            RMHookNetwork();
            RMInstallReset();
            if (gRMFresh) {
                RMDiagLog(@"trace: skipped on this launch (first launch after a reinstall/reset). It starts on the next launch.");
            } else {
                RMInstallTracer();
            }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC), dispatch_get_global_queue(0, 0), ^{
                RMWriteMethodDump();
            });
        } @catch (NSException *e) {
        }
    }
}
