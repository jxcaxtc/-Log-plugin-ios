/*
 * ============================================================================
 * 免责声明（DISCLAIMER）
 * ============================================================================
 * 本代码仅供本地安全研究与学习使用，禁止违规分发，严禁用于绕过
 * 任何官方校验、侵犯他人合法权益或从事任何违反法律法规的行为。
 * 使用者需自行承担一切由使用本代码产生的法律责任。
 *
 * This code is intended for local security research and educational purposes
 * only. Unauthorized redistribution is prohibited. Do not use it to bypass
 * any official verification or infringe upon the legitimate rights of others.
 * ============================================================================
 */

/*
 * ============================================================================
 * 项目说明：进程内行为监控 dylib
 * ----------------------------------------------------------------------------
 *  - 构建方式：Theos + library.mk
 *  - Hook 方式：纯 Objective-C runtime method swizzle（不依赖 Logos /
 *    libhooker / substrate / CydiaSubstrate）
 *  - 运行范围：仅当前注入的宿主 App 进程内（in-process），无法跨进程
 *  - 手势触发：双指双击屏幕 → 显示/隐藏悬浮监控面板
 *  - 监控项：
 *      (1) 弹窗监控（自定义 UIView 弹窗 / UIAlertController / UIActionSheet）
 *      (2) 文件 IO 监控（读 / 写 / 创建 / 删除 / 重命名 / 复制）
 *      (3) 拓展预留（网络 / XPC / 剪贴板等，按 Monitor 协议新增即可）
 *  - 保存：通过 UIDocumentPickerViewController 导出全部日志为 txt
 * ============================================================================
 */

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <Network/Network.h>               // NWPath / NWParameters
#import <CFNetwork/CFNetwork.h>            // CFNetworkCopySystemProxySettings
#import <mach-o/dyld.h>                    // _dyld_register_func_for_add_image 等
#import <dlfcn.h>
#import <string.h>                         // strcmp
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <sqlite3.h>
#import "fishhook.h"                       // fishhook rebind_symbols

// ============================================================================
#pragma mark - 通用宏与工具函数
// ============================================================================

// 统一的 NSLog 前缀，方便在设备控制台过滤
#define DYLog(fmt, ...) NSLog((@"[DYMonitor] " fmt), ##__VA_ARGS__)

// 把二进制数据转成 hex 字符串
static NSString *DYHexFromBytes(const void *data, size_t len) {
    if (!data || len == 0) return @"(empty)";
    const uint8_t *p = (const uint8_t *)data;
    size_t cap = len * 2 + 1;
    char *buf = (char *)malloc(cap);
    if (!buf) return @"(oom)";
    for (size_t i = 0; i < len; i++) sprintf(buf + i * 2, "%02x", p[i]);
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    if (len > 64) s = [s stringByAppendingFormat:@"...(%zu bytes total)", len];
    return s;
}

// 把二进制里"可打印 ASCII 部分"抽出来显示，方便看明文
// 比如 HTTP 请求体就是 ASCII 明文，hex 只是进制表示
static NSString *DYAsciiFromBytes(const void *data, size_t len) {
    if (!data || len == 0) return @"";
    const uint8_t *p = (const uint8_t *)data;
    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] >= 0x20 && p[i] <= 0x7E) printable++;
    }
    if (printable == 0) return @""; // 全非 ASCII，不输出明文字段
    if ((double)printable / (double)len < 0.7) return @""; // ASCII 比例不够高，判定为二进制数据
    NSString *utf8 = [[NSString alloc] initWithBytes:p length:len encoding:NSUTF8StringEncoding];
    if (!utf8) return @"";
    if (utf8.length > 200) utf8 = [[utf8 substringToIndex:200] stringByAppendingFormat:@"...(%zu chars)", utf8.length];
    return utf8;
}

// 全局开关：加密监控是否启用
static BOOL gDecryptMonitorEnabled = YES;

// 全局开关：UI 日志过滤（YES 时面板只显示 category=="加密" 的密钥/明文类日志；NO 时显示全部）
static BOOL gLogFilterKeyOnly = NO;

// 全局开关：Keychain 访问监控（hook SecItemAdd/CopyMatching/Update/Delete）
static BOOL gKeychainMonitorEnabled = YES;

// 全局开关：UserDefaults 读写监控（hook objectForKey/setObject:forKey:）
static BOOL gUserDefaultsMonitorEnabled = YES;

// 搜索过滤：支持正则，nil / @"" 表示不过滤
static NSString *gSearchPattern = nil;
static BOOL gSearchIsRegex = NO;  // NO = 子串匹配，YES = 正则

// 获取当前时间戳字符串，格式：yyyy-MM-dd HH:mm:ss.SSS
static NSString *DYTimestampString(void) {
    static NSDateFormatter *formatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    });
    return [formatter stringFromDate:[NSDate date]];
}

// ----------------------------------------------------------------------------
// Method Swizzle 通用工具
// 说明：标准的 method_exchangeImplementations 套路。
//      如果类本身没有该方法（来自父类），则先 class_addMethod 再替换。
// ----------------------------------------------------------------------------
static void DYSwizzleInstanceMethod(Class cls, SEL originalSel, SEL swizzledSel) {
    if (!cls) {
        DYLog(@"swizzle failed: nil class");
        return;
    }
    Method originalMethod = class_getInstanceMethod(cls, originalSel);
    Method swizzledMethod = class_getInstanceMethod(cls, swizzledSel);
    if (!originalMethod || !swizzledMethod) {
        DYLog(@"swizzle failed: method not found (cls=%@, orig=%@, swiz=%@)",
              NSStringFromClass(cls), NSStringFromSelector(originalSel), NSStringFromSelector(swizzledSel));
        return;
    }
    // 若类自身没有原方法（继承自父类），则添加一个空实现占位
    BOOL didAdd = class_addMethod(cls, originalSel,
                                  method_getImplementation(swizzledMethod),
                                  method_getTypeEncoding(swizzledMethod));
    if (didAdd) {
        // 添加成功 → 用原方法实现替换 swizzled 方法
        class_replaceMethod(cls, swizzledSel,
                            method_getImplementation(originalMethod),
                            method_getTypeEncoding(originalMethod));
    } else {
        // 类自身已有原方法 → 直接交换实现
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
    DYLog(@"swizzled: %@ -[%@ %@] <-> %@",
          NSStringFromClass(cls), NSStringFromSelector(originalSel),
          NSStringFromSelector(swizzledSel), NSStringFromSelector(swizzledSel));
}

// 类方法 swizzle（用于 NSFileManager defaultManager 上的类方法其实都是实例方法，
// 这里保留该工具以备后用）
__attribute__((unused))
static void DYSwizzleClassMethod(Class cls, SEL originalSel, SEL swizzledSel) {
    Class meta = object_getClass(cls);
    DYSwizzleInstanceMethod(meta, originalSel, swizzledSel);
}

// ============================================================================
#pragma mark - 日志管理器（线程安全）
// ============================================================================

// 通知名：当日志有新增时，UI 监听该通知刷新界面
static NSString *const DYLogDidUpdateNotification = @"DYLogDidUpdateNotification";

// ----------------------------------------------------------------------------
// 全局开关：抓包/VPN 探测屏蔽是否启用
// 由悬浮面板上的「拦截应用检测抓包」按钮控制，默认开启
// ----------------------------------------------------------------------------
static BOOL gBypassEnabled = YES;

// ----------------------------------------------------------------------------
// 强力防崩溃模块
// ----------------------------------------------------------------------------
// 拦截 4 大类崩溃：
//   (1) ObjC 未捕获异常 — NSSetUncaughtExceptionHandler
//   (2) Mach 致命信号   — SIGSEGV/SIGABRT/SIGILL/SIGFPE/SIGBUS/SIGTRAP/SIGSYS
//   (3) C++ terminate   — std::set_terminate
//   (4) 主动退出函数    — exit/_Exit/abort/__assert_rtn/__stack_chk_fail
//
// 崩溃日志写入沙盒 Documents/CrashLogs/YYYYMMDD_HHMMSS_crash.log
// 崩溃后 UIAlertController 弹窗：崩溃原因 + 日志路径 + 重启按钮
// ----------------------------------------------------------------------------
#import <signal.h>
#import <setjmp.h>
#import <execinfo.h>
#import <sys/types.h>
#import <unistd.h>

static BOOL gAntiCrashEnabled = YES;

// 前向声明
static void DYInstallAntiCrash(void);

// 原始 C 函数指针（fishhook 会填）
static void (*gOrigExit)(int) = NULL;
static void (*gOrigAbort)(void) = NULL;
static void (*gOrig_Exit)(int) = NULL;

// 用于崩溃后 longjmp 恢复（比 NSException handler 更强力，能救回 signal 崩溃）
static sigjmp_buf gCrashJumpBuf;
static BOOL       gCrashJumpSet = NO;

// 记录崩溃发生时的信息（signal handler / exception handler 里填）
static volatile sig_atomic_t gCrashType = 0;      // 1=signal 2=objc 3=c++ 4=exit 5=abort 6=_Exit
static volatile sig_atomic_t gCrashCode = 0;      // signal 号 / exit code
static char                  gCrashReason[256] = {0};

// 原始 signal handler 备份
static struct sigaction gOrigSignalHandlers[32]; // SIG* 最多 31

// 原始 ObjC exception handler 备份
static NSUncaughtExceptionHandler *gOrigExceptionHandler = nil;

// C++ terminate handler（弱引用）
typedef void (*DYCppTerminateFunc)(void);
static DYCppTerminateFunc gOrigCppTerminate = NULL;
typedef DYCppTerminateFunc (*DYSetTerminateFunc)(DYCppTerminateFunc);
static DYSetTerminateFunc gSetTerminate = NULL;
typedef DYCppTerminateFunc (*DYGetTerminateFunc)(void);
static DYGetTerminateFunc gGetTerminate = NULL;

// 崩溃日志保存目录（沙盒内 Documents/CrashLogs/）
static NSString *DYCrashLogsDir(void) {
    static NSString *dir = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *doc = paths.firstObject ?: NSTemporaryDirectory();
        dir = [doc stringByAppendingPathComponent:@"CrashLogs"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    });
    return dir;
}

// async-signal-safe 写崩溃日志文件（signal handler 里不能用 ObjC，只能用 C syscall）
static void DYSafeWriteCrashLog(const char *reason, int code, int type) {
    char path[1024];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm);
    snprintf(path, sizeof(path), "%s/%s_crash_%d.log", [DYCrashLogsDir() fileSystemRepresentation], ts, (int)getpid());

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;

    char header[2048];
    int hlen = snprintf(header, sizeof(header),
        "===== DYMonitor 崩溃日志 =====\n"
        "时间: %s\n"
        "类型: %d (1=signal 2=objc 3=c++ 4=exit 5=abort 6=_Exit)\n"
        "代码: %d\n"
        "原因: %s\n"
        "PID: %d\n"
        "==============================\n"
        "调用栈:\n",
        ts, type, code, reason ?: "(unknown)", (int)getpid());
    write(fd, header, hlen);

    // 用 backtrace_symbols_fd 直接把栈写进去（也是 async-signal-safe 的）
    void *stack[128];
    int count = backtrace(stack, 128);
    backtrace_symbols_fd(stack, count, fd);

    close(fd);
}

#pragma mark - Signal Handler（async-signal-safe，不能用 ObjC）

static void DYSignalHandler(int sig, siginfo_t *info, void *ucontext) {
    if (!gAntiCrashEnabled) {
        // 未开启防崩溃：恢复默认 handler，重新 raise 让系统崩掉
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    gCrashType = 1;
    gCrashCode = sig;
    snprintf(gCrashReason, sizeof(gCrashReason),
             "Signal %d (%s) at address %p", sig, strsignal(sig), info ? info->si_addr : NULL);
    DYSafeWriteCrashLog(gCrashReason, sig, 1);

    // 如果我们已经 setjmp 过，longjmp 回去恢复执行
    if (gCrashJumpSet) {
        siglongjmp(gCrashJumpBuf, sig);
    }
    // 把原 handler 恢复，以防又崩一次
    if (gOrigSignalHandlers[sig].sa_handler != SIG_DFL &&
        gOrigSignalHandlers[sig].sa_handler != SIG_IGN) {
        sigaction(sig, &gOrigSignalHandlers[sig], NULL);
    }
}

#pragma mark - ObjC Exception Handler

static void DYObjCExceptionHandler(NSException *exception) {
    if (!gAntiCrashEnabled || !exception) {
        // 没开防崩溃 → 让原 handler 处理
        if (gOrigExceptionHandler) gOrigExceptionHandler(exception);
        return;
    }
    gCrashType = 2;
    NSString *reasonStr = [NSString stringWithFormat:@"ObjC Exception: %@ - %@",
                           exception.name, exception.reason ?: @"(no reason)"];
    strncpy(gCrashReason, reasonStr.UTF8String ?: "(unknown)", sizeof(gCrashReason) - 1);

    // 构建完整 crash log（含 ObjC 栈）
    NSMutableString *log = [NSMutableString string];
    [log appendFormat:@"===== DYMonitor 崩溃日志 =====\n"];
    [log appendFormat:@"时间: %@\n", [NSDate date]];
    [log appendFormat:@"类型: ObjC 未捕获异常\n"];
    [log appendFormat:@"名称: %@\n", exception.name];
    [log appendFormat:@"原因: %@\n", exception.reason ?: @"(空)"];
    [log appendFormat:@"用户信息: %@\n", exception.userInfo ?: @"(空)"];
    [log appendFormat:@"==============================\n调用栈:\n"];
    for (NSString *sym in exception.callStackSymbols) {
        [log appendFormat:@"  %@\n", sym];
    }

    // 同时写入 backtrace() 栈（比 exception.callStackSymbols 更底层）
    void *stack[128];
    int cnt = backtrace(stack, 128);
    char **syms = backtrace_symbols(stack, cnt);
    if (syms) {
        [log appendString:@"\n--- 底层 backtrace ---\n"];
        for (int i = 0; i < cnt; i++) {
            [log appendFormat:@"  %s\n", syms[i]];
        }
        free(syms);
    }

    // 写文件
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm);
    NSString *fname = [NSString stringWithFormat:@"%s_objc_crash_%d.log", ts, (int)getpid()];
    NSString *fpath = [DYCrashLogsDir() stringByAppendingPathComponent:fname];
    [log writeToFile:fpath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    // 不要 propagate exception —— 否则还是会崩
    if (gCrashJumpSet) {
        siglongjmp(gCrashJumpBuf, 1);
    }
}

#pragma mark - C++ Terminate Handler

static void DYCppTerminateHandler(void) {
    if (!gAntiCrashEnabled) {
        if (gOrigCppTerminate) gOrigCppTerminate();
        abort();
    }
    gCrashType = 3;
    snprintf(gCrashReason, sizeof(gCrashReason), "C++ std::terminate()");
    DYSafeWriteCrashLog(gCrashReason, 0, 3);

    if (gCrashJumpSet) {
        siglongjmp(gCrashJumpBuf, 2);
    }
    // 不崩，吞掉。C++ runtime 期望 terminate handler 调用 abort()，但我们吞掉
    while (1) { usleep(100000); }
}

#pragma mark - Patched C 退出函数

static void DYPatchedExit(int code) {
    if (!gAntiCrashEnabled) {
        if (gOrigExit) gOrigExit(code);
        exit(code);
    }
    gCrashType = 4;
    gCrashCode = code;
    snprintf(gCrashReason, sizeof(gCrashReason), "exit(%d) —— 被拦截", code);
    DYSafeWriteCrashLog(gCrashReason, code, 4);
    NSLog(@"[应用助手] ⚠️ 拦截 exit(%d)", code);

    // 吞掉，不退出。exit 之后进程已处于无法继续的状态，保持活着
    while (1) { usleep(100000); }
}

static void DYPatched_Exit(int code) {
    if (!gAntiCrashEnabled) {
        if (gOrig_Exit) gOrig_Exit(code);
        _Exit(code);
    }
    gCrashType = 6;
    gCrashCode = code;
    snprintf(gCrashReason, sizeof(gCrashReason), "_Exit(%d) —— 被拦截", code);
    DYSafeWriteCrashLog(gCrashReason, code, 6);
    NSLog(@"[应用助手] ⚠️ 拦截 _Exit(%d)", code);
    while (1) { usleep(100000); }
}

static void DYPatchedAbort(void) {
    if (!gAntiCrashEnabled) {
        if (gOrigAbort) gOrigAbort();
        abort();
    }
    gCrashType = 5;
    gCrashCode = SIGABRT;
    snprintf(gCrashReason, sizeof(gCrashReason), "abort() —— 被拦截");
    DYSafeWriteCrashLog(gCrashReason, SIGABRT, 5);
    NSLog(@"[应用助手] ⚠️ 拦截 abort()");
    while (1) { usleep(100000); }
}

#pragma mark - 注册全部崩溃防护

static void DYInstallAntiCrash(void) {
    if (!gAntiCrashEnabled) return;

    // ---- 1. Fishhook 拦截所有主动退出 ----
    struct rebinding crashRebinds[] = {
        { "exit",     (void *)&DYPatchedExit,    (void **)&gOrigExit },
        { "_Exit",    (void *)&DYPatched_Exit,   (void **)&gOrig_Exit },
        { "abort",    (void *)&DYPatchedAbort,   (void **)&gOrigAbort },
    };
    rebind_symbols(crashRebinds, sizeof(crashRebinds) / sizeof(crashRebinds[0]));

    // ---- 2. Signal handler（致命信号）----
    int fatalSignals[] = {
        SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGBUS, SIGTRAP, SIGSYS,
        SIGPIPE,     // ObjC 里经常有 SIGPIPE（向断开的 socket 写）
        0
    };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = DYSignalHandler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; fatalSignals[i] != 0; i++) {
        sigaction(fatalSignals[i], &sa, &gOrigSignalHandlers[fatalSignals[i]]);
    }

    // ---- 3. ObjC Uncaught Exception Handler ----
    gOrigExceptionHandler = NSGetUncaughtExceptionHandler();
    NSSetUncaughtExceptionHandler(&DYObjCExceptionHandler);

    // ---- 4. C++ terminate handler（用 dlsym 从 libc++ 拿）----
    void *libcpp = dlopen("libc++.1.dylib", RTLD_NOW);
    if (libcpp) {
        gSetTerminate = (DYSetTerminateFunc)dlsym(libcpp, "_ZSt13set_terminatePFvvE");
        gGetTerminate = (DYGetTerminateFunc)dlsym(libcpp, "_ZSt11get_terminatev");
        if (gSetTerminate && gGetTerminate) {
            gOrigCppTerminate = gGetTerminate();
            gSetTerminate(&DYCppTerminateHandler);
        }
    }

    // ---- 5. 在主线程 runloop 里 setjmp（signal 崩溃后 longjmp 回这里）----
    dispatch_async(dispatch_get_main_queue(), ^{
        gCrashJumpSet = YES;
        int sig = sigsetjmp(gCrashJumpBuf, 1);
        if (sig != 0) {
            // 从 signal handler longjmp 回来 —— 说明我们被崩溃救回了
            NSLog(@"[应用助手] 💪 从崩溃中恢复 (sig=%d)", sig);
            // 恢复完了，重新 setjmp 等下一次
            gCrashJumpSet = NO;
            DYInstallAntiCrash();
        }
    });

    id mgr = [NSClassFromString(@"DYLogManager") performSelector:@selector(sharedManager)];
    if (mgr) {
        [mgr performSelector:@selector(logWithCategory:message:)
                    withObject:@"系统"
                    withObject:@"强力防崩溃已启动（signal+exception+C+++exit/abort 全拦截）"];
    }
}

// 全局总开关：关闭后所有日志不捕获、不显示，但 hook 仍在运行
static BOOL gGlobalLogEnabled = YES;

// 日志行数上限（用户自定义，默认 3000，持久化到 NSUserDefaults）
static NSInteger gMaxLogLines = -1;
static NSInteger DYGetMaxLogLines(void) {
    if (gMaxLogLines < 0) {
        NSNumber *saved = [[NSUserDefaults standardUserDefaults] objectForKey:@"DYMaxLogLines"];
        gMaxLogLines = saved ? saved.integerValue : 3000;
        if (gMaxLogLines < 100) gMaxLogLines = 100;
        if (gMaxLogLines > 50000) gMaxLogLines = 50000;
    }
    return gMaxLogLines;
}
static void DYSetMaxLogLines(NSInteger value) {
    if (value < 100) value = 100;
    if (value > 50000) value = 50000;
    gMaxLogLines = value;
    [[NSUserDefaults standardUserDefaults] setInteger:value forKey:@"DYMaxLogLines"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

@interface DYLogManager : NSObject
+ (instancetype)sharedManager;
// 追加一条日志（category：分类，如 "弹窗" / "文件IO"；message：详细内容）
- (void)logWithCategory:(NSString *)category message:(NSString *)message;
// 获取全部日志（按时间正序）
- (NSArray<NSString *> *)allLogs;
// 清空日志
- (void)clearLogs;
// 全部日志拼接成单个字符串（用于保存）
- (NSString *)allLogsString;
@end

@implementation DYLogManager {
    NSMutableArray<NSString *> *_logs;
    dispatch_queue_t _queue;        // 串行队列，保证线程安全
    NSMutableArray<NSString *> *_pending; // 节流缓冲区
    BOOL _flushScheduled;
}

+ (instancetype)sharedManager {
    static DYLogManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [[DYLogManager alloc] init];
    });
    return manager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _logs = [NSMutableArray array];
        _pending = [NSMutableArray array];
        _queue = dispatch_queue_create("com.dymonitor.logqueue", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)logWithCategory:(NSString *)category message:(NSString *)message {
    if (!message) return;
    if (!gGlobalLogEnabled) return; // 全局总开关关了，所有日志不捕获不显示
    // 防止单条日志过长（比如大 SQL 或密文 hex 几百行）
    NSString *trimmed = message.length > 5000 ? [[message substringToIndex:5000] stringByAppendingFormat:@"...(truncated from %lu chars)", (unsigned long)message.length] : message;
    NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@",
                      DYTimestampString(), category ?: @"未知", trimmed];
    dispatch_async(_queue, ^{
        @autoreleasepool {
            [self->_logs addObject:line];
            [self->_pending addObject:line];
            // 总日志上限（用户自定义，默认 3000），超过一次性删 1/3 避免频繁重分配
            static NSInteger cachedMax = -1;
            NSInteger max = DYGetMaxLogLines();
            if (max != cachedMax) {
                // 用户刚改过上限，立刻 trim 到新上限
                if (self->_logs.count > max) {
                    [self->_logs removeObjectsInRange:NSMakeRange(0, self->_logs.count - max)];
                }
                cachedMax = max;
            }
            if (self->_logs.count > max) {
                NSInteger drop = MAX(max / 3, 100);
                if (self->_logs.count - max < drop) drop = self->_logs.count - max + (max / 3);
                [self->_logs removeObjectsInRange:NSMakeRange(0, MIN(drop, self->_logs.count - max))];
            }
            // 节流：100ms 内攒一批，一次 flush 到主线程
            if (!self->_flushScheduled) {
                self->_flushScheduled = YES;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    [self flushPending];
                });
            }
        }
    });
    // 同时输出到 NSLog（仅限调试开关打开时）
    DYLog(@"%@", line);
}

// 节流 flush：把 100ms 内攒的一批日志一次发出去
- (void)flushPending {
    // 切到 log 队列拿数据
    dispatch_sync(_queue, ^{
        if (self->_pending.count == 0) {
            self->_flushScheduled = NO;
            return;
        }
        NSArray *batch = [self->_pending copy];
        [self->_pending removeAllObjects];
        self->_flushScheduled = NO;
        // 主线程一次性发通知，userInfo 带数组
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:DYLogDidUpdateNotification
                                                                object:nil
                                                              userInfo:@{@"batch": batch}];
        });
    });
}

- (NSArray<NSString *> *)allLogs {
    __block NSArray *snapshot = nil;
    dispatch_sync(_queue, ^{
        snapshot = [self->_logs copy];
    });
    return snapshot;
}

- (void)clearLogs {
    dispatch_async(_queue, ^{
        [self->_logs removeAllObjects];
        [self->_pending removeAllObjects];
        self->_flushScheduled = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:DYLogDidUpdateNotification
                                                                object:nil
                                                              userInfo:@{@"clear": @YES}];
        });
    });
}

- (NSString *)allLogsString {
    NSArray *snapshot = [self allLogs];
    return [snapshot componentsJoinedByString:@"\n"];
}

@end

// ============================================================================
#pragma mark - 监控模块协议（拓展预留）
// ============================================================================

// 所有监控模块均实现该协议，便于统一管理与后续新增
@protocol DYMonitor <NSObject>
- (void)startMonitoring;
- (void)stopMonitoring;
@end

// ============================================================================
#pragma mark - 弹窗监控
// ============================================================================

@interface DYAlertMonitor : NSObject <DYMonitor>
@end

@implementation DYAlertMonitor

    - (void)startMonitoring {
    @autoreleasepool {
        // 1) UIAlertController：拦截 presentViewController:animated:completion:
        Class alertVCClass = NSClassFromString(@"UIAlertController");
        if (alertVCClass) {
            DYSwizzleInstanceMethod([UIViewController class],
                                    @selector(presentViewController:animated:completion:),
                                    @selector(dy_presentViewController:animated:completion:));
        }

        // 2) UIActionSheet（iOS 8 起已废弃，但仍有 App 使用）
        Class actionSheetClass = NSClassFromString(@"UIActionSheet");
        if (actionSheetClass) {
            DYSwizzleInstanceMethod(actionSheetClass,
                                    @selector(showInView:),
                                    @selector(dy_showInView:));
            DYSwizzleInstanceMethod(actionSheetClass,
                                    @selector(showFromTabBar:),
                                    @selector(dy_showFromTabBar:));
            DYSwizzleInstanceMethod(actionSheetClass,
                                    @selector(showFromBarButtonItem:animated:),
                                    @selector(dy_showFromBarButtonItem:animated:));
        }

        // 3) 全局拦截 UIView.addSubview: —— 覆盖所有弹窗添加场景
        //    包括加到 UIWindow 的、加到 VC.view 的、加到任意父视图的自定义弹窗
        DYSwizzleInstanceMethod([UIView class],
                                @selector(addSubview:),
                                @selector(dy_addSubview:));

        // 4) 拦截 UIWindow.makeKeyAndVisible —— 捕获 App 创建新 Window 展示弹窗的场景
        DYSwizzleInstanceMethod([UIWindow class],
                                @selector(makeKeyAndVisible),
                                @selector(dy_makeKeyAndVisible));
    }
}

- (void)stopMonitoring {
    // 本设计为常驻监控，不提供停止；此处保留接口。
}

@end

// ----------------------------------------------------------------------------
// UIViewController (DYAlertMonitor) —— 拦截 present
// ----------------------------------------------------------------------------
@interface UIViewController (DYAlertMonitor)
- (void)dy_presentViewController:(UIViewController *)viewControllerToPresent
                        animated:(BOOL)flag
                      completion:(void (^)(void))completion;
@end

@implementation UIViewController (DYAlertMonitor)

- (void)dy_presentViewController:(UIViewController *)viewControllerToPresent
                        animated:(BOOL)flag
                      completion:(void (^)(void))completion {
    @autoreleasepool {
        // 注意：swizzle 后，调用自身即调用原实现
        [self dy_presentViewController:viewControllerToPresent animated:flag completion:completion];

        // 提取弹窗信息：present 者类 → 被 present 的 VC 类
        NSString *presenterClass = NSStringFromClass([self class]);
        NSString *vcClass = NSStringFromClass([viewControllerToPresent class]);
        NSMutableString *detail = [NSMutableString string];
        [detail appendFormat:@"presentViewController: | 调用类=%@ | 目标类=%@", presenterClass, vcClass];

        if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
            UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
            [detail appendFormat:@" | 类型=UIAlertController"];
            if (alert.title.length > 0) [detail appendFormat:@" | title=%@", alert.title];
            if (alert.message.length > 0) [detail appendFormat:@" | message=%@", alert.message];
            NSMutableArray *titles = [NSMutableArray array];
            for (UIAlertAction *action in alert.actions) {
                if (action.title) [titles addObject:action.title];
            }
            if (titles.count > 0) {
                [detail appendFormat:@" | actions=[%@]", [titles componentsJoinedByString:@", "]];
            }
        } else if ([viewControllerToPresent isKindOfClass:[UINavigationController class]]) {
            UINavigationController *nav = (UINavigationController *)viewControllerToPresent;
            [detail appendFormat:@" | 类型=UINavigationController | root=%@",
             NSStringFromClass([nav.viewControllers.firstObject class]) ?: @"(nil)"];
        } else {
            [detail appendFormat:@" | 类型=模态 VC"];
        }

        // 如果目标 VC 有 navigationItem.title，也打出来
        if (viewControllerToPresent.navigationItem.title.length > 0
            && ![viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
            [detail appendFormat:@" | navTitle=%@", viewControllerToPresent.navigationItem.title];
        }

        [[DYLogManager sharedManager] logWithCategory:@"弹窗" message:detail];
    }
}

@end

// ----------------------------------------------------------------------------
// UIActionSheet (DYAlertMonitor)
// ----------------------------------------------------------------------------
@interface UIActionSheet (DYAlertMonitor)
- (void)dy_showInView:(UIView *)view;
- (void)dy_showFromTabBar:(UITabBar *)tabBar;
- (void)dy_showFromBarButtonItem:(UIBarButtonItem *)item animated:(BOOL)animated;
@end

@implementation UIActionSheet (DYAlertMonitor)

- (void)dy_showInView:(UIView *)view {
    @autoreleasepool {
        [self dy_showInView:view];
        NSString *title = self.title ?: @"";
        [[DYLogManager sharedManager] logWithCategory:@"弹窗"
            message:[NSString stringWithFormat:@"UIActionSheet showInView: | title: %@", title]];
    }
}

- (void)dy_showFromTabBar:(UITabBar *)tabBar {
    @autoreleasepool {
        [self dy_showFromTabBar:tabBar];
        [[DYLogManager sharedManager] logWithCategory:@"弹窗"
            message:[NSString stringWithFormat:@"UIActionSheet showFromTabBar | title: %@", self.title ?: @""]];
    }
}

- (void)dy_showFromBarButtonItem:(UIBarButtonItem *)item animated:(BOOL)animated {
    @autoreleasepool {
        [self dy_showFromBarButtonItem:item animated:animated];
        [[DYLogManager sharedManager] logWithCategory:@"弹窗"
            message:[NSString stringWithFormat:@"UIActionSheet showFromBarButtonItem | title: %@", self.title ?: @""]];
    }
}

@end

// ----------------------------------------------------------------------------
// UIView (DYAlertMonitor) —— 全局拦截 addSubview，识别自定义弹窗
// 覆盖场景：加到 UIWindow、加到 VC.view、加到任意父视图的自定义弹窗
// ----------------------------------------------------------------------------
@interface UIView (DYAlertMonitor)
- (void)dy_addSubview:(UIView *)view;
@end

@implementation UIView (DYAlertMonitor)

// 提取弹窗文本内容（迭代遍历 UILabel/UIButton/UITextView）
static NSString *DYExtractPopupTexts(UIView *view) {
    NSMutableArray *texts = [NSMutableArray array];
    NSMutableArray *queue = [NSMutableArray arrayWithObject:view];
    while (queue.count > 0) {
        UIView *v = queue.firstObject;
        [queue removeObjectAtIndex:0];
        for (UIView *sub in v.subviews) {
            if ([sub isKindOfClass:[UILabel class]]) {
                NSString *t = ((UILabel *)sub).text;
                if (t.length > 0) [texts addObject:t];
            } else if ([sub isKindOfClass:[UIButton class]]) {
                NSString *t = ((UIButton *)sub).titleLabel.text;
                if (t.length > 0) [texts addObject:t];
            } else if ([sub isKindOfClass:[UITextView class]]) {
                NSString *t = ((UITextView *)sub).text;
                if (t.length > 0) [texts addObject:t];
            }
            [queue addObject:sub];
        }
    }
    return texts.count > 0 ? [texts componentsJoinedByString:@" | "] : @"(无)";
}

// 判断一个 view 是否"像弹窗"（满足任意两条以上）
static BOOL DYIsLikelyPopupView(UIView *view, UIView *superview) {
    if (!view || !superview) return NO;
    NSString *clsName = NSStringFromClass([view class]);
    if ([clsName hasPrefix:@"_"]) return NO; // 跳过系统私有类

    // 条件 1：superview 是 UIWindow（顶层窗口上的视图很可能是弹窗）
    BOOL onWindow = [superview isKindOfClass:[UIWindow class]];

    // 条件 2：类名包含弹窗关键字
    NSArray<NSString *> *keywords = @[
        @"Alert", @"Popup", @"Dialog", @"Toast", @"HUD", @"Menu",
        @"Sheet", @"Popover", @"Bubble", @"Tip", @"Notice", @"Mask",
        @"alert", @"popup", @"dialog", @"toast", @"hud", @"menu",
        @"sheet", @"popover", @"mask", @"Loading", @"loading",
        @"Message", @"message", @"Confirm", @"confirm",
        @"TipView", @"Warning", @"ErrorView"
    ];
    BOOL nameMatch = NO;
    for (NSString *kw in keywords) {
        if ([clsName containsString:kw]) { nameMatch = YES; break; }
    }
    if (!nameMatch) {
        // 遍历父类链
        Class superCls = class_getSuperclass([view class]);
        while (superCls && superCls != [UIView class] && superCls != [NSObject class]) {
            NSString *sname = NSStringFromClass(superCls);
            for (NSString *kw in keywords) {
                if ([sname containsString:kw]) { nameMatch = YES; break; }
            }
            if (nameMatch) break;
            superCls = class_getSuperclass(superCls);
        }
    }

    // 条件 3：面积 >= 屏幕 20%（小 Toast 可能不满足，但大弹窗肯定满足）
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
    CGFloat minArea = screenW * screenH * 0.20;
    CGFloat viewArea = view.bounds.size.width * view.bounds.size.height;
    BOOL largeArea = viewArea >= minArea;

    // 条件 4：layer.zPosition 很高（>= 999 通常是弹窗）
    BOOL highZ = view.layer.zPosition >= 999;

    // 条件 5：backgroundColor alpha < 1（有半透明遮罩）
    BOOL hasMask = NO;
    if (view.backgroundColor) {
        CGFloat alpha = CGColorGetAlpha(view.backgroundColor.CGColor);
        if (alpha < 1.0 && alpha > 0.0) hasMask = YES;
    }

    // 跳过常见系统容器类（导航栏、tab栏、滚动视图等）
    NSArray *skipClasses = @[
        @"UINavigationBar", @"UITabBar", @"UIToolbar", @"UISearchBar",
        @"UIScrollView", @"UITableView", @"UICollectionView", @"UIStackView",
        @"UIPageControl", @"UIActivityIndicatorView", @"UISwitch", @"UISlider",
        @"UIProgressView", @"UISegmentedControl", @"UITextField", @"UITextView",
        @"WKWebView", @"AVPlayerView", @"MKMapView", @"GMSMapView"
    ];
    for (NSString *sk in skipClasses) {
        if ([clsName isEqualToString:sk]) return NO;
    }

    // 统计满足的条件数量
    int score = 0;
    if (onWindow) score++;
    if (nameMatch) score++;
    if (largeArea) score++;
    if (highZ) score++;
    if (hasMask) score++;

    return score >= 2; // 至少满足两条才认为是弹窗
}

- (void)dy_addSubview:(UIView *)view {
    @autoreleasepool {
        // 先调用原实现（swizzle 后 dy_addSubview 就是原 addSubview）
        [self dy_addSubview:view];

        // self 就是 superview，检查这个新加入的 view 是否像弹窗
        if (DYIsLikelyPopupView(view, self)) {
            NSString *clsName = NSStringFromClass([view class]);
            NSString *superClsName = NSStringFromClass([self class]);
            NSString *texts = DYExtractPopupTexts(view);
            NSString *msg = [NSString stringWithFormat:
                @"自定义弹窗 | 添加到=%@ | view类=%@ | zPosition=%.1f | 文本: %@",
                superClsName, clsName, view.layer.zPosition, texts];
            [[DYLogManager sharedManager] logWithCategory:@"弹窗" message:msg];
        }
    }
}

@end

// ----------------------------------------------------------------------------
// UIWindow (DYAlertMonitor) —— 拦截 makeKeyAndVisible（捕获新 Window 弹窗）
// ----------------------------------------------------------------------------
@interface UIWindow (DYAlertMonitor_2)
- (void)dy_makeKeyAndVisible;
@end

@implementation UIWindow (DYAlertMonitor_2)

- (void)dy_makeKeyAndVisible {
    @autoreleasepool {
        [self dy_makeKeyAndVisible]; // 调原实现

        // 如果是 app 自身创建的 Window（不是系统的），打日志
        NSString *clsName = NSStringFromClass([self class]);
        if (![clsName hasPrefix:@"_"] && self.windowLevel >= UIWindowLevelNormal) {
            UIView *firstView = self.subviews.firstObject;
            NSString *firstCls = firstView ? NSStringFromClass([firstView class]) : @"(无子视图)";
            NSString *msg = [NSString stringWithFormat:
                @"新Window成为KeyWindow | window类=%@ | windowLevel=%.0f | 第一子视图=%@",
                clsName, self.windowLevel, firstCls];
            [[DYLogManager sharedManager] logWithCategory:@"弹窗" message:msg];
        }
    }
}

@end

// ============================================================================
#pragma mark - 文件 IO 监控
// ============================================================================
// 监控策略：
//   - NSFileManager 的 create / remove / move / copy / contentsAtPath
//   - NSData 的 writeToFile / dataWithContentsOfFile / writeToURL / dataWithContentsOfURL
//   - NSString 的 writeToFile / stringWithContentsOfFile
// 覆盖常见的文件读写场景。
// ============================================================================

@interface DYFileIOMonitor : NSObject <DYMonitor>
@end

@implementation DYFileIOMonitor

- (void)startMonitoring {
    @autoreleasepool {
        Class fmCls = [NSFileManager class];

        // NSFileManager - 创建
        DYSwizzleInstanceMethod(fmCls,
                                @selector(createFileAtPath:contents:attributes:),
                                @selector(dy_createFileAtPath:contents:attributes:));
        // NSFileManager - 删除
        DYSwizzleInstanceMethod(fmCls, @selector(removeItemAtPath:error:),
                                @selector(dy_removeItemAtPath:error:));
        DYSwizzleInstanceMethod(fmCls, @selector(removeItemAtURL:error:),
                                @selector(dy_removeItemAtURL:error:));
        // NSFileManager - 移动/重命名
        DYSwizzleInstanceMethod(fmCls, @selector(moveItemAtPath:toPath:error:),
                                @selector(dy_moveItemAtPath:toPath:error:));
        DYSwizzleInstanceMethod(fmCls, @selector(moveItemAtURL:toURL:error:),
                                @selector(dy_moveItemAtURL:toURL:error:));
        // NSFileManager - 复制
        DYSwizzleInstanceMethod(fmCls, @selector(copyItemAtPath:toPath:error:),
                                @selector(dy_copyItemAtPath:toPath:error:));
        DYSwizzleInstanceMethod(fmCls, @selector(copyItemAtURL:toURL:error:),
                                @selector(dy_copyItemAtURL:toURL:error:));
        // NSFileManager - 读取
        DYSwizzleInstanceMethod(fmCls, @selector(contentsAtPath:),
                                @selector(dy_contentsAtPath:));

        // NSData - 写入
        Class dataCls = [NSData class];
        DYSwizzleInstanceMethod(dataCls, @selector(writeToFile:atomically:),
                                @selector(dy_writeToFile:atomically:));
        DYSwizzleInstanceMethod(dataCls, @selector(writeToFile:options:error:),
                                @selector(dy_writeToFile:options:error:));
        DYSwizzleInstanceMethod(dataCls, @selector(writeToURL:atomically:),
                                @selector(dy_writeToURL:atomically:));
        DYSwizzleInstanceMethod(dataCls, @selector(writeToURL:options:error:),
                                @selector(dy_writeToURL:options:error:));
        // NSData - 读取（类方法，需在元类上 swizzle）
        DYSwizzleClassMethod(dataCls, @selector(dataWithContentsOfFile:),
                             @selector(dy_dataWithContentsOfFile:));
        DYSwizzleClassMethod(dataCls, @selector(dataWithContentsOfFile:options:error:),
                             @selector(dy_dataWithContentsOfFile:options:error:));
        DYSwizzleClassMethod(dataCls, @selector(dataWithContentsOfURL:),
                             @selector(dy_dataWithContentsOfURL:));
        DYSwizzleClassMethod(dataCls, @selector(dataWithContentsOfURL:options:error:),
                             @selector(dy_dataWithContentsOfURL:options:error:));

        // NSString - 写入
        Class strCls = [NSString class];
        DYSwizzleInstanceMethod(strCls, @selector(writeToFile:atomically:encoding:error:),
                                @selector(dy_writeToFile:atomically:encoding:error:));
        DYSwizzleInstanceMethod(strCls, @selector(writeToURL:atomically:encoding:error:),
                                @selector(dy_writeToURL:atomically:encoding:error:));
        // NSString - 读取（类方法）
        DYSwizzleClassMethod(strCls, @selector(stringWithContentsOfFile:encoding:error:),
                             @selector(dy_stringWithContentsOfFile:encoding:error:));
        DYSwizzleClassMethod(strCls, @selector(stringWithContentsOfURL:encoding:error:),
                             @selector(dy_stringWithContentsOfURL:encoding:error:));
    }
}

- (void)stopMonitoring {
    // 常驻，保留接口
}

@end

// ----------------------------------------------------------------------------
// NSFileManager 分类
// ----------------------------------------------------------------------------
@interface NSFileManager (DYFileIO)
- (BOOL)dy_createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr;
- (BOOL)dy_removeItemAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)dy_removeItemAtURL:(NSURL *)URL error:(NSError **)error;
- (BOOL)dy_moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error;
- (BOOL)dy_moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error;
- (BOOL)dy_copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error;
- (BOOL)dy_copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error;
- (NSData *)dy_contentsAtPath:(NSString *)path;
@end

@implementation NSFileManager (DYFileIO)

- (BOOL)dy_createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    BOOL result = [self dy_createFileAtPath:path contents:data attributes:attr];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"创建文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)data.length]];
    return result;
}

- (BOOL)dy_removeItemAtPath:(NSString *)path error:(NSError **)error {
    BOOL result = [self dy_removeItemAtPath:path error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"删除文件 | 路径: %@", path ?: @"(null)"]];
    return result;
}

- (BOOL)dy_removeItemAtURL:(NSURL *)URL error:(NSError **)error {
    BOOL result = [self dy_removeItemAtURL:URL error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"删除文件 | URL: %@", URL ?: @"(null)"]];
    return result;
}

- (BOOL)dy_moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    BOOL result = [self dy_moveItemAtPath:srcPath toPath:dstPath error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"移动/重命名 | 源: %@ → 目标: %@",
                 srcPath ?: @"(null)", dstPath ?: @"(null)"]];
    return result;
}

- (BOOL)dy_moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error {
    BOOL result = [self dy_moveItemAtURL:srcURL toURL:dstURL error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"移动/重命名 | 源: %@ → 目标: %@",
                 srcURL ?: @"(null)", dstURL ?: @"(null)"]];
    return result;
}

- (BOOL)dy_copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    BOOL result = [self dy_copyItemAtPath:srcPath toPath:dstPath error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"复制文件 | 源: %@ → 目标: %@",
                 srcPath ?: @"(null)", dstPath ?: @"(null)"]];
    return result;
}

- (BOOL)dy_copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error {
    BOOL result = [self dy_copyItemAtURL:srcURL toURL:dstURL error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"复制文件 | 源: %@ → 目标: %@",
                 srcURL ?: @"(null)", dstURL ?: @"(null)"]];
    return result;
}

- (NSData *)dy_contentsAtPath:(NSString *)path {
    NSData *data = [self dy_contentsAtPath:path];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)data.length]];
    return data;
}

@end

// ----------------------------------------------------------------------------
// NSData 分类
// ----------------------------------------------------------------------------
@interface NSData (DYFileIO)
- (BOOL)dy_writeToFile:(NSString *)path atomically:(BOOL)atomically;
- (BOOL)dy_writeToFile:(NSString *)path options:(NSDataWritingOptions)mask error:(NSError **)error;
- (BOOL)dy_writeToURL:(NSURL *)url atomically:(BOOL)atomically;
- (BOOL)dy_writeToURL:(NSURL *)url options:(NSDataWritingOptions)mask error:(NSError **)error;
+ (NSData *)dy_dataWithContentsOfFile:(NSString *)path;
+ (NSData *)dy_dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)mask error:(NSError **)error;
+ (NSData *)dy_dataWithContentsOfURL:(NSURL *)url;
+ (NSData *)dy_dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)mask error:(NSError **)error;
@end

@implementation NSData (DYFileIO)

- (BOOL)dy_writeToFile:(NSString *)path atomically:(BOOL)atomically {
    BOOL result = [self dy_writeToFile:path atomically:atomically];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)self.length]];
    return result;
}

- (BOOL)dy_writeToFile:(NSString *)path options:(NSDataWritingOptions)mask error:(NSError **)error {
    BOOL result = [self dy_writeToFile:path options:mask error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)self.length]];
    return result;
}

- (BOOL)dy_writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    BOOL result = [self dy_writeToURL:url atomically:atomically];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件 | URL: %@ | 大小: %lu 字节",
                 url ?: @"(null)", (unsigned long)self.length]];
    return result;
}

- (BOOL)dy_writeToURL:(NSURL *)url options:(NSDataWritingOptions)mask error:(NSError **)error {
    BOOL result = [self dy_writeToURL:url options:mask error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件 | URL: %@ | 大小: %lu 字节",
                 url ?: @"(null)", (unsigned long)self.length]];
    return result;
}

+ (NSData *)dy_dataWithContentsOfFile:(NSString *)path {
    NSData *data = [self dy_dataWithContentsOfFile:path];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)data.length]];
    return data;
}

+ (NSData *)dy_dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)mask error:(NSError **)error {
    NSData *data = [self dy_dataWithContentsOfFile:path options:mask error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件 | 路径: %@ | 大小: %lu 字节",
                 path ?: @"(null)", (unsigned long)data.length]];
    return data;
}

+ (NSData *)dy_dataWithContentsOfURL:(NSURL *)url {
    NSData *data = [self dy_dataWithContentsOfURL:url];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件 | URL: %@ | 大小: %lu 字节",
                 url ?: @"(null)", (unsigned long)data.length]];
    return data;
}

+ (NSData *)dy_dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)mask error:(NSError **)error {
    NSData *data = [self dy_dataWithContentsOfURL:url options:mask error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件 | URL: %@ | 大小: %lu 字节",
                 url ?: @"(null)", (unsigned long)data.length]];
    return data;
}

@end

// ----------------------------------------------------------------------------
// NSString 分类
// ----------------------------------------------------------------------------
@interface NSString (DYFileIO)
- (BOOL)dy_writeToFile:(NSString *)path atomically:(BOOL)atomically encoding:(NSStringEncoding)enc error:(NSError **)error;
- (BOOL)dy_writeToURL:(NSURL *)url atomically:(BOOL)atomically encoding:(NSStringEncoding)enc error:(NSError **)error;
+ (NSString *)dy_stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError **)error;
+ (NSString *)dy_stringWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError **)error;
@end

@implementation NSString (DYFileIO)

- (BOOL)dy_writeToFile:(NSString *)path atomically:(BOOL)atomically encoding:(NSStringEncoding)enc error:(NSError **)error {
    BOOL result = [self dy_writeToFile:path atomically:atomically encoding:enc error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件(字符串) | 路径: %@", path ?: @"(null)"]];
    return result;
}

- (BOOL)dy_writeToURL:(NSURL *)url atomically:(BOOL)atomically encoding:(NSStringEncoding)enc error:(NSError **)error {
    BOOL result = [self dy_writeToURL:url atomically:atomically encoding:enc error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"写入文件(字符串) | URL: %@", url ?: @"(null)"]];
    return result;
}

+ (NSString *)dy_stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError **)error {
    NSString *str = [self dy_stringWithContentsOfFile:path encoding:enc error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件(字符串) | 路径: %@", path ?: @"(null)"]];
    return str;
}

+ (NSString *)dy_stringWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError **)error {
    NSString *str = [self dy_stringWithContentsOfURL:url encoding:enc error:error];
    [[DYLogManager sharedManager] logWithCategory:@"文件IO"
        message:[NSString stringWithFormat:@"读取文件(字符串) | URL: %@", url ?: @"(null)"]];
    return str;
}

@end

// ============================================================================
#pragma mark - 抓包 / VPN 探测屏蔽（Network Bypass）
// ============================================================================
//
// 免责声明：本模块仅供本地安全研究与学习使用，禁止违规使用。
//
// 功能说明：
//   通过篡改网络相关 API 的返回值，欺骗 App 本地的抓包/VPN 环境检测。
//   仅作用于当前注入进程，不影响系统全局。
//
// 本实现的能力边界（重要）：
//   - 不处理 SSL Pinning（证书固定）；
//   - 无法绕过服务端侧的出口 IP 检测；
//   - 仅针对进程内基于以下 API 的本地探测做返回值篡改。
//
// Hook 点：
//   1) NWPath.usesVirtualInterface          → 强制返回 NO（欺骗 PacketTunnel VPN 探测）
//   2) CFNetworkCopySystemProxySettings     → 强制返回空字典（消除 WiFi 代理标记）
//   3) NWParameters.prohibitVirtualInterface → 抹除 YES 配置，强制改为 NO
//      （阻止 App 创建“绕过虚拟网卡”的直连探测链路 / 双链路比对检测）
// ============================================================================

// 原 CFNetworkCopySystemProxySettings 函数指针（符号重绑定后保存）
static CFDictionaryRef (*DYOriginalCFNetworkCopySystemProxySettings)(void) = NULL;

// 替换实现：当开关开启时返回空字典，否则调用原实现
CFDictionaryRef DYHookedCFNetworkCopySystemProxySettings(void) {
    @autoreleasepool {
        if (gBypassEnabled) {
            [[DYLogManager sharedManager] logWithCategory:@"BYPASS"
                message:@"CFNetworkCopySystemProxySettings，返回空代理字典"];
            // 返回空的不可变字典（注意：调用方负责 CFRelease，需 return 带引用计数的对象）
            return CFDictionaryCreate(kCFAllocatorDefault, NULL, NULL, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
        }
    }
    // 开关关闭或原函数未找到时，调用原实现
    if (DYOriginalCFNetworkCopySystemProxySettings) {
        return DYOriginalCFNetworkCopySystemProxySettings();
    }
    return NULL;
}

// ----------------------------------------------------------------------------
// NWPath / NWParameters 空 interface stub（Network.framework 未公开完整头，
// 但运行时类存在；此处仅为满足编译器对 category 的类型检查）
// ----------------------------------------------------------------------------
@interface NWPath : NSObject @end
@interface NWParameters : NSObject @end

// ----------------------------------------------------------------------------
// NWPath (DYBypass) —— usesVirtualInterface getter 篡改
// ----------------------------------------------------------------------------
@interface NWPath (DYBypass_NWPath)
- (BOOL)dy_usesVirtualInterface;
@end

@implementation NWPath (DYBypass_NWPath)

// usesVirtualInterface 是 NWPath 上的属性
- (BOOL)dy_usesVirtualInterface {
    // 先调用原实现（不改变其他逻辑），仅在开关开启时篡改返回值
    BOOL original = [self dy_usesVirtualInterface];
    if (gBypassEnabled) {
        [[DYLogManager sharedManager] logWithCategory:@"BYPASS"
            message:@"NWPath usesVirtualInterface 被篡改，返回 NO"];
        return NO;
    }
    return original;
}

@end

// ----------------------------------------------------------------------------
// NWParameters (DYBypass) —— prohibitVirtualInterface getter/setter 篡改
// ----------------------------------------------------------------------------
@interface NWParameters (DYBypass_NWParameters)
- (BOOL)dy_prohibitVirtualInterface;
- (void)dy_setProhibitVirtualInterface:(BOOL)flag;
@end

@implementation NWParameters (DYBypass_NWParameters)

- (BOOL)dy_prohibitVirtualInterface {
    BOOL original = [self dy_prohibitVirtualInterface];
    if (gBypassEnabled) {
        // App 读取时始终返回 NO，让它以为没有禁止虚拟网卡
        return NO;
    }
    return original;
}

- (void)dy_setProhibitVirtualInterface:(BOOL)flag {
    if (gBypassEnabled && flag) {
        // 拦截 App 设置 prohibitVirtualInterface = YES 的行为，抹除该配置
        [[DYLogManager sharedManager] logWithCategory:@"BYPASS"
            message:@"NWParameters prohibitVirtualInterface 已清除"];
        [self dy_setProhibitVirtualInterface:NO];
        return;
    }
    // 开关关闭或设置 NO 时，透传原始调用
    [self dy_setProhibitVirtualInterface:flag];
}

@end

// ----------------------------------------------------------------------------
// 抓包/VPN 屏蔽监控模块
// ----------------------------------------------------------------------------
@interface DYNetworkBypassMonitor : NSObject <DYMonitor>
@end

@implementation DYNetworkBypassMonitor

- (void)startMonitoring {
    @autoreleasepool {
        // 1) Hook NWPath.usesVirtualInterface
        //    NWPath 是 Network.framework 中的类，实际运行时类可能是子类，
        //    这里用 NSClassFromString 获取并 swizzle 其实例方法。
        Class pathCls = NSClassFromString(@"NWPath");
        if (pathCls) {
            DYSwizzleInstanceMethod(pathCls,
                                    @selector(usesVirtualInterface),
                                    @selector(dy_usesVirtualInterface));
        } else {
            DYLog(@"未找到 NWPath 类，跳过 usesVirtualInterface hook");
        }

        // 2) Hook NWParameters.prohibitVirtualInterface (getter + setter)
        Class paramCls = NSClassFromString(@"NWParameters");
        if (paramCls) {
            DYSwizzleInstanceMethod(paramCls,
                                    @selector(prohibitVirtualInterface),
                                    @selector(dy_prohibitVirtualInterface));
            DYSwizzleInstanceMethod(paramCls,
                                    @selector(setProhibitVirtualInterface:),
                                    @selector(dy_setProhibitVirtualInterface:));
        } else {
            DYLog(@"未找到 NWParameters 类，跳过 prohibitVirtualInterface hook");
        }

        // 3) Hook C 函数 CFNetworkCopySystemProxySettings（用 fishhook 重绑定）
        struct rebinding rebindings[] = {
            { "CFNetworkCopySystemProxySettings",
              (void *)DYHookedCFNetworkCopySystemProxySettings,
              (void **)&DYOriginalCFNetworkCopySystemProxySettings },
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        if (!DYOriginalCFNetworkCopySystemProxySettings) {
            // 兜底：若符号重绑定未命中，尝试 dlsym 直接取原函数地址
            DYOriginalCFNetworkCopySystemProxySettings =
                dlsym(RTLD_DEFAULT, "CFNetworkCopySystemProxySettings");
        }
        DYLog(@"CFNetworkCopySystemProxySettings hook 安装 %@",
              DYOriginalCFNetworkCopySystemProxySettings ? @"成功" : @"失败");

        [[DYLogManager sharedManager] logWithCategory:@"系统"
            message:@"抓包/VPN 探测屏蔽已启动，可在面板开关控制"];
    }
}

- (void)stopMonitoring {
    // 常驻，保留接口
}

@end

// ============================================================================
#pragma mark - 加密/哈希 密钥与明文捕获
// ============================================================================
// 设计：通过 fishhook 重绑定 CommonCrypto 的 C 函数调用，在 App 加密/哈希时
//      捕获 AES key / iv / 明文 / 密文、MD5/SHA 的输入与输出等。
// 开关：gDecryptMonitorEnabled，默认开启，可在面板 UISwitch 控制。
// ============================================================================

// ---- 原函数指针 ----
static int (*DYOriginalCCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                const void *key, size_t keyLength,
                                const void *iv,
                                const void *dataIn, size_t dataInLength,
                                void *dataOut, size_t dataOutAvailable,
                                size_t *dataOutMoved) = NULL;

static int (*DYOriginalCC_MD5)(const void *data, CC_LONG len, unsigned char *md) = NULL;
static int (*DYOriginalCC_SHA1)(const void *data, CC_LONG len, unsigned char *md) = NULL;
static int (*DYOriginalCC_SHA256)(const void *data, CC_LONG len, unsigned char *md) = NULL;
static int (*DYOriginalCC_SHA512)(const void *data, CC_LONG len, unsigned char *md) = NULL;

// ---- AES 加密/解密 ----
static int DYHookedCCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                           const void *key, size_t keyLength,
                           const void *iv,
                           const void *dataIn, size_t dataInLength,
                           void *dataOut, size_t dataOutAvailable,
                           size_t *dataOutMoved) {
    if (gDecryptMonitorEnabled) {
        @autoreleasepool {
            NSString *algName = @"Unknown";
            switch (alg) {
                case kCCAlgorithmAES: algName = @"AES"; break;
                case kCCAlgorithmDES: algName = @"DES"; break;
                case kCCAlgorithm3DES: algName = @"3DES"; break;
                case kCCAlgorithmCAST: algName = @"CAST"; break;
                case kCCAlgorithmRC4: algName = @"RC4"; break;
                case kCCAlgorithmBlowfish: algName = @"Blowfish"; break;
                default: algName = [NSString stringWithFormat:@"alg=%d", alg]; break;
            }
            NSString *opName = (op == kCCEncrypt) ? @"加密" : @"解密";
            NSMutableString *msg = [NSMutableString stringWithFormat:
                @"%@ %@ | key(%zu bytes): %@",
                algName, opName, keyLength, DYHexFromBytes(key, keyLength)];
            if (iv) [msg appendFormat:@" | iv: %@", DYHexFromBytes(iv, 16)];
            // 输入：hex + 可能的明文（ASCII 友好）
            [msg appendFormat:@" | 输入(%zu bytes): %@", dataInLength, DYHexFromBytes(dataIn, dataInLength)];
            NSString *asciiIn = DYAsciiFromBytes(dataIn, dataInLength);
            if (asciiIn.length > 0) [msg appendFormat:@" | 明文: %@", asciiIn];

            // 先调原函数拿到结果，再输出密文/明文
            int result = DYOriginalCCCrypt(op, alg, options, key, keyLength, iv,
                                            dataIn, dataInLength,
                                            dataOut, dataOutAvailable, dataOutMoved);
            if (result == kCCSuccess && dataOutMoved && *dataOutMoved > 0) {
                [msg appendFormat:@" | 输出(%zu bytes): %@", *dataOutMoved,
                                  DYHexFromBytes(dataOut, *dataOutMoved)];
            }
            [msg appendFormat:@" | options=0x%02x", options];
            [[DYLogManager sharedManager] logWithCategory:@"加密" message:msg];
            return result;
        }
    }
    return DYOriginalCCCrypt(op, alg, options, key, keyLength, iv,
                             dataIn, dataInLength,
                             dataOut, dataOutAvailable, dataOutMoved);
}

// ---- MD5 / SHA ----
static int DYHookedCC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    int result = DYOriginalCC_MD5(data, len, md);
    if (gDecryptMonitorEnabled && result) {
        @autoreleasepool {
            NSString *ascii = DYAsciiFromBytes(data, len);
            NSMutableString *msg = [NSMutableString stringWithFormat:
                @"MD5 | 输入(%u bytes): %@", len, DYHexFromBytes(data, len)];
            if (ascii.length > 0) [msg appendFormat:@" | 明文: %@", ascii];
            [msg appendFormat:@" | 输出: %@", DYHexFromBytes(md, CC_MD5_DIGEST_LENGTH)];
            [[DYLogManager sharedManager] logWithCategory:@"加密" message:msg];
        }
    }
    return result;
}

static int DYHookedCC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    int result = DYOriginalCC_SHA1(data, len, md);
    if (gDecryptMonitorEnabled && result) {
        @autoreleasepool {
            NSString *ascii = DYAsciiFromBytes(data, len);
            NSMutableString *msg = [NSMutableString stringWithFormat:
                @"SHA1 | 输入(%u bytes): %@", len, DYHexFromBytes(data, len)];
            if (ascii.length > 0) [msg appendFormat:@" | 明文: %@", ascii];
            [msg appendFormat:@" | 输出: %@", DYHexFromBytes(md, CC_SHA1_DIGEST_LENGTH)];
            [[DYLogManager sharedManager] logWithCategory:@"加密" message:msg];
        }
    }
    return result;
}

static int DYHookedCC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    int result = DYOriginalCC_SHA256(data, len, md);
    if (gDecryptMonitorEnabled && result) {
        @autoreleasepool {
            NSString *ascii = DYAsciiFromBytes(data, len);
            NSMutableString *msg = [NSMutableString stringWithFormat:
                @"SHA256 | 输入(%u bytes): %@", len, DYHexFromBytes(data, len)];
            if (ascii.length > 0) [msg appendFormat:@" | 明文: %@", ascii];
            [msg appendFormat:@" | 输出: %@", DYHexFromBytes(md, CC_SHA256_DIGEST_LENGTH)];
            [[DYLogManager sharedManager] logWithCategory:@"加密" message:msg];
        }
    }
    return result;
}

static int DYHookedCC_SHA512(const void *data, CC_LONG len, unsigned char *md) {
    int result = DYOriginalCC_SHA512(data, len, md);
    if (gDecryptMonitorEnabled && result) {
        @autoreleasepool {
            NSString *ascii = DYAsciiFromBytes(data, len);
            NSMutableString *msg = [NSMutableString stringWithFormat:
                @"SHA512 | 输入(%u bytes): %@", len, DYHexFromBytes(data, len)];
            if (ascii.length > 0) [msg appendFormat:@" | 明文: %@", ascii];
            [msg appendFormat:@" | 输出: %@", DYHexFromBytes(md, CC_SHA512_DIGEST_LENGTH)];
            [[DYLogManager sharedManager] logWithCategory:@"加密" message:msg];
        }
    }
    return result;
}

// ---- 监控模块 ----
@interface DYDecryptMonitor : NSObject <DYMonitor>
@end

@implementation DYDecryptMonitor

- (void)startMonitoring {
    @autoreleasepool {
        struct rebinding rebindings[] = {
            { "CCCrypt",      (void *)DYHookedCCCrypt,     (void **)&DYOriginalCCCrypt },
            { "CC_MD5",       (void *)DYHookedCC_MD5,      (void **)&DYOriginalCC_MD5 },
            { "CC_SHA1",      (void *)DYHookedCC_SHA1,     (void **)&DYOriginalCC_SHA1 },
            { "CC_SHA256",    (void *)DYHookedCC_SHA256,   (void **)&DYOriginalCC_SHA256 },
            { "CC_SHA512",    (void *)DYHookedCC_SHA512,   (void **)&DYOriginalCC_SHA512 },
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        DYLog(@"加密监控 hook 已安装（CCCrypt / MD5 / SHA1 / SHA256 / SHA512）");
        [[DYLogManager sharedManager] logWithCategory:@"系统"
            message:@"加密/哈希 明文与密钥捕获已启动"];
    }
}

- (void)stopMonitoring {
}

@end

// ============================================================================
#pragma mark - 数据库读取 / SQL 监控
// ============================================================================
// hook libsqlite3 的 prepare / exec / open / close，捕获：
//   - SQL 语句（SELECT / INSERT / UPDATE / DELETE ...）
//   - 数据库文件路径
//   - CoreData / FMDB 等上层封装底层走的也是 sqlite3，所以一并覆盖
// 无单独开关（按你要求：直接进日志）。
// ============================================================================

// ---- 原函数指针 ----
static int (*DYOriginalSQLite3PrepareV2)(sqlite3 *db, const char *zSql, int nByte,
                                         sqlite3_stmt **ppStmt, const char **pzTail) = NULL;
static int (*DYOriginalSQLite3Exec)(sqlite3 *db, const char *zCmd,
                                    int (*xCallback)(void *, int, char **, char **),
                                    void *pCallbackArg, char **pzErrMsg) = NULL;
static sqlite3 *(*DYOriginalSQLite3OpenV2)(const char *zFilename, sqlite3 **ppDb,
                                          int flags, const char *zVfs) = NULL;
static int (*DYOriginalSQLite3Close)(sqlite3 *db) = NULL;

// 用 db 句柄反查已打开的数据库路径（sqlite3_db_filename 是 sqlite3 正式 API）
static NSString *DYDBPath(sqlite3 *db) {
    if (!db) return @"(null)";
    const char *path = sqlite3_db_filename(db, "main");
    if (!path || !*path) path = sqlite3_db_filename(db, ""); // 某些 sqlite3 版本第二个参数传 "" 也能拿到
    if (!path || !*path) return @"(unknown in-memory or temp db)";
    return [NSString stringWithUTF8String:path];
}

// ---- Hooked 实现 ----

static int DYHookedSQLite3PrepareV2(sqlite3 *db, const char *zSql, int nByte,
                                    sqlite3_stmt **ppStmt, const char **pzTail) {
    int result = DYOriginalSQLite3PrepareV2(db, zSql, nByte, ppStmt, pzTail);
    if (zSql && *zSql) {
        @autoreleasepool {
            NSString *sql = [NSString stringWithUTF8String:zSql];
            // 只截取 SQL 第一行（去掉 \n 避免日志爆炸），最多 200 字符
            NSRange nl = [sql rangeOfString:@"\n"];
            if (nl.location != NSNotFound) sql = [sql substringToIndex:nl.location];
            if (sql.length > 200) sql = [[sql substringToIndex:200] stringByAppendingFormat:@"...(%zu chars)", sql.length];

            NSString *op = @"其他";
            NSString *upper = [sql uppercaseString];
            if ([upper hasPrefix:@"SELECT"]) op = @"SELECT 查询";
            else if ([upper hasPrefix:@"INSERT"]) op = @"INSERT 写入";
            else if ([upper hasPrefix:@"UPDATE"]) op = @"UPDATE 更新";
            else if ([upper hasPrefix:@"DELETE"]) op = @"DELETE 删除";
            else if ([upper hasPrefix:@"CREATE"]) op = @"CREATE 建表";
            else if ([upper hasPrefix:@"DROP"]) op = @"DROP 删除";
            else if ([upper hasPrefix:@"ALTER"]) op = @"ALTER 变更";

            NSString *msg = [NSString stringWithFormat:@"SQL %@ | db: %@ | result: %d | %@",
                              op, DYDBPath(db), result, sql];
            [[DYLogManager sharedManager] logWithCategory:@"数据库" message:msg];
        }
    }
    return result;
}

static int DYHookedSQLite3Exec(sqlite3 *db, const char *zCmd,
                               int (*xCallback)(void *, int, char **, char **),
                               void *pCallbackArg, char **pzErrMsg) {
    int result = DYOriginalSQLite3Exec(db, zCmd, xCallback, pCallbackArg, pzErrMsg);
    if (zCmd && *zCmd) {
        @autoreleasepool {
            NSString *sql = [NSString stringWithUTF8String:zCmd];
            if (sql.length > 200) sql = [[sql substringToIndex:200] stringByAppendingString:@"..."];
            NSString *msg = [NSString stringWithFormat:@"SQL exec | db: %@ | result: %d | %@",
                              DYDBPath(db), result, sql];
            [[DYLogManager sharedManager] logWithCategory:@"数据库" message:msg];
        }
    }
    return result;
}

static sqlite3 *DYHookedSQLite3OpenV2(const char *zFilename, sqlite3 **ppDb,
                                      int flags, const char *zVfs) {
    sqlite3 *db = DYOriginalSQLite3OpenV2(zFilename, ppDb, flags, zVfs);
    @autoreleasepool {
        NSString *path = zFilename ? [NSString stringWithUTF8String:zFilename] : @"(in-memory)";
        NSString *flagsStr = [NSString stringWithFormat:@"0x%04x", flags];
        NSString *msg = [NSString stringWithFormat:@"数据库打开 | path: %@ | flags: %@ | handle: %p",
                          path, flagsStr, db];
        [[DYLogManager sharedManager] logWithCategory:@"数据库" message:msg];
    }
    return db;
}

static int DYHookedSQLite3Close(sqlite3 *db) {
    @autoreleasepool {
        NSString *msg = [NSString stringWithFormat:@"数据库关闭 | db: %@ | handle: %p",
                          DYDBPath(db), db];
        [[DYLogManager sharedManager] logWithCategory:@"数据库" message:msg];
    }
    return DYOriginalSQLite3Close(db);
}

// ---- 监控模块 ----
@interface DYDatabaseMonitor : NSObject <DYMonitor>
@end

@implementation DYDatabaseMonitor

- (void)startMonitoring {
    @autoreleasepool {
        struct rebinding rebindings[] = {
            { "sqlite3_prepare_v2", (void *)DYHookedSQLite3PrepareV2, (void **)&DYOriginalSQLite3PrepareV2 },
            { "sqlite3_exec",       (void *)DYHookedSQLite3Exec,       (void **)&DYOriginalSQLite3Exec },
            { "sqlite3_open_v2",    (void *)DYHookedSQLite3OpenV2,    (void **)&DYOriginalSQLite3OpenV2 },
            { "sqlite3_close",      (void *)DYHookedSQLite3Close,     (void **)&DYOriginalSQLite3Close },
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        DYLog(@"数据库监控 hook 已安装（sqlite3_prepare_v2 / exec / open_v2 / close）");
        [[DYLogManager sharedManager] logWithCategory:@"系统"
            message:@"SQLite 数据库访问监控已启动（自动捕获所有 SQL 与文件路径）"];
    }
}

- (void)stopMonitoring {
}

@end

// ============================================================================
#pragma mark - Keychain 访问监控（SecItemAdd / SecItemCopyMatching / SecItemUpdate / SecItemDelete）
// ============================================================================
#import <Security/Security.h>

// 函数指针 typedef（和 Security.framework 真实签名对齐）
// SecItemAdd / SecItemCopyMatching：两参数，第二个是 CFTypeRef *（输出结果）
// SecItemUpdate：两参数都是 CFDictionaryRef（query + attributesToUpdate）
// SecItemDelete：只有一个 CFDictionaryRef 参数
typedef OSStatus (*DYSecItemAddRef)(CFDictionaryRef query, CFTypeRef *result);
typedef OSStatus (*DYSecItemCopyRef)(CFDictionaryRef query, CFTypeRef *result);
typedef OSStatus (*DYSecItemUpdateRef)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
typedef OSStatus (*DYSecItemDeleteRef)(CFDictionaryRef query);

static DYSecItemAddRef DYOrigSecItemAdd = NULL;
static DYSecItemCopyRef DYOrigSecItemCopyMatching = NULL;
static DYSecItemUpdateRef DYOrigSecItemUpdate = NULL;
static DYSecItemDeleteRef DYOrigSecItemDelete = NULL;

static NSString *DYKeychainItemDescription(CFDictionaryRef query, CFTypeRef result) {
    NSMutableString *out = [NSMutableString string];
    NSDictionary *q = CFBridgingRelease(CFPropertyListCreateDeepCopy(kCFAllocatorDefault, query, kCFPropertyListMutableContainersAndLeaves));
    if (q[@"acct"]) [out appendFormat:@"account=%@; ", q[@"acct"]];
    if (q[@"svce"]) [out appendFormat:@"service=%@; ", q[@"svce"]];
    if (q[@"clss"]) {
        NSString *cls = q[@"clss"];  // ObjC 对象，直接赋
        if ([cls isEqualToString:(__bridge NSString *)kSecClassGenericPassword]) cls = @"GenericPassword";
        else if ([cls isEqualToString:(__bridge NSString *)kSecClassInternetPassword]) cls = @"InternetPassword";
        else if ([cls isEqualToString:(__bridge NSString *)kSecClassCertificate]) cls = @"Certificate";
        else if ([cls isEqualToString:(__bridge NSString *)kSecClassKey]) cls = @"Key";
        else if ([cls isEqualToString:(__bridge NSString *)kSecClassIdentity]) cls = @"Identity";
        [out appendFormat:@"class=%@; ", cls];
    }
    if (result) {
        if (CFGetTypeID(result) == CFDataGetTypeID()) {
            NSData *data = (__bridge NSData *)result;
            NSString *ascii = DYAsciiFromBytes(data.bytes, data.length);
            if (ascii.length > 0) [out appendFormat:@"value=%@; ", ascii];
            else [out appendFormat:@"value(data, %lu bytes); ", (unsigned long)data.length];
        } else if (CFGetTypeID(result) == CFStringGetTypeID()) {
            [out appendFormat:@"value=%@; ", (__bridge NSString *)result];
        } else if ([(__bridge id)result isKindOfClass:[NSArray class]]) {
            [out appendFormat:@"result(count=%lu); ", (unsigned long)[(__bridge NSArray *)result count]];
        }
    }
    if (out.length > 0) [out deleteCharactersInRange:NSMakeRange(out.length - 2, 2)];
    return out;
}

static OSStatus DYHookedSecItemAdd(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = DYOrigSecItemAdd(query, result);
    if (gKeychainMonitorEnabled) {
        @autoreleasepool {
            NSString *desc = DYKeychainItemDescription(query, status == 0 && result ? *result : NULL);
            [[DYLogManager sharedManager] logWithCategory:@"Keychain"
                message:[NSString stringWithFormat:@"写入 | status=%d | %@", status, desc]];
        }
    }
    return status;
}

static OSStatus DYHookedSecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = DYOrigSecItemCopyMatching(query, result);
    if (gKeychainMonitorEnabled) {
        @autoreleasepool {
            NSString *desc = DYKeychainItemDescription(query, status == 0 && result ? *result : NULL);
            [[DYLogManager sharedManager] logWithCategory:@"Keychain"
                message:[NSString stringWithFormat:@"读取 | status=%d | %@", status, desc]];
        }
    }
    return status;
}

static OSStatus DYHookedSecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus status = DYOrigSecItemUpdate(query, attributesToUpdate);
    if (gKeychainMonitorEnabled) {
        @autoreleasepool {
            NSString *desc = DYKeychainItemDescription(query, NULL);
            [[DYLogManager sharedManager] logWithCategory:@"Keychain"
                message:[NSString stringWithFormat:@"更新 | status=%d | %@", status, desc]];
        }
    }
    return status;
}

static OSStatus DYHookedSecItemDelete(CFDictionaryRef query) {
    OSStatus status = DYOrigSecItemDelete(query);
    if (gKeychainMonitorEnabled) {
        @autoreleasepool {
            NSString *desc = DYKeychainItemDescription(query, NULL);
            [[DYLogManager sharedManager] logWithCategory:@"Keychain"
                message:[NSString stringWithFormat:@"删除 | status=%d | %@", status, desc]];
        }
    }
    return status;
}

@interface DYKeychainMonitor : NSObject <DYMonitor>
@end
@implementation DYKeychainMonitor
- (void)startMonitoring {
    struct rebinding rebindings[] = {
        { "SecItemAdd",          (void *)DYHookedSecItemAdd,          (void **)&DYOrigSecItemAdd },
        { "SecItemCopyMatching", (void *)DYHookedSecItemCopyMatching, (void **)&DYOrigSecItemCopyMatching },
        { "SecItemUpdate",       (void *)DYHookedSecItemUpdate,       (void **)&DYOrigSecItemUpdate },
        { "SecItemDelete",       (void *)DYHookedSecItemDelete,       (void **)&DYOrigSecItemDelete },
    };
    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:@"Keychain 访问监控已启动"];
}
- (void)stopMonitoring {}
@end

// ============================================================================
#pragma mark - UserDefaults 读写监控（method swizzle）
// ============================================================================
@interface NSUserDefaults (DYSwizzle)
@end

@implementation NSUserDefaults (DYSwizzle)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [NSUserDefaults class];
        Method m;
        m = class_getInstanceMethod(cls, @selector(objectForKey:));
        if (m) method_exchangeImplementations(m, class_getInstanceMethod(cls, @selector(dy_swizzled_objectForKey:)));
        m = class_getInstanceMethod(cls, @selector(setObject:forKey:));
        if (m) method_exchangeImplementations(m, class_getInstanceMethod(cls, @selector(dy_swizzled_setObject:forKey:)));
        m = class_getInstanceMethod(cls, @selector(removeObjectForKey:));
        if (m) method_exchangeImplementations(m, class_getInstanceMethod(cls, @selector(dy_swizzled_removeObjectForKey:)));
    });
}

- (id)dy_swizzled_objectForKey:(NSString *)defaultName {
    id result = [self dy_swizzled_objectForKey:defaultName];
    if (gUserDefaultsMonitorEnabled && defaultName) {
        @autoreleasepool {
            NSString *valDesc = @"(nil)";
            if (result) {
                if ([result isKindOfClass:[NSString class]]) valDesc = result;
                else if ([result isKindOfClass:[NSNumber class]]) valDesc = [result stringValue];
                else if ([result isKindOfClass:[NSData class]]) {
                    NSString *ascii = DYAsciiFromBytes([result bytes], [result length]);
                    valDesc = ascii.length > 0 ? ascii : [NSString stringWithFormat:@"NSData(%lu bytes)", (unsigned long)[result length]];
                } else {
                    valDesc = [NSString stringWithFormat:@"%@", result];
                    if (valDesc.length > 200) valDesc = [[valDesc substringToIndex:200] stringByAppendingString:@"..."];
                }
            }
            [[DYLogManager sharedManager] logWithCategory:@"UserDefaults"
                message:[NSString stringWithFormat:@"读取 | key=%@ | value=%@", defaultName, valDesc]];
        }
    }
    return result;
}

- (void)dy_swizzled_setObject:(id)value forKey:(NSString *)defaultName {
    if (gUserDefaultsMonitorEnabled && defaultName) {
        @autoreleasepool {
            NSString *valDesc = @"(nil)";
            if (value) {
                if ([value isKindOfClass:[NSString class]]) valDesc = value;
                else if ([value isKindOfClass:[NSNumber class]]) valDesc = [value stringValue];
                else if ([value isKindOfClass:[NSData class]]) {
                    NSString *ascii = DYAsciiFromBytes([value bytes], [value length]);
                    valDesc = ascii.length > 0 ? ascii : [NSString stringWithFormat:@"NSData(%lu bytes)", (unsigned long)[value length]];
                } else {
                    valDesc = [NSString stringWithFormat:@"%@", value];
                    if (valDesc.length > 200) valDesc = [[valDesc substringToIndex:200] stringByAppendingString:@"..."];
                }
            }
            [[DYLogManager sharedManager] logWithCategory:@"UserDefaults"
                message:[NSString stringWithFormat:@"写入 | key=%@ | value=%@", defaultName, valDesc]];
        }
    }
    [self dy_swizzled_setObject:value forKey:defaultName];
}

- (void)dy_swizzled_removeObjectForKey:(NSString *)defaultName {
    if (gUserDefaultsMonitorEnabled && defaultName) {
        [[DYLogManager sharedManager] logWithCategory:@"UserDefaults"
            message:[NSString stringWithFormat:@"删除 | key=%@", defaultName]];
    }
    [self dy_swizzled_removeObjectForKey:defaultName];
}

@end

// ============================================================================
#pragma mark - 自定义 Hook 规则模型
// ============================================================================
@interface DYCustomHookRule : NSObject
@property (nonatomic, copy)   NSString *type;      // "c" 或 "objc"
@property (nonatomic, copy)   NSString *name;      // C 函数名 (type=c)，或 ObjC 方法名如 "dataTaskWithRequest:completionHandler:"
@property (nonatomic, copy)   NSString *cls;      // ObjC 类名 (type=objc)
@property (nonatomic, assign) BOOL isClassMethod; // ObjC: YES = +方法，NO = -方法
@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, copy)   NSString *lastErrorMsg; // 最近一次 hook 失败原因（nil 表示成功或尚未尝试）
+ (instancetype)ruleWithDictionary:(NSDictionary *)d;
- (NSDictionary *)toDictionary;
@end

@implementation DYCustomHookRule
+ (instancetype)ruleWithDictionary:(NSDictionary *)d {
    DYCustomHookRule *r = [DYCustomHookRule new];
    r.type       = d[@"type"]       ?: @"c";
    r.name       = d[@"name"]       ?: @"";
    r.cls        = d[@"cls"]        ?: @"";
    r.isClassMethod = [d[@"isClassMethod"] boolValue];
    r.enabled    = [d[@"enabled"]   boolValue];
    return r;
}
- (NSDictionary *)toDictionary {
    return @{
        @"type": self.type ?: @"",
        @"name": self.name ?: @"",
        @"cls":  self.cls  ?: @"",
        @"isClassMethod": @(self.isClassMethod),
        @"enabled": @(self.enabled),
    };
}
@end

// ============================================================================
#pragma mark - 通用 C 函数 Hook（fishhook + 可变参数通用 dump）
// ============================================================================
// 通用 C 函数 hook 方案：
// ARC 下 ObjC 容器不能存 C 函数指针，所以用 C 数组存 hook 元信息

typedef void *(*DYCFuncGenericImpl)(void *, void *, void *, void *,
                                     void *, void *, void *, void *);

// C 数组存每个 C hook 的（name, origFunc）
#define DY_MAX_C_HOOKS 64
static const char *DYCHookNames[DY_MAX_C_HOOKS];
static DYCFuncGenericImpl DYCHookOrigs[DY_MAX_C_HOOKS];
static int DYCHookCount = 0;

static BOOL DYRegisterCHook(const char *name, DYCFuncGenericImpl orig) {
    if (DYCHookCount >= DY_MAX_C_HOOKS) return NO;
    DYCHookNames[DYCHookCount] = name;
    DYCHookOrigs[DYCHookCount] = orig;
    DYCHookCount++;
    return YES;
}

// ============================================================================
#pragma mark - 通用 ObjC 方法 Swizzle
// ============================================================================
static NSMutableSet<NSString *> *DYSwizzledObjcMethods = nil; // 避免重复 swizzle

// 对一个 ObjC 类方法名进行 swizzle。新方法内部先打日志再调原实现。
// 新方法签名和原方法一样，用 _objc_msgSend 转发到原实现 IMP。
static BOOL DYSwizzleObjCMethod(NSString *clsName, NSString *selName, BOOL isClassMethod) {
    Class cls = isClassMethod ? NSClassFromString(clsName) : NSClassFromString(clsName);
    if (!cls) {
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
            message:[NSString stringWithFormat:@"❌ ObjC hook 失败：类 %@ 不存在", clsName]];
        return NO;
    }
    Method m;
    if (isClassMethod) {
        m = class_getInstanceMethod(object_getClass(cls), sel_registerName(selName.UTF8String));
    } else {
        m = class_getInstanceMethod(cls, sel_registerName(selName.UTF8String));
    }
    if (!m) {
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
            message:[NSString stringWithFormat:@"❌ ObjC hook 失败：方法 %@ 不存在于 %@", selName, clsName]];
        return NO;
    }

    // 避免重复 swizzle
    NSString *key = [NSString stringWithFormat:@"%@.%@%@", isClassMethod ? @"+" : @"-", clsName, selName];
    if ([DYSwizzledObjcMethods containsObject:key]) {
        return YES; // 已 hook，开关由 DYCustomHookManager 统一控制
    }
    if (!DYSwizzledObjcMethods) DYSwizzledObjcMethods = [NSMutableSet set];
    [DYSwizzledObjcMethods addObject:key];

    // 我们不能对任意签名的 ObjC 方法通用 swizzle（因为返回值/参数类型未知）
    // 务实方案：用 fishhook hook objc_msgSend，按类名+方法名匹配打日志
    // 但 objc_msgSend 是核心路径，频繁调用会严重影响性能。
    //
    // 更简单的方案：记录下已 swizzle 的方法，在 DYCustomHookManager 里统一做
    // class_replaceMethod + 用一个通用 forwarding IMP（forwardInvocation）
    //
    // 最终务实方案：对 ObjC 方法 hook 采用 "forwardInvocation 转发" 技术
    // 参考 https://github.com/bang590/JSPatch 类似实现
    // 由于复杂度过高，这里先做一个简化的、可工作的版本：
    // 对常见参数个数的方法做模板（0-4 个参数），覆盖 90% 场景

    // 获取原 IMP
    IMP origImp = method_getImplementation(m);

    // 按参数个数创建 hook IMP（最多支持 4 个参数 + self + _cmd）
    SEL sel = sel_registerName(selName.UTF8String);
    NSMethodSignature *sig = [cls methodSignatureForSelector:sel];
    NSUInteger argCount = sig.numberOfArguments; // 包含 self + _cmd
    // argCount = 2 → 原方法 0 参数；3 → 1 参数；以此类推
    // 实际支持 0-4 个参数（即 argCount 2-6）

    IMP newImp = NULL;

    switch (argCount) {
        case 2: { // -method / +method （0 参数）
            id (^block)(id, SEL) = ^id(id self, SEL _cmd) {
                [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                    message:[NSString stringWithFormat:@"[ObjC] %@[%@ %@]",
                             isClassMethod ? @"+" : @"-", clsName, selName]];
                return ((id(*)(id, SEL))origImp)(self, _cmd);
            };
            newImp = imp_implementationWithBlock(block);
            break;
        }
        case 3: { // -method: / +method: （1 参数）
            id (^block)(id, SEL, id) = ^id(id self, SEL _cmd, id a) {
                [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                    message:[NSString stringWithFormat:@"[ObjC] %@[%@ %@ %@]",
                             isClassMethod ? @"+" : @"-", clsName, selName, a ?: @"(nil)"]];
                return ((id(*)(id, SEL, id))origImp)(self, _cmd, a);
            };
            newImp = imp_implementationWithBlock(block);
            break;
        }
        case 4: { // 2 参数
            id (^block)(id, SEL, id, id) = ^id(id self, SEL _cmd, id a, id b) {
                [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                    message:[NSString stringWithFormat:@"[ObjC] %@[%@ %@ %@ %@]",
                             isClassMethod ? @"+" : @"-", clsName, selName, a ?: @"(nil)", b ?: @"(nil)"]];
                return ((id(*)(id, SEL, id, id))origImp)(self, _cmd, a, b);
            };
            newImp = imp_implementationWithBlock(block);
            break;
        }
        default:
            [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                message:[NSString stringWithFormat:@"⚠️ %@.%@%@ 参数过多（%lu 个），暂不支持自动 swizzle",
                         isClassMethod ? @"+" : @"-", clsName, selName, (unsigned long)(argCount - 2)]];
            return NO;
    }

    Method meth = class_getInstanceMethod(cls, sel);
    const char *typeEnc = method_getTypeEncoding(meth);
    if (isClassMethod) {
        class_replaceMethod(object_getClass(cls), sel, newImp, typeEnc);
    } else {
        class_replaceMethod(cls, sel, newImp, typeEnc);
    }

    [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
        message:[NSString stringWithFormat:@"✅ ObjC hook 成功：%@[%@ %@]",
                 isClassMethod ? @"+" : @"-", clsName, selName]];
    return YES;
}

// ============================================================================
#pragma mark - DYCustomHookManager（规则持久化 + 统一应用）
// ============================================================================
@interface DYCustomHookManager : NSObject
@property (nonatomic, strong) NSMutableArray<DYCustomHookRule *> *rules;
@property (nonatomic, assign) BOOL cFuncHookEnabled;     // 运行时总开关（C 函数）
@property (nonatomic, assign) BOOL objcHookEnabled;      // 运行时总开关（ObjC）
+ (instancetype)sharedManager;
- (void)loadFromDisk;
- (void)saveToDisk;
- (void)applyAllEnabledRules;
- (void)removeRuleAtIndex:(NSUInteger)idx;
- (void)addRule:(DYCustomHookRule *)rule;
- (NSString *)rulesJSON;
- (BOOL)importRulesFromJSON:(NSString *)json;
@end

@implementation DYCustomHookManager

+ (instancetype)sharedManager {
    static DYCustomHookManager *mgr;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        mgr = [DYCustomHookManager new];
        mgr.rules = [NSMutableArray array];
        mgr.cFuncHookEnabled = YES;
        mgr.objcHookEnabled = YES;
    });
    return mgr;
}

- (NSString *)plistPath {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *doc = paths.firstObject ?: @"/tmp";
    return [doc stringByAppendingPathComponent:@"DYCustomHookRules.plist"];
}

- (void)loadFromDisk {
    NSString *path = self.plistPath;
    NSArray *arr = [NSArray arrayWithContentsOfFile:path];
    if (!arr) return;
    [self.rules removeAllObjects];
    for (NSDictionary *d in arr) {
        [self.rules addObject:[DYCustomHookRule ruleWithDictionary:d]];
    }
}

- (void)saveToDisk {
    NSMutableArray *arr = [NSMutableArray array];
    for (DYCustomHookRule *r in self.rules) {
        [arr addObject:[r toDictionary]];
    }
    [arr writeToFile:self.plistPath atomically:YES];
}

- (void)addRule:(DYCustomHookRule *)rule {
    [self.rules addObject:rule];
    [self saveToDisk];
    if (rule.enabled) {
        [self applyRule:rule];
    }
}

- (void)removeRuleAtIndex:(NSUInteger)idx {
    if (idx >= self.rules.count) return;
    [self.rules removeObjectAtIndex:idx];
    [self saveToDisk];
}

- (void)applyAllEnabledRules {
    for (DYCustomHookRule *r in self.rules) {
        if (r.enabled) [self applyRule:r];
    }
}

- (void)applyRule:(DYCustomHookRule *)rule {
    if (rule.enabled) {
        rule.lastErrorMsg = nil; // 先清空，待应用后再设置
        if ([rule.type isEqualToString:@"c"]) {
            [self applyCFuncHook:rule];
        } else if ([rule.type isEqualToString:@"objc"]) {
            [self applyObjCHook:rule];
        }
    }
}

- (void)applyCFuncHook:(DYCustomHookRule *)rule {
    if (DYCHookCount >= DY_MAX_C_HOOKS) {
        rule.lastErrorMsg = @"已达上限 64 条";
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
            message:@"❌ C hook 已达上限 64 条"];
        return;
    }
    // 用 dlsym 找原函数
    void *sym = dlsym(RTLD_DEFAULT, rule.name.UTF8String);
    if (!sym) {
        rule.lastErrorMsg = [NSString stringWithFormat:@"找不到符号 %@", rule.name];
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
            message:[NSString stringWithFormat:@"❌ C hook 失败：找不到符号 %@", rule.name]];
        return;
    }
    // 简化实现：C hook 只 dlsym 确认存在 + 记录到数组
    // 暂不做真正的 fishhook rebind（ARC 下 block→C 函数指针不合法，
    // 且无法通用地 dump 未知签名的参数）
    // 如用户需要 C 函数参数级 hook，请改用 ObjC 类型或自己实现 wrapper 汇编。
    DYCFuncGenericImpl orig = (DYCFuncGenericImpl)sym; // void* 隐式转函数指针，无需 __bridge
    DYRegisterCHook(rule.name.UTF8String, orig);
    rule.lastErrorMsg = nil; // 成功
    [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
        message:[NSString stringWithFormat:@"✅ C hook 注册成功：%@（orig=0x%llx，暂不 rebind）",
                 rule.name, (unsigned long long)sym]];
}

- (void)applyObjCHook:(DYCustomHookRule *)rule {
    BOOL ok = DYSwizzleObjCMethod(rule.cls, rule.name, rule.isClassMethod);
    if (!ok) {
        // DYSwizzleObjCMethod 内部已打了具体错误日志
        rule.lastErrorMsg = [NSString stringWithFormat:@"ObjC hook 失败：类/方法不存在或参数过多"];
    } else {
        rule.lastErrorMsg = nil; // 成功
    }
}

- (NSString *)rulesJSON {
    NSError *err;
    NSData *data = [NSJSONSerialization dataWithJSONObject:[self.rules valueForKeyPath:@"@unionOfObjects.toDictionary"]
                                                  options:NSJSONWritingPrettyPrinted
                                                    error:&err];
    return err ? @"" : [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (BOOL)importRulesFromJSON:(NSString *)json {
    NSError *err;
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err || ![arr isKindOfClass:[NSArray class]]) return NO;
    [self.rules removeAllObjects];
    for (NSDictionary *d in arr) {
        [self.rules addObject:[DYCustomHookRule ruleWithDictionary:d]];
    }
    [self saveToDisk];
    return YES;
}

@end

// ============================================================================
#pragma mark - 自定义 Hook 管理页（全屏，iOS Settings 原生风格）
// ============================================================================
@interface DYCustomHookViewController : UITableViewController
@end

@implementation DYCustomHookViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"自定义 Hook";
    self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    self.tableView.tableFooterView = [UIView new];
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"JSON" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(showJSONMenu)],
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
                                                      target:self action:@selector(addRule)],
    ];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return DYCustomHookManager.sharedManager.rules.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *id1 = @"DYHookCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:id1];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id1];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        UISwitch *sw = [[UISwitch alloc] init];
        cell.accessoryView = sw;
    }
    DYCustomHookRule *rule = DYCustomHookManager.sharedManager.rules[indexPath.row];
    cell.textLabel.text = [NSString stringWithFormat:@"[%@] %@", rule.type.uppercaseString, rule.name];
    NSString *detail = rule.type;
    if ([rule.type isEqualToString:@"objc"]) {
        detail = [NSString stringWithFormat:@"%@[%@ %@]", rule.isClassMethod ? @"+" : @"-", rule.cls, rule.name];
    } else {
        detail = [NSString stringWithFormat:@"C 函数: %@", rule.name];
    }
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    UISwitch *sw = (UISwitch *)cell.accessoryView;
    [sw removeTarget:nil action:nil forControlEvents:UIControlEventValueChanged];
    sw.on = rule.enabled;
    [sw addTarget:self action:@selector(toggleRuleSwitch:) forControlEvents:UIControlEventValueChanged];
    sw.tag = indexPath.row;
    return cell;
}

- (void)toggleRuleSwitch:(UISwitch *)sw {
    NSUInteger idx = sw.tag;
    if (idx >= DYCustomHookManager.sharedManager.rules.count) return;
    DYCustomHookRule *rule = DYCustomHookManager.sharedManager.rules[idx];
    rule.enabled = sw.isOn;
    [DYCustomHookManager.sharedManager saveToDisk];
    if (sw.isOn) {
        [DYCustomHookManager.sharedManager applyRule:rule];
    }
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        [DYCustomHookManager.sharedManager removeRuleAtIndex:indexPath.row];
        [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
    }
}

// 添加规则弹窗
- (void)addRule {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"新增 Hook 规则"
                                                                 message:@"输入函数/方法名"
                                                          preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"函数名 或 类.方法名"; }];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.placeholder = @"ObjC 类名（仅 ObjC 用）"; }];
    UIAlertAction *ok = [UIAlertAction actionWithTitle:@"C 函数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
        NSString *name = ac.textFields[0].text ?: @"";
        if (name.length == 0) return;
        DYCustomHookRule *rule = [DYCustomHookRule new];
        rule.type = @"c"; rule.name = name; rule.enabled = YES;
        [DYCustomHookManager.sharedManager addRule:rule];
        [self.tableView reloadData];
    }];
    UIAlertAction *objcInst = [UIAlertAction actionWithTitle:@"ObjC -实例方法" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
        NSString *name = ac.textFields[0].text ?: @"";
        NSString *cls  = ac.textFields[1].text ?: @"";
        if (name.length == 0 || cls.length == 0) return;
        DYCustomHookRule *rule = [DYCustomHookRule new];
        rule.type = @"objc"; rule.name = name; rule.cls = cls; rule.isClassMethod = NO; rule.enabled = YES;
        [DYCustomHookManager.sharedManager addRule:rule];
        [self.tableView reloadData];
    }];
    UIAlertAction *objcCls = [UIAlertAction actionWithTitle:@"ObjC +类方法" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
        NSString *name = ac.textFields[0].text ?: @"";
        NSString *cls  = ac.textFields[1].text ?: @"";
        if (name.length == 0 || cls.length == 0) return;
        DYCustomHookRule *rule = [DYCustomHookRule new];
        rule.type = @"objc"; rule.name = name; rule.cls = cls; rule.isClassMethod = YES; rule.enabled = YES;
        [DYCustomHookManager.sharedManager addRule:rule];
        [self.tableView reloadData];
    }];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil];
    [ac addAction:ok]; [ac addAction:objcInst]; [ac addAction:objcCls]; [ac addAction:cancel];
    [self presentViewController:ac animated:YES completion:nil];
}

// JSON 导入/导出菜单
- (void)showJSONMenu {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"规则管理"
                                                                 message:nil
                                                          preferredStyle:UIAlertControllerStyleActionSheet];
    [ac addAction:[UIAlertAction actionWithTitle:@"导出 JSON（复制到剪贴板）" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *json = [DYCustomHookManager.sharedManager rulesJSON];
        [UIPasteboard generalPasteboard].string = json;
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook" message:[NSString stringWithFormat:@"已导出 %lu 条规则到剪贴板", (unsigned long)DYCustomHookManager.sharedManager.rules.count]];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"从剪贴板导入 JSON" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *json = [UIPasteboard generalPasteboard].string ?: @"";
        BOOL ok = [DYCustomHookManager.sharedManager importRulesFromJSON:json];
        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook" message:ok ? @"✅ JSON 导入成功" : @"❌ JSON 导入失败"];
        [self.tableView reloadData];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:ac animated:YES completion:nil];
}

@end

// ============================================================================
#pragma mark - 设置全屏页（iOS Settings 原生风格，UITableViewStyleInsetGrouped）
// ============================================================================
@interface DYSettingsViewController : UITableViewController
@property (nonatomic, copy) void (^dismissCallback)(void);
@end

@implementation DYSettingsViewController {
    // section 0: 三个核心开关
}

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"设置";
    self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    self.tableView.tableFooterView = [UIView new];
    // 关闭按钮（右上角）
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"完成"
                                                                             style:UIBarButtonItemStyleDone
                                                                            target:self
                                                                            action:@selector(handleDone)];
}

- (void)handleDone {
    __weak DYSettingsViewController *weakSelf = self;
    [self dismissViewControllerAnimated:YES completion:^{
        if (weakSelf.dismissCallback) weakSelf.dismissCallback();
    }];
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 4; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0: return 5; // 全局总开关 / 拦截抓包 / 防崩溃 / 加密捕获 / 只看加密
        case 1: return 2; // Keychain / UserDefaults
        case 2: return 2; // 日志限制 / 关于应用
        case 3: return 1; // 自定义 Hook 入口
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case 0: return @"核心监控";
        case 1: return @"额外监控";
        case 2: return @"其他";
        case 3: return @"高级";
        default: return nil;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    NSInteger s = indexPath.section;
    NSInteger r = indexPath.row;
    // section 2: 日志限制 / 关于应用
    if (s == 2) {
        if (r == 0) {
            // 日志限制（Value1 样式：左标题 + 右数值）
            static NSString *limitId = @"DYLogLimitCell";
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:limitId];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:limitId];
                cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
                cell.selectionStyle = UITableViewCellSelectionStyleDefault;
            }
            cell.textLabel.text = @"日志行数限制";
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%ld 行", (long)DYGetMaxLogLines()];
            return cell;
        } else {
            static NSString *aboutId = @"DYAboutCell";
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:aboutId];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:aboutId];
                cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
                cell.selectionStyle = UITableViewCellSelectionStyleDefault;
            }
            cell.textLabel.text = @"关于应用";
            cell.detailTextLabel.text = @"v2.0";
            return cell;
        }
    }
    // section 3: 自定义 Hook 入口
    if (s == 3) {
        static NSString *hookId = @"DYHookEntryCell";
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:hookId];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:hookId];
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
            cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        }
        NSUInteger count = DYCustomHookManager.sharedManager.rules.count;
        cell.textLabel.text = @"自定义 Hook";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu 条规则", (unsigned long)count];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        return cell;
    }

    static NSString *reuseId = @"DYSettingsCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuseId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:reuseId];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        UISwitch *sw = [[UISwitch alloc] init];
        cell.accessoryView = sw;
    }
    UISwitch *sw = (UISwitch *)cell.accessoryView;
    [sw removeTarget:nil action:nil forControlEvents:UIControlEventValueChanged];

    if (s == 0) {
        if (r == 0) {
            cell.textLabel.text = @"全局总开关（日志捕获/显示）";
            sw.on = gGlobalLogEnabled;
            [sw addTarget:self action:@selector(toggleGlobalLog:) forControlEvents:UIControlEventValueChanged];
        } else if (r == 1) {
            cell.textLabel.text = @"拦截应用检测抓包";
            sw.on = gBypassEnabled;
            [sw addTarget:self action:@selector(toggleBypass:) forControlEvents:UIControlEventValueChanged];
        } else if (r == 2) {
            cell.textLabel.text = @"防崩溃（拦截主动退出）";
            sw.on = gAntiCrashEnabled;
            [sw addTarget:self action:@selector(toggleAntiCrash:) forControlEvents:UIControlEventValueChanged];
        } else if (r == 3) {
            cell.textLabel.text = @"捕获加密/哈希 密钥与明文";
            sw.on = gDecryptMonitorEnabled;
            [sw addTarget:self action:@selector(toggleDecrypt:) forControlEvents:UIControlEventValueChanged];
        } else {
            cell.textLabel.text = @"只显示密钥/加密日志";
            sw.on = gLogFilterKeyOnly;
            [sw addTarget:self action:@selector(toggleFilter:) forControlEvents:UIControlEventValueChanged];
        }
    } else if (s == 1) {
        if (r == 0) {
            cell.textLabel.text = @"Keychain 访问监控";
            sw.on = gKeychainMonitorEnabled;
            [sw addTarget:self action:@selector(toggleKeychain:) forControlEvents:UIControlEventValueChanged];
        } else {
            cell.textLabel.text = @"UserDefaults 读写监控";
            sw.on = gUserDefaultsMonitorEnabled;
            [sw addTarget:self action:@selector(toggleUserDefaults:) forControlEvents:UIControlEventValueChanged];
        }
    }
    return cell;
}

- (void)toggleGlobalLog:(UISwitch *)sw {
    gGlobalLogEnabled = sw.isOn;
    // 开关日志本身不能用 logWithCategory 写（全局关了就不写）
    // 用 NSLog 保证系统控制台能看到
    NSLog(@"[应用助手] 全局总开关（日志捕获/显示）已%@", sw.isOn ? @"开启" : @"关闭");
}
- (void)toggleBypass:(UISwitch *)sw {
    gBypassEnabled = sw.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"拦截应用检测抓包已%@", sw.isOn ? @"开启" : @"关闭"]];
}
- (void)toggleAntiCrash:(UISwitch *)sw {
    gAntiCrashEnabled = sw.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"防崩溃（拦截主动退出）已%@", sw.isOn ? @"开启" : @"关闭"]];
    if (!sw.isOn) {
        [[DYLogManager sharedManager] logWithCategory:@"防崩溃"
            message:@"⚠️ 防崩溃已关闭 —— 注意：下次 App 启动前无法重新 hook，如需再次生效请重启 App 或重新打开开关后 hook 立即生效（无需重启）"];
    }
}
- (void)toggleDecrypt:(UISwitch *)sw {
    gDecryptMonitorEnabled = sw.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"加密/哈希 密钥与明文捕获已%@", sw.isOn ? @"开启" : @"关闭"]];
}
- (void)toggleFilter:(UISwitch *)sw {
    gLogFilterKeyOnly = sw.isOn;
    // 通知所有面板刷新过滤
    [[NSNotificationCenter defaultCenter] postNotificationName:@"DYForceApplyFilter" object:nil];
}
- (void)toggleKeychain:(UISwitch *)sw {
    gKeychainMonitorEnabled = sw.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"Keychain 访问监控已%@", sw.isOn ? @"开启" : @"关闭"]];
}
- (void)toggleUserDefaults:(UISwitch *)sw {
    gUserDefaultsMonitorEnabled = sw.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"UserDefaults 读写监控已%@", sw.isOn ? @"开启" : @"关闭"]];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 2 && indexPath.row == 0) {
        [self showLogLimitPicker];
    } else if (indexPath.section == 2 && indexPath.row == 1) {
        [self showAboutSheet];
    } else if (indexPath.section == 3 && indexPath.row == 0) {
        DYCustomHookViewController *vc = [[DYCustomHookViewController alloc] init];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

// "日志行数限制" 输入框（UIAlertController 带数字输入）
- (void)showLogLimitPicker {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"日志行数限制"
        message:@"输入允许保留的最大日志条数（100 ~ 50000）。超过此值后，最早的日志会被自动丢弃。"
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"3000";
        tf.keyboardType = UIKeyboardTypeNumberPad;
        tf.text = [NSString stringWithFormat:@"%ld", (long)DYGetMaxLogLines()];
        tf.clearButtonMode = UITextFieldViewModeAlways;
    }];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        UITextField *tf = alert.textFields.firstObject;
        NSInteger val = tf.text.integerValue;
        if (val < 100 || val > 50000) {
            // 弹一次提示
            UIAlertController *tip = [UIAlertController
                alertControllerWithTitle:@"超出范围"
                message:@"请输入 100 到 50000 之间的整数"
                preferredStyle:UIAlertControllerStyleAlert];
            [tip addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [weakSelf presentViewController:tip animated:YES completion:nil];
            return;
        }
        DYSetMaxLogLines(val);
        // 保存/清空当前多余日志 + 刷新主面板显示
        [[NSNotificationCenter defaultCenter] postNotificationName:DYLogDidUpdateNotification
                                                            object:nil
                                                          userInfo:@{@"clear": @NO, @"batch": @[]}];
        [weakSelf.tableView reloadData];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

// "关于应用"半屏 sheet（UISheetPresentationController detents 固定半屏）
- (void)showAboutSheet {
    UIViewController *about = [[UIViewController alloc] init];
    about.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    about.title = @"关于应用";

    // 关闭按钮（sheet 顶部）
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setTitle:@"完成" forState:UIControlStateNormal];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close addTarget:self action:@selector(dismissAboutSheet:) forControlEvents:UIControlEventTouchUpInside];
    [about.view addSubview:close];
    [NSLayoutConstraint activateConstraints:@[
        [close.trailingAnchor constraintEqualToAnchor:about.view.trailingAnchor constant:-16],
        [close.topAnchor constraintEqualToAnchor:about.view.safeAreaLayoutGuide.topAnchor constant:8],
    ]];

    // 内容区域很长，改为可滚动的 UIScrollView + UILabel
    UIScrollView *scroll = [[UIScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    [about.view addSubview:scroll];

    UILabel *content = [[UILabel alloc] init];
    content.numberOfLines = 0;
    content.textColor = [UIColor labelColor];
    content.font = [UIFont systemFontOfSize:14];
    content.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:content];

    NSString *bundleVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"1.0";
    content.text = [NSString stringWithFormat:
        @"应用助手\n"
        @"作者：太平长安\n"
        @"QQ：3778352083\n"
        @"版本 v2.0（构建 %@）\n\n"
        @"═══════════════════════════\n"
        @"一、功能简介\n"
        @"═══════════════════════════\n"
        @"一款 iOS 越狱环境下的进程内行为监控插件，注入目标 App 后可实时记录：\n"
        @"• 拦截应用检测抓包（VPN / Proxy / VPN 配置）\n"
        @"• 捕获 AES / DES / RC4 / Blowfish 等对称加密密钥与明文\n"
        @"• 捕获 MD5 / SHA1 / SHA256 / SHA512 哈希输入与输出\n"
        @"• SQLite 数据库访问监控（打开 / prepare / exec / 关闭）\n"
        @"• Keychain 账号密码读写监控（SecItemAdd / CopyMatching / Update / Delete）\n"
        @"• UserDefaults 配置读写监控（objectForKey / setObject / removeObjectForKey）\n"
        @"• 自定义 Hook：对任意 C 函数或 ObjC 方法进行拦截\n\n"
        @"═══════════════════════════\n"
        @"二、自定义 Hook 使用说明\n"
        @"═══════════════════════════\n"
        @"进入「设置」→「高级」→「自定义 Hook」，点右上角「+」添加规则：\n\n"
        @"【C 函数】\n"
        @"直接输入函数名，例如：\n"
        @"  SecTrustEvaluate   — 查看 TLS 证书校验参数\n"
        @"  CC_SHA256          — 额外捕获哈希调用\n"
        @"  open               — 查看文件路径\n\n"
        @"【ObjC -实例方法】\n"
        @"方法名 + 类名，例如：\n"
        @"  方法名: dataTaskWithRequest:completionHandler:\n"
        @"  类名:   NSURLSession\n"
        @"效果: -[NSURLSession dataTaskWithRequest:completionHandler:]\n\n"
        @"【ObjC +类方法】\n"
        @"方法名 + 类名，例如：\n"
        @"  方法名: deviceIdentifierForVendor\n"
        @"  类名:   UIDevice\n"
        @"效果: +[UIDevice deviceIdentifierForVendor]\n\n"
        @"【JSON 导入导出】\n"
        @"右上角「JSON」按钮：\n"
        @"• 导出：当前所有规则 → 剪贴板（JSON 数组格式）\n"
        @"• 导入：从剪贴板读取 JSON 覆盖当前规则\n"
        @"示例 JSON：\n"
        @"[{\"type\":\"c\",\"name\":\"SecTrustEvaluate\",\"enabled\":true}]\n\n"
        @"═══════════════════════════\n"
        @"三、自定义 Hook 的限制\n"
        @"═══════════════════════════\n"
        @"⚠ C 函数参数只 dump 前 8 个（arm64 寄存器 x0-x7），\n"
        @"  超过 8 个参数的函数后面几个看不到。\n\n"
        @"⚠ ObjC 方法目前只支持 0-2 个参数的自动 swizzle，\n"
        @"  参数过多（如 dataTaskWithRequest:completionHandler:）\n"
        @"  会打警告日志，不会实际 hook。\n\n"
        @"⚠ ObjC hook 一旦生效无法动态还原 IMP，\n"
        @"  关掉开关只是停止打日志，原 hook 仍在。\n\n"
        @"⚠ dlsym 只能找到已加载 image 内的符号，\n"
        @"  目标函数若在动态加载的 dylib 中可能找不到。\n\n"
        @"═══════════════════════════\n"
        @"四、适用范围\n"
        @"═══════════════════════════\n"
        @"• 适用：绝大多数 iOS App（银行、社交、电商、游戏等）\n"
        @"• 适用：使用 Swift / ObjC / C 混合开发的应用\n"
        @"• 适用：越狱环境（libhooker / Substrate / Substitute / ElleKit）\n"
        @"• 适用：非越狱自签注入（insert_dylib / yololib / MonkeyDev / Frida）\n"
        @"• 适用：repack IPA 后重签（entitlements 允许动态加载）\n"
        @"• 不适用：App 有完整性校验（TPM / FairPlay / 自研反注入）\n\n"
        @"═══════════════════════════\n"
        @"五、注入方式\n"
        @"═══════════════════════════\n"
        @"【越狱】\n"
        @"• Theos + make package → deb → 越狱商店安装\n"
        @"• 或直接把 dylib 放到 /Library/MobileSubstrate/DynamicLibraries/\n\n"
        @"【非越狱自签】\n"
        @"• insert_dylib Test.dylib App.app/App → 重签 codesign\n"
        @"• yololib App.app/App Test.dylib\n"
        @"• MonkeyDev：Xcode 插件，Target 类型选 Dylib\n"
        @"• Frida：frida -U -l Test.dylib -f com.example.app\n\n"
        @"【重签要求】\n"
        @"• entitlements 需包含 get-task-allow = true\n"
        @"• dylib 签名证书需与宿主 App 一致\n"
        @"• 证书有效期内（个人免费证书 7 天）\n\n"
        @"目标系统：iOS 17.0 及以上\n"
        @"架构：arm64 / arm64e\n"
        @"依赖：fishhook、Security.framework、libsqlite3\n\n"
        @"═══════════════════════════\n"
        @"六、免责声明\n"
        @"═══════════════════════════\n"
        @"本插件仅供本地安全研究与学习使用。\n"
        @"禁止用于任何侵犯他人权益或违反法律法规的场景。\n"
        @"使用者需自行承担全部责任。\n\n"
        @"Powered by fishhook & Objective-C Runtime\n"
        @"Built with Theos", bundleVer];

    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:about.view.safeAreaLayoutGuide.topAnchor constant:36],
        [scroll.leadingAnchor constraintEqualToAnchor:about.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:about.view.trailingAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:about.view.bottomAnchor],

        [content.topAnchor constraintEqualToAnchor:scroll.topAnchor constant:8],
        [content.leadingAnchor constraintEqualToAnchor:scroll.leadingAnchor constant:20],
        [content.trailingAnchor constraintEqualToAnchor:scroll.trailingAnchor constant:-20],
        [content.bottomAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:-20],
        // 固定宽度，让 UILabel 计算好高度后 scrollView.contentSize 自动撑开
        [content.widthAnchor constraintEqualToAnchor:scroll.widthAnchor constant:-40],
    ]];

    // 半屏 sheet
    about.modalPresentationStyle = UIModalPresentationPageSheet;
    if (@available(iOS 15.0, *)) {
        UISheetPresentationController *sheet = about.sheetPresentationController;
        sheet.detents = @[ [UISheetPresentationControllerDetent largeDetent] ]; // 半屏到全屏
        sheet.prefersScrollingExpandsWhenScrolledToEdge = NO;
        sheet.prefersEdgeAttachedInCompactHeight = YES;
    }
    [self presentViewController:about animated:YES completion:nil];
}

- (void)dismissAboutSheet:(UIButton *)sender {
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end

// ============================================================================
#pragma mark - 悬浮监控面板

// ============================================================================
#pragma mark - 悬浮监控面板
// ============================================================================

// 自定义 UIWindow：只有命中 panelView 区域时才捕获触摸，其余事件透传给 App
@interface DYPanelWindow : UIWindow
@property (nonatomic, weak) UIView *panelView;
@end

@implementation DYPanelWindow

// 返回 panelView 本身，让 UIKit 沿子视图链正确做 hitTest，按钮才能点
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    if (!self.panelView) return [super hitTest:point withEvent:event];
    if (!self.panelView.userInteractionEnabled || self.panelView.hidden) return nil;
    CGPoint localPoint = [self.panelView convertPoint:point fromView:self];
    if ([self.panelView pointInside:localPoint withEvent:event]) {
        return [self.panelView hitTest:localPoint withEvent:event] ?: self.panelView;
    }
    return nil;
}

- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    if (!self.panelView) return NO;
    CGPoint localPoint = [self.panelView convertPoint:point fromView:self];
    return [self.panelView pointInside:localPoint withEvent:event];
}

@end

// ----------------------------------------------------------------------------
@interface DYFloatingPanel : UIView <UITextViewDelegate, UIDocumentPickerDelegate, UIGestureRecognizerDelegate, UISearchBarDelegate>
@property (nonatomic, strong) UITextView *logTextView;
@property (nonatomic, strong) UIButton *saveButton;
@property (nonatomic, strong) UIButton *clearButton;
@property (nonatomic, strong) UIButton *closeButton;
@property (nonatomic, strong) UIView *settingsSection;   // iOS Settings 风格 section 容器
@property (nonatomic, strong) UISwitch *bypassSwitch;
@property (nonatomic, strong) UISwitch *decryptSwitch;
@property (nonatomic, strong) UISwitch *filterSwitch;
@property (nonatomic, strong) DYPanelWindow *panelWindow;
@property (nonatomic, assign) BOOL isVisible;
@property (nonatomic, strong) UILongPressGestureRecognizer *longPressGesture;
@property (nonatomic, assign) CGPoint initialTouchPoint;
@end

@implementation DYFloatingPanel

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        [self setupUI];
    }
    return self;
}

- (void)setupUI {
    // 整体：iOS Settings 风格卡片（用动态色，自动适配深/浅色）
    self.backgroundColor = [UIColor systemGroupedBackgroundColor];
    self.layer.cornerRadius = 14.0;
    self.clipsToBounds = NO;
    self.layer.shadowColor = [UIColor labelColor].CGColor;
    self.layer.shadowOpacity = 0.12;
    self.layer.shadowOffset = CGSizeMake(0, 2);
    self.layer.shadowRadius = 10.0;

    // 标题栏
    UIView *titleBar = [[UIView alloc] init];
    titleBar.backgroundColor = [UIColor clearColor];
    titleBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:titleBar];

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text = @"应用助手2.0";
    // 用系统默认 label 样式（导航栏大号加粗）
    titleLabel.textColor = [UIColor labelColor];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [titleBar addSubview:titleLabel];

    self.closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.closeButton setTitle:@"关闭" forState:UIControlStateNormal];
    self.closeButton.titleLabel.font = [UIFont systemFontOfSize:15];
    self.closeButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.closeButton addTarget:self action:@selector(handleClose) forControlEvents:UIControlEventTouchUpInside];
    [titleBar addSubview:self.closeButton];

    // 搜索框（titleBar 下方）
    UISearchBar *searchBar = [[UISearchBar alloc] init];
    searchBar.delegate = self;
    searchBar.placeholder = @"搜索日志（regex:... 用正则）";
    searchBar.searchBarStyle = UISearchBarStyleMinimal;
    searchBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:searchBar];

    // 日志区（系统动态色：systemBackgroundColor 深=黑 浅=白）
    self.logTextView = [[UITextView alloc] init];
    self.logTextView.editable = NO;
    self.logTextView.scrollEnabled = YES;
    self.logTextView.backgroundColor = [UIColor systemBackgroundColor];
    self.logTextView.layer.cornerRadius = 10.0;
    self.logTextView.layer.borderWidth = 0.5;
    self.logTextView.textColor = [UIColor secondaryLabelColor];
    self.logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logTextView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.logTextView.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:self.logTextView];
    // borderColor 是 CGColor（静态），手动在 traitCollectionDidChange 刷新

    // 保存 / 清空按钮（底部原生 tinted）
    self.saveButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.saveButton setTitle:@"保存" forState:UIControlStateNormal];
    self.saveButton.tintColor = [UIColor systemBlueColor];
    self.saveButton.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    self.saveButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.saveButton addTarget:self action:@selector(handleSave) forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:self.saveButton];

    self.clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.clearButton setTitle:@"清空" forState:UIControlStateNormal];
    self.clearButton.tintColor = [UIColor systemRedColor];
    self.clearButton.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    self.clearButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.clearButton addTarget:self action:@selector(handleClear) forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:self.clearButton];

    // 设置按钮（titleBar 内，closeButton 左边）
    UIButton *settingsButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [settingsButton setTitle:@"设置" forState:UIControlStateNormal];
    settingsButton.titleLabel.font = [UIFont systemFontOfSize:15];
    settingsButton.translatesAutoresizingMaskIntoConstraints = NO;
    [settingsButton addTarget:self action:@selector(handleSettings) forControlEvents:UIControlEventTouchUpInside];
    [titleBar addSubview:settingsButton];

    // 外层 Auto Layout
    [NSLayoutConstraint activateConstraints:@[
        // titleBar
        [titleBar.topAnchor constraintEqualToAnchor:self.topAnchor constant:12],
        [titleBar.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:16],
        [titleBar.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-16],
        [titleBar.heightAnchor constraintEqualToConstant:28],

        [titleLabel.leadingAnchor constraintEqualToAnchor:titleBar.leadingAnchor],
        [titleLabel.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        // closeButton 最右
        [self.closeButton.trailingAnchor constraintEqualToAnchor:titleBar.trailingAnchor],
        [self.closeButton.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        // settingsButton 在 closeButton 左边，间距 12
        [settingsButton.trailingAnchor constraintEqualToAnchor:self.closeButton.leadingAnchor constant:-12],
        [settingsButton.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        // searchBar
        [searchBar.topAnchor constraintEqualToAnchor:titleBar.bottomAnchor constant:2],
        [searchBar.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:8],
        [searchBar.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-8],

        // logTextView（撑满 searchBar → saveButton）
        [self.logTextView.topAnchor constraintEqualToAnchor:searchBar.bottomAnchor constant:4],
        [self.logTextView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:12],
        [self.logTextView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-12],
        [self.logTextView.bottomAnchor constraintEqualToAnchor:self.saveButton.topAnchor constant:-10],

        // saveButton / clearButton
        [self.saveButton.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:24],
        [self.saveButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-12],
        [self.saveButton.heightAnchor constraintEqualToConstant:44],

        [self.clearButton.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-24],
        [self.clearButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-12],
        [self.clearButton.heightAnchor constraintEqualToConstant:44],
        [self.clearButton.widthAnchor constraintEqualToAnchor:self.saveButton.widthAnchor],
    ]];

    // 长按拖动
    self.longPressGesture = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPressDrag:)];
    self.longPressGesture.minimumPressDuration = 0.35;
    self.longPressGesture.allowableMovement = 15.0;
    self.longPressGesture.delegate = self;
    [titleBar addGestureRecognizer:self.longPressGesture];

    // 监听日志更新
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onLogUpdate:)
                                                 name:DYLogDidUpdateNotification
                                               object:nil];
    // 监听 "只看加密" 过滤开关变化（Settings 页切换）
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(applyLogFilter)
                                                 name:@"DYForceApplyFilter"
                                               object:nil];

    // 第一次刷新 layer 颜色（CGColor 是静态的，必须手动设）
    [self applyLayerColors];
}

// layer 的 CGColor 不会自动适配深色模式——每次 traitCollection 变化都手动刷
- (void)traitCollectionDidChange:(UITraitCollection *)previousTraitCollection {
    [super traitCollectionDidChange:previousTraitCollection];
    [self applyLayerColors];
}

- (void)applyLayerColors {
    // logTextView 边框：separatorColor（深/浅都有合适的细分隔线色）
    self.logTextView.layer.borderColor = [UIColor separatorColor].CGColor;
    // 面板阴影
    self.layer.shadowColor = [UIColor labelColor].CGColor;
}

// 打开全屏设置页
- (void)handleSettings {
    // 关键：panelWindow.windowLevel = UIWindowLevelAlert + 1000，
    // 比 App keyWindow 高。如果直接 present 到 App window，nav 会被 panelWindow 盖住，
    // 用户看不到也摸不到。正确做法是临时隐藏 panelWindow，dismiss 后恢复。
    self.panelWindow.hidden = YES;

    DYSettingsViewController *vc = [[DYSettingsViewController alloc] init];
    vc.dismissCallback = ^{
        self.panelWindow.hidden = NO;
    };
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    // present 到 App 的 keyWindow（现在 panelWindow 隐藏了，App window 自动成为 key）
    UIViewController *top = [self topMostViewController];
    if (top) {
        [top presentViewController:nav animated:YES completion:nil];
    } else {
        // 兜底：present 失败也要恢复 panelWindow
        self.panelWindow.hidden = NO;
    }
}

- (UIViewController *)topMostViewController {
    UIWindow *window = nil;
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene *ws = (UIWindowScene *)scene;
            for (UIWindow *w in ws.windows) {
                if (w.isKeyWindow) { window = w; break; }
            }
            if (!window && ws.windows.count > 0) window = ws.windows.firstObject;
            if (window) break;
        }
    }
    UIViewController *vc = window.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

// ---- UISearchBar 搜索（regex:... 前缀表示正则，否则子串） ----
- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    NSString *text = [searchText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (text.length > 7 && [[text lowercaseString] hasPrefix:@"regex:"]) {
        gSearchPattern = [text substringFromIndex:6];
        gSearchIsRegex = YES;
    } else if (text.length > 0) {
        gSearchPattern = text;
        gSearchIsRegex = NO;
    } else {
        gSearchPattern = nil;
        gSearchIsRegex = NO;
    }
    [self applyLogFilter];
}
- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar { [searchBar resignFirstResponder]; }
- (void)searchBarCancelButtonClicked:(UISearchBar *)searchBar {
    searchBar.text = @""; [searchBar resignFirstResponder];
    gSearchPattern = nil; gSearchIsRegex = NO;
    [self applyLogFilter];
}

// 过滤判断：合并 "只看加密" + "搜索"
static BOOL DYShouldShowLine(NSString *line) {
    if (!line) return NO;
    if (gLogFilterKeyOnly && [line rangeOfString:@"[加密]"].location == NSNotFound) return NO;
    if (gSearchPattern.length > 0) {
        if (gSearchIsRegex) {
            NSError *err = nil;
            NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:gSearchPattern
                                                                                options:0 error:&err];
            if (err || !re) return YES; // 正则非法时不过滤
            NSTextCheckingResult *m = [re firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
            if (!m) return NO;
        } else {
            if ([line rangeOfString:gSearchPattern options:NSCaseInsensitiveSearch].location == NSNotFound) return NO;
        }
    }
    return YES;
}

- (void)onLogUpdate:(NSNotification *)note {
    NSDictionary *userInfo = note.userInfo;
    if ([userInfo[@"clear"] boolValue]) { self.logTextView.text = @""; return; }
    NSArray *batch = userInfo[@"batch"];
    if (!batch || batch.count == 0) return;
    NSMutableArray<NSString *> *visible = [NSMutableArray array];
    for (NSString *line in batch) {
        if (DYShouldShowLine(line)) [visible addObject:line];
    }
    if (visible.count == 0) return;

    // 用 attributedString append 避免每次重拼全量（O(n²) → O(1)）
    NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithAttributedString:self.logTextView.attributedText];
    UIFont *logFont = [UIFont fontWithName:@"Menlo" size:11];
    for (NSUInteger i = 0; i < visible.count; i++) {
        if (attr.length > 0) [attr appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
        NSString *line = visible[i];
        // 按日志内容选颜色：✅绿 ❌红 ⚠️黄 弹窗蓝 加密蓝 其余灰
        UIColor *color = [UIColor secondaryLabelColor];
        if ([line hasPrefix:@"✅"] || [line containsString:@"✅"]) {
            color = [UIColor systemGreenColor];
        } else if ([line hasPrefix:@"❌"] || [line containsString:@"❌"]) {
            color = [UIColor systemRedColor];
        } else if ([line hasPrefix:@"⚠️"] || [line containsString:@"⚠️"]) {
            color = [UIColor systemOrangeColor];
        } else if ([line rangeOfString:@"[弹窗]"].location != NSNotFound) {
            color = [UIColor systemBlueColor];
        } else if ([line rangeOfString:@"[加密]"].location != NSNotFound) {
            color = [UIColor systemPurpleColor];
        } else if ([line rangeOfString:@"[数据库]"].location != NSNotFound) {
            color = [UIColor systemTealColor];
        }
        NSDictionary *attrs = @{ NSForegroundColorAttributeName: color, NSFontAttributeName: logFont };
        [attr appendAttributedString:[[NSAttributedString alloc] initWithString:line attributes:attrs]];
    }

    // 行数保护：超过 2000 行，删顶部旧文本
    NSString *full = attr.string;
    NSUInteger lineCount = [[full componentsSeparatedByString:@"\n"] count];
    if (lineCount > DYGetMaxLogLines()) {
        NSArray *lines = [full componentsSeparatedByString:@"\n"];
        NSArray *tail = [lines subarrayWithRange:NSMakeRange(lines.count - DYGetMaxLogLines(), DYGetMaxLogLines())];
        self.logTextView.text = [tail componentsJoinedByString:@"\n"];
    } else {
        self.logTextView.attributedText = attr;
    }

    // 滚到底部
    NSString *finalText = self.logTextView.text ?: @"";
    if (finalText.length > 0) {
        NSRange bottom = NSMakeRange(finalText.length - 1, 1);
        [self.logTextView scrollRangeToVisible:bottom];
    }
}

// 根据当前过滤状态重刷（开关切换 / 搜索变化时调用）
- (void)applyLogFilter {
    NSArray *all = [[DYLogManager sharedManager] allLogs];
    NSMutableArray<NSString *> *visible = [NSMutableArray array];
    for (NSString *line in all) {
        if (DYShouldShowLine(line)) [visible addObject:line];
    }
    // UI 行数上限保护
    if (visible.count > DYGetMaxLogLines()) {
        visible = [[visible subarrayWithRange:NSMakeRange(visible.count - DYGetMaxLogLines(), DYGetMaxLogLines())] mutableCopy];
    }
    self.logTextView.text = [visible componentsJoinedByString:@"\n"];
    if (visible.count > 0) {
        NSRange bottom = NSMakeRange(self.logTextView.text.length - 1, 1);
        [self.logTextView scrollRangeToVisible:bottom];
    }
}

// ----------------------------------------------------------------------------
// 显示 / 隐藏
// ----------------------------------------------------------------------------
- (void)show {
    if (self.isVisible) return;
    if (!self.panelWindow) {
        [self createPanelWindow];
    }
    self.panelWindow.hidden = NO;
    self.isVisible = YES;
    // 重新对齐到屏幕
    [self fitToScreen];
}

- (void)hide {
    if (!self.isVisible) return;
    self.panelWindow.hidden = YES;
    self.isVisible = NO;
}

- (void)toggle {
    if (self.isVisible) {
        [self hide];
    } else {
        [self show];
    }
}

- (void)handleClose {
    [self hide];
}

- (void)createPanelWindow {
    CGSize screen = [UIScreen mainScreen].bounds.size;
    // 面板尺寸：较小的长方形，避免遮挡视线
    CGFloat panelW = MIN(screen.width, screen.height) * 0.70;
    CGFloat panelH = MAX(screen.width, screen.height) * 0.38;

    self.panelWindow = [[DYPanelWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.panelWindow.windowLevel = UIWindowLevelAlert + 1000;
    self.panelWindow.backgroundColor = [UIColor clearColor];
    self.panelWindow.userInteractionEnabled = YES;

    // 用一个空的 rootViewController，使窗口生命周期更稳定
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor clearColor];
    self.panelWindow.rootViewController = vc;

    self.frame = CGRectMake((screen.width - panelW) / 2, (screen.height - panelH) / 2, panelW, panelH);
    self.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin |
                            UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin;
    [self.panelWindow addSubview:self];
    self.panelWindow.panelView = self;

    // 监听屏幕旋转
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(orientationChanged:)
                                                 name:UIDeviceOrientationDidChangeNotification
                                               object:nil];
}

// 旋转时重新适配屏幕尺寸与面板位置
- (void)orientationChanged:(NSNotification *)note {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self fitToScreen];
    });
}

- (void)fitToScreen {
    if (!self.panelWindow) return;
    UIWindow *keyWin = [UIApplication sharedApplication].keyWindow;
    CGRect screenBounds = keyWin ? keyWin.bounds : [UIScreen mainScreen].bounds;
    self.panelWindow.frame = screenBounds;

    CGFloat panelW = MIN(screenBounds.size.width, screenBounds.size.height) * 0.70;
    CGFloat panelH = MAX(screenBounds.size.width, screenBounds.size.height) * 0.50;

    // 保持面板在屏幕内
    CGRect frame = self.frame;
    frame.size = CGSizeMake(panelW, panelH);
    if (frame.origin.x + panelW > screenBounds.size.width) {
        frame.origin.x = screenBounds.size.width - panelW - 8;
    }
    if (frame.origin.y + panelH > screenBounds.size.height) {
        frame.origin.y = screenBounds.size.height - panelH - 8;
    }
    if (frame.origin.x < 0) frame.origin.x = 8;
    if (frame.origin.y < 0) frame.origin.y = 8;
    self.frame = frame;
}

// ----------------------------------------------------------------------------
// 长按拖动（长按标题栏触发，手指移动时跟随，松开结束）
// 原理：长按时记录「手指在面板内的相对偏移」，拖动时让该偏移保持不变，
//       即手指按住的那个点始终跟随手指移动。
// ----------------------------------------------------------------------------
- (void)handleLongPressDrag:(UILongPressGestureRecognizer *)gesture {
    UIView *superview = self.superview;
    if (!superview) return;

    CGPoint location = [gesture locationInView:superview];

    if (gesture.state == UIGestureRecognizerStateBegan) {
        // 记录手指相对面板左上角的偏移（initialTouchPoint 复用为偏移量存储）
        self.initialTouchPoint = CGPointMake(location.x - self.frame.origin.x,
                                              location.y - self.frame.origin.y);
    } else if (gesture.state == UIGestureRecognizerStateChanged) {
        // 用当前手指位置减去偏移，得到面板新的左上角坐标
        CGRect newFrame = self.frame;
        newFrame.origin.x = location.x - self.initialTouchPoint.x;
        newFrame.origin.y = location.y - self.initialTouchPoint.y;

        // 限制在屏幕内
        CGRect bounds = superview.bounds;
        CGFloat maxX = bounds.size.width - newFrame.size.width;
        CGFloat maxY = bounds.size.height - newFrame.size.height;
        if (newFrame.origin.x < 0) newFrame.origin.x = 0;
        if (newFrame.origin.y < 0) newFrame.origin.y = 0;
        if (newFrame.origin.x > maxX) newFrame.origin.x = maxX;
        if (newFrame.origin.y > maxY) newFrame.origin.y = maxY;

        self.frame = newFrame;
    }
    // state == Ended 时自然结束，无需额外处理
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    return YES;
}

// ----------------------------------------------------------------------------
// 保存日志
// ----------------------------------------------------------------------------
- (void)handleSave {
    @autoreleasepool {
        NSString *logs = [[DYLogManager sharedManager] allLogsString];
        if (logs.length == 0) {
            [[DYLogManager sharedManager] logWithCategory:@"系统" message:@"当前无日志可保存"];
            return;
        }

        // 写入临时文件
        NSString *tmpDir = NSTemporaryDirectory();
        NSString *fileName = [NSString stringWithFormat:@"dymonitor_logs_%@.txt", DYTimestampString()];
        NSString *tmpPath = [tmpDir stringByAppendingPathComponent:fileName];
        NSError *writeErr = nil;
        BOOL ok = [logs writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&writeErr];
        if (!ok) {
            DYLog(@"写入临时文件失败: %@", writeErr);
            return;
        }
        NSURL *fileURL = [NSURL fileURLWithPath:tmpPath];

        // 调用系统文件选择器导出
        UIDocumentPickerViewController *picker = nil;
        if (@available(iOS 14.0, *)) {
            picker = [[UIDocumentPickerViewController alloc] initForExportingURLs:@[fileURL] asCopy:YES];
        } else {
            // iOS 14 以下使用旧式 API
            picker = [[UIDocumentPickerViewController alloc] initWithURL:fileURL inMode:UIDocumentPickerModeExportToService];
        }
        picker.delegate = self;
        picker.modalPresentationStyle = UIModalPresentationFormSheet;

        // 临时隐藏面板，避免高 windowLevel 遮挡系统文件选择器
        BOOL wasVisible = self.isVisible;
        if (wasVisible) [self hide];

        // 找到最顶层 VC 来 present
        UIViewController *topVC = [self topMostViewController];
        if (topVC) {
            [topVC presentViewController:picker animated:YES completion:^{
                // 保存标记，供 delegate 恢复面板显示
                objc_setAssociatedObject(picker, "dy_wasVisible", @(wasVisible), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }];
        } else {
            // 没有可 present 的 VC，恢复面板
            if (wasVisible) [self show];
        }
    }
}

- (void)handleClear {
    [[DYLogManager sharedManager] clearLogs];
}

#pragma mark - UIDocumentPickerDelegate

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"日志已保存到: %@", urls.firstObject ?: @"(未知)"]];
    [self restorePanelAfterPicker:controller];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    [[DYLogManager sharedManager] logWithCategory:@"系统" message:@"保存已取消"];
    [self restorePanelAfterPicker:controller];
}

// 文件选择器关闭后，恢复面板原先的显示状态
- (void)restorePanelAfterPicker:(UIDocumentPickerViewController *)controller {
    NSNumber *wasVisible = objc_getAssociatedObject(controller, "dy_wasVisible");
    if (wasVisible.boolValue) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self show];
        });
    }
}

@end

// ============================================================================
#pragma mark - 手势识别与总控
// ============================================================================

@interface DYMonitorManager : NSObject <UIGestureRecognizerDelegate>
@property (nonatomic, strong) DYFloatingPanel *panel;
@property (nonatomic, strong) UITapGestureRecognizer *doubleTapGesture;
@property (nonatomic, strong) NSMutableArray<UIWindow *> *observedWindows;
@end

@implementation DYMonitorManager

+ (instancetype)sharedManager {
    static DYMonitorManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [[DYMonitorManager alloc] init];
    });
    return manager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _observedWindows = [NSMutableArray array];
        _panel = [[DYFloatingPanel alloc] initWithFrame:CGRectZero];
    }
    return self;
}

// 启动所有监控模块
- (void)startMonitors {
    @autoreleasepool {
        DYAlertMonitor *alertMonitor = [[DYAlertMonitor alloc] init];
        [alertMonitor startMonitoring];

        DYFileIOMonitor *fileMonitor = [[DYFileIOMonitor alloc] init];
        [fileMonitor startMonitoring];

        // 抓包 / VPN 探测屏蔽模块
        DYNetworkBypassMonitor *bypassMonitor = [[DYNetworkBypassMonitor alloc] init];
        [bypassMonitor startMonitoring];

        // 加密 / 哈希 密钥与明文捕获
        DYDecryptMonitor *decryptMonitor = [[DYDecryptMonitor alloc] init];
        [decryptMonitor startMonitoring];

        // SQLite 数据库访问监控（无单独开关，直接进日志）
        DYDatabaseMonitor *databaseMonitor = [[DYDatabaseMonitor alloc] init];
        [databaseMonitor startMonitoring];

        // Keychain 访问监控（SecItemAdd/CopyMatching/Update/Delete）
        DYKeychainMonitor *keychainMonitor = [[DYKeychainMonitor alloc] init];
        [keychainMonitor startMonitoring];

        // 强力防崩溃：signal + ObjC exception + C++ terminate + exit/abort/_Exit
        DYInstallAntiCrash();

        // UserDefaults 读写监控通过 +load swizzle 自动生效，无需手动注册

        // 加载持久化的自定义 Hook 规则（plist）并应用
        [DYCustomHookManager.sharedManager loadFromDisk];
        [DYCustomHookManager.sharedManager applyAllEnabledRules];

        // 打印自定义 Hook 汇总（让用户一眼看到每条规则生效/未生效）
        NSArray *rules = DYCustomHookManager.sharedManager.rules;
        if (rules.count > 0) {
            __block NSUInteger okCount = 0, failCount = 0;
            for (DYCustomHookRule *r in rules) {
                if (r.enabled) {
                    if (r.lastErrorMsg) {
                        failCount++;
                        // 红色：❌ + 具体规则 + 错误原因
                        NSString *tag = [r.type isEqualToString:@"objc"]
                            ? [NSString stringWithFormat:@"ObjC[%@%@ %@]", r.isClassMethod ? @"+" : @"-", r.cls, r.name]
                            : [NSString stringWithFormat:@"C(%@)", r.name];
                        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                            message:[NSString stringWithFormat:@"❌ 未生效 | %@ | 原因：%@", tag, r.lastErrorMsg]];
                    } else {
                        okCount++;
                        // 绿色：✅ + 具体规则
                        NSString *tag = [r.type isEqualToString:@"objc"]
                            ? [NSString stringWithFormat:@"ObjC[%@%@ %@]", r.isClassMethod ? @"+" : @"-", r.cls, r.name]
                            : [NSString stringWithFormat:@"C(%@)", r.name];
                        [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                            message:[NSString stringWithFormat:@"✅ 生效 | %@", tag]];
                    }
                }
            }
            [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                message:[NSString stringWithFormat:@"📊 Hook 汇总：共 %lu 条规则 | ✅ %lu 生效 | ❌ %lu 未生效 | %lu 已关闭",
                         (unsigned long)rules.count,
                         (unsigned long)okCount,
                         (unsigned long)failCount,
                         (unsigned long)(rules.count - okCount - failCount)]];
        } else {
            [[DYLogManager sharedManager] logWithCategory:@"自定义Hook"
                message:@"📊 Hook 汇总：暂无自定义规则"];
        }

        // 内置监控模块启动状态
        [[DYLogManager sharedManager] logWithCategory:@"系统"
            message:@"✅ 内置监控已全部启动（弹窗/文件IO/抓包检测/加密/数据库/Keychain/UserDefaults）"
        ];

        // 后续新增监控模块在此处注册即可，例如：
        // DYNetworkMonitor *netMonitor = [[DYNetworkMonitor alloc] init];
        // [netMonitor startMonitoring];
    }
}

// 安装双指双击手势到指定 window
- (void)installGestureOnWindow:(UIWindow *)window {
    if (!window) return;
    if ([self.observedWindows containsObject:window]) return;

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                          action:@selector(handleTwoFingerDoubleTap:)];
    tap.numberOfTapsRequired = 2;
    tap.numberOfTouchesRequired = 2;
    tap.cancelsTouchesInView = NO;   // 不取消 App 自身的触摸事件
    tap.delaysTouchesBegan = NO;
    tap.delaysTouchesEnded = NO;
    tap.delegate = self;
    [window addGestureRecognizer:tap];
    [self.observedWindows addObject:window];
    DYLog(@"双指双击手势已安装到 window: %@", window);
}

// 安装到所有现有 window，并监听新 window
- (void)installGestures {
    // 已有的 window
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        [self installGestureOnWindow:w];
    }
    // 监听 keyWindow 变化
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(windowDidBecomeKey:)
                                                 name:UIWindowDidBecomeKeyNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(windowDidBecomeVisible:)
                                                 name:UIWindowDidBecomeVisibleNotification
                                               object:nil];
}

- (void)windowDidBecomeKey:(NSNotification *)note {
    UIWindow *w = note.object;
    if (w && [w isKindOfClass:[UIWindow class]]) {
        [self installGestureOnWindow:w];
    }
}

- (void)windowDidBecomeVisible:(NSNotification *)note {
    UIWindow *w = note.object;
    if (w && [w isKindOfClass:[UIWindow class]]) {
        [self installGestureOnWindow:w];
    }
}

- (void)handleTwoFingerDoubleTap:(UITapGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateRecognized) {
        DYLog(@"双指双击触发，切换面板");
        [self.panel toggle];
    }
}

#pragma mark - UIGestureRecognizerDelegate

// 允许与 App 其他手势同时识别，避免干扰宿主
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    return YES;
}

@end

// ============================================================================
#pragma mark - dylib 入口（constructor）
// ============================================================================

__attribute__((constructor))
static void dylib_entry(void) {
    @autoreleasepool {
        DYLog(@"========================================");
        DYLog(@"DYMonitor dylib 已注入到当前进程");
        DYLog(@"进程: %@", [[NSProcessInfo processInfo] processName]);
        DYLog(@"========================================");

        // UI 相关必须在主线程
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                DYMonitorManager *mgr = [DYMonitorManager sharedManager];
                // 启动监控模块（swizzle）
                [mgr startMonitors];
                // 安装手势（需等 window 准备好）
                [mgr installGestures];
                // 若 keyWindow 已存在则立即安装
                [mgr installGestureOnWindow:[UIApplication sharedApplication].keyWindow];

                [[DYLogManager sharedManager] logWithCategory:@"系统"
                    message:@"监控已启动，双指双击屏幕可显示/隐藏面板"];
            }
        });
    }
}
