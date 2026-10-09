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
    // 防止单条日志过长（比如大 SQL 或密文 hex 几百行）
    NSString *trimmed = message.length > 5000 ? [[message substringToIndex:5000] stringByAppendingFormat:@"...(truncated from %lu chars)", (unsigned long)message.length] : message;
    NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@",
                      DYTimestampString(), category ?: @"未知", trimmed];
    dispatch_async(_queue, ^{
        @autoreleasepool {
            [self->_logs addObject:line];
            [self->_pending addObject:line];
            // 总日志上限 5000 条，超过删前 1000 条（避免频繁内存重分配）
            if (self->_logs.count > 5000) {
                [self->_logs removeObjectsInRange:NSMakeRange(0, 1000)];
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

        // 3) 自定义 UIView 弹窗：拦截 UIWindow 的 addSubview:，
        //    通过类名启发式判断是否为弹窗类视图。
        DYSwizzleInstanceMethod([UIWindow class],
                                @selector(addSubview:),
                                @selector(dy_addSubview:));
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

        // 提取弹窗信息
        NSString *vcClass = NSStringFromClass([viewControllerToPresent class]);
        NSMutableString *detail = [NSMutableString string];
        [detail appendFormat:@"present VC: %@", vcClass];

        if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
            UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
            [detail appendString:@" | 类型: UIAlertController"];
            if (alert.title.length > 0) [detail appendFormat:@" | title: %@", alert.title];
            if (alert.message.length > 0) [detail appendFormat:@" | message: %@", alert.message];
            NSMutableArray *titles = [NSMutableArray array];
            for (UIAlertAction *action in alert.actions) {
                if (action.title) [titles addObject:action.title];
            }
            if (titles.count > 0) {
                [detail appendFormat:@" | actions: [%@]", [titles componentsJoinedByString:@", "]];
            }
        } else {
            [detail appendString:@" | 类型: 模态 VC（可能是自定义弹窗）"];
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
// UIWindow (DYAlertMonitor) —— 识别自定义 UIView 弹窗
// ----------------------------------------------------------------------------
@interface UIWindow (DYAlertMonitor)
- (void)dy_addSubview:(UIView *)view;
@end

@implementation UIWindow (DYAlertMonitor)

// 启发式：类名包含这些关键字的子视图，判定为"自定义 UIView 弹窗"
static BOOL DYIsAlertLikeViewClass(Class cls) {
    if (!cls) return NO;
    NSString *name = NSStringFromClass(cls);
    if (name.length == 0) return NO;
    NSArray<NSString *> *keywords = @[
        @"Alert", @"Popup", @"Dialog", @"Toast", @"HUD", @"Menu",
        @"Sheet", @"Popover", @"Bubble", @"Tip", @"Notice",
        @"alert", @"popup", @"dialog", @"toast", @"hud", @"menu",
        @"sheet", @"popover"
    ];
    for (NSString *kw in keywords) {
        if ([name containsString:kw]) return YES;
    }
    // 遍历父类链
    Class superCls = class_getSuperclass(cls);
    if (superCls && superCls != [UIView class] && superCls != [NSObject class]) {
        return DYIsAlertLikeViewClass(superCls);
    }
    return NO;
}

- (void)dy_addSubview:(UIView *)view {
    @autoreleasepool {
        // 先调用原实现
        [self dy_addSubview:view];

        // 过滤掉系统自身的视图（如 UIWindow 内的 UIStatusBar、UIRemoteView 等）
        if (!view) return;
        NSString *clsName = NSStringFromClass([view class]);
        if ([clsName hasPrefix:@"_"]) return; // 跳过私有视图

        if (DYIsAlertLikeViewClass([view class])) {
            // 提取文本内容：遍历子视图，找出所有 UILabel / UITextView 的文本
            NSMutableString *texts = [NSMutableString string];
            for (UIView *sub in [view subviews]) {
                if ([sub isKindOfClass:[UILabel class]]) {
                    UILabel *lbl = (UILabel *)sub;
                    if (lbl.text.length > 0) {
                        if (texts.length > 0) [texts appendString:@" | "];
                        [texts appendString:lbl.text];
                    }
                } else if ([sub isKindOfClass:[UITextView class]]) {
                    UITextView *tv = (UITextView *)sub;
                    if (tv.text.length > 0) {
                        if (texts.length > 0) [texts appendString:@" | "];
                        [texts appendString:tv.text];
                    }
                }
            }
            NSString *msg = [NSString stringWithFormat:@"自定义UIView弹窗: %@ | 文本: %@",
                             clsName, texts.length > 0 ? texts : @"(无)"];
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

// 辅助：创建一个 iOS Settings 风格的行容器（左边 label + 右边 switch）
- (UIView *)makeSwitchRowWithTitle:(NSString *)title
                            target:(id)target
                            action:(SEL)action
                         switchOn:(BOOL)on
                       dividerTop:(BOOL)divTop
                    dividerBottom:(BOOL)divBottom {
    UIView *row = [[UIView alloc] init];
    row.backgroundColor = [UIColor whiteColor];
    row.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *label = [[UILabel alloc] init];
    label.text = title;
    // Settings 行标准字号 15pt，labelColor
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor labelColor];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [row addSubview:label];

    UISwitch *sw = [[UISwitch alloc] init];
    sw.on = on;
    // 不指定 onTintColor，用系统默认（iOS 原生绿色）
    sw.translatesAutoresizingMaskIntoConstraints = NO;
    [sw addTarget:target action:action forControlEvents:UIControlEventValueChanged];
    [row addSubview:sw];

    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:16],
        [label.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [sw.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-16],
        [sw.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [row.heightAnchor constraintEqualToConstant:44],
    ]];

    // 顶部分割线
    if (divTop) {
        UIView *topSep = [[UIView alloc] init];
        topSep.backgroundColor = [UIColor colorWithWhite:0.9 alpha:1.0];
        topSep.translatesAutoresizingMaskIntoConstraints = NO;
        [row addSubview:topSep];
        [NSLayoutConstraint activateConstraints:@[
            [topSep.topAnchor constraintEqualToAnchor:row.topAnchor],
            [topSep.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:16],
            [topSep.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
            [topSep.heightAnchor constraintEqualToConstant:0.5],
        ]];
    }
    // 底部分割线
    if (divBottom) {
        UIView *botSep = [[UIView alloc] init];
        botSep.backgroundColor = [UIColor colorWithWhite:0.9 alpha:1.0];
        botSep.translatesAutoresizingMaskIntoConstraints = NO;
        [row addSubview:botSep];
        [NSLayoutConstraint activateConstraints:@[
            [botSep.bottomAnchor constraintEqualToAnchor:row.bottomAnchor],
            [botSep.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:16],
            [botSep.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
            [botSep.heightAnchor constraintEqualToConstant:0.5],
        ]];
    }

    return row;
}

- (void)setupUI {
    // 整体：iOS Settings 风格卡片
    self.backgroundColor = [UIColor colorWithWhite:0.94 alpha:1.0]; // systemGroupedBackground
    self.layer.cornerRadius = 14.0;
    self.clipsToBounds = NO;
    self.layer.shadowColor = [UIColor blackColor].CGColor;
    self.layer.shadowOpacity = 0.12;
    self.layer.shadowOffset = CGSizeMake(0, 2);
    self.layer.shadowRadius = 10.0;

    // 标题栏
    UIView *titleBar = [[UIView alloc] init];
    titleBar.backgroundColor = [UIColor clearColor];
    titleBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:titleBar];

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text = @"太平长安-应用助手1.0";
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

    // 三个开关横向并排（放到 logTextView 之后创建）
    UIStackView *switchStack = [[UIStackView alloc] init];
    switchStack.axis = UILayoutConstraintAxisHorizontal;
    switchStack.distribution = UIStackViewDistributionFillEqually;
    switchStack.alignment = UIStackViewAlignmentTop;
    switchStack.spacing = 8;
    switchStack.translatesAutoresizingMaskIntoConstraints = NO;
    // 整体缩小到 85%
    switchStack.transform = CGAffineTransformMakeScale(0.85, 0.85);
    [self addSubview:switchStack];

    UIView * (^makeSwitch)(NSString *, SEL, BOOL) = ^(NSString *title, SEL action, BOOL on) {
        UIView *col = [[UIView alloc] init];
        col.translatesAutoresizingMaskIntoConstraints = NO;

        UISwitch *sw = [[UISwitch alloc] init];
        sw.on = on;
        sw.translatesAutoresizingMaskIntoConstraints = NO;
        [sw addTarget:self action:action forControlEvents:UIControlEventValueChanged];
        [col addSubview:sw];

        UILabel *lb = [[UILabel alloc] init];
        lb.text = title;
        lb.font = [UIFont systemFontOfSize:17];
        lb.textColor = [UIColor labelColor];
        lb.textAlignment = NSTextAlignmentCenter;
        lb.numberOfLines = 1;
        lb.adjustsFontSizeToFitWidth = YES;
        lb.minimumScaleFactor = 0.6;
        lb.translatesAutoresizingMaskIntoConstraints = NO;
        [col addSubview:lb];

        [NSLayoutConstraint activateConstraints:@[
            [sw.topAnchor constraintEqualToAnchor:col.topAnchor],
            [sw.centerXAnchor constraintEqualToAnchor:col.centerXAnchor],
            [lb.topAnchor constraintEqualToAnchor:sw.bottomAnchor constant:4],
            [lb.leadingAnchor constraintEqualToAnchor:col.leadingAnchor],
            [lb.trailingAnchor constraintEqualToAnchor:col.trailingAnchor],
            [col.bottomAnchor constraintEqualToAnchor:lb.bottomAnchor],
        ]];
        return col;
    };

    UIView *col1 = makeSwitch(@"拦截抓包", @selector(handleBypassSwitch:), gBypassEnabled);
    UIView *col2 = makeSwitch(@"加密捕获", @selector(handleDecryptSwitch:), gDecryptMonitorEnabled);
    UIView *col3 = makeSwitch(@"只看加密", @selector(handleFilterSwitch:), gLogFilterKeyOnly);
    [switchStack addArrangedSubview:col1];
    [switchStack addArrangedSubview:col2];
    [switchStack addArrangedSubview:col3];

    // 日志区（全部系统默认：secondaryLabelColor + 系统字体）
    self.logTextView = [[UITextView alloc] init];
    self.logTextView.editable = NO;
    self.logTextView.scrollEnabled = YES;
    self.logTextView.backgroundColor = [UIColor whiteColor];
    self.logTextView.layer.cornerRadius = 10.0;
    self.logTextView.layer.borderWidth = 0.5;
    self.logTextView.layer.borderColor = [UIColor colorWithWhite:0.9 alpha:1.0].CGColor;
    self.logTextView.textColor = [UIColor secondaryLabelColor];
    self.logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logTextView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.logTextView.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:self.logTextView];

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

    // 外层 Auto Layout
    [NSLayoutConstraint activateConstraints:@[
        // titleBar
        [titleBar.topAnchor constraintEqualToAnchor:self.topAnchor constant:12],
        [titleBar.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:16],
        [titleBar.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-16],
        [titleBar.heightAnchor constraintEqualToConstant:28],

        [titleLabel.leadingAnchor constraintEqualToAnchor:titleBar.leadingAnchor],
        [titleLabel.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        [self.closeButton.trailingAnchor constraintEqualToAnchor:titleBar.trailingAnchor],
        [self.closeButton.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        // searchBar
        [searchBar.topAnchor constraintEqualToAnchor:titleBar.bottomAnchor constant:2],
        [searchBar.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:8],
        [searchBar.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-8],

        // logTextView
        [self.logTextView.topAnchor constraintEqualToAnchor:searchBar.bottomAnchor constant:4],
        [self.logTextView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:12],
        [self.logTextView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-12],

        // switchStack（三个开关横排，logTextView 下方）
        [switchStack.topAnchor constraintEqualToAnchor:self.logTextView.bottomAnchor constant:6],
        [switchStack.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:12],
        [switchStack.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-12],
        [switchStack.heightAnchor constraintEqualToConstant:56],

        // saveButton / clearButton
        [self.saveButton.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:24],
        [self.saveButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-12],
        [self.saveButton.heightAnchor constraintEqualToConstant:44],

        [self.clearButton.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-24],
        [self.clearButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-12],
        [self.clearButton.heightAnchor constraintEqualToConstant:44],
        [self.clearButton.widthAnchor constraintEqualToAnchor:self.saveButton.widthAnchor],

        // switchStack 底部 = saveButton 上方（== 锁死）
        [switchStack.bottomAnchor constraintEqualToAnchor:self.saveButton.topAnchor constant:-6],

        // logTextView 底部 = switchStack 顶部 - 6（== 锁死，这样 log 区自动撑满 searchBar 和 switchStack 之间）
        [self.logTextView.bottomAnchor constraintEqualToAnchor:switchStack.topAnchor constant:-6],
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

// logTextView 显示上限：最多保留 3000 行（足够排查问题，又不会爆内存）
#define DYMaxLogLinesInTextView 3000

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
    NSDictionary *attrs = @{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor],
                            NSFontAttributeName: [UIFont fontWithName:@"Menlo" size:11] };
    for (NSUInteger i = 0; i < visible.count; i++) {
        if (attr.length > 0) [attr appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
        [attr appendAttributedString:[[NSAttributedString alloc] initWithString:visible[i] attributes:attrs]];
    }

    // 行数保护：超过 2000 行，删顶部旧文本
    NSString *full = attr.string;
    NSUInteger lineCount = [[full componentsSeparatedByString:@"\n"] count];
    if (lineCount > DYMaxLogLinesInTextView) {
        NSArray *lines = [full componentsSeparatedByString:@"\n"];
        NSArray *tail = [lines subarrayWithRange:NSMakeRange(lines.count - DYMaxLogLinesInTextView, DYMaxLogLinesInTextView)];
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
    if (visible.count > DYMaxLogLinesInTextView) {
        visible = [[visible subarrayWithRange:NSMakeRange(visible.count - DYMaxLogLinesInTextView, DYMaxLogLinesInTextView)] mutableCopy];
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

// 抓包检测拦截 —— UISwitch
- (void)handleBypassSwitch:(UISwitch *)sender {
    gBypassEnabled = sender.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"抓包检测拦截已%@", gBypassEnabled ? @"开启" : @"关闭"]];
}

// 加密/哈希 明文捕获 —— UISwitch
- (void)handleDecryptSwitch:(UISwitch *)sender {
    gDecryptMonitorEnabled = sender.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"加密/哈希 明文与密钥捕获已%@", gDecryptMonitorEnabled ? @"开启" : @"关闭"]];
}

// 只显示密钥/加密日志 —— UISwitch
- (void)handleFilterSwitch:(UISwitch *)sender {
    gLogFilterKeyOnly = sender.isOn;
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"面板日志过滤：%@", gLogFilterKeyOnly ? @"只显示加密/密钥类" : @"显示全部"]];
    [self applyLogFilter];
}

// 递归获取最顶层的 view controller
- (UIViewController *)topMostViewController {
    UIViewController *rootVC = [UIApplication sharedApplication].keyWindow.rootViewController;
    if (!rootVC) rootVC = [UIApplication sharedApplication].delegate.window.rootViewController;
    UIViewController *topVC = rootVC;
    while (topVC.presentedViewController) {
        topVC = topVC.presentedViewController;
    }
    return topVC;
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
