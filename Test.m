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
#import <mach-o/dyld.h>                    // 符号重绑定
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <string.h>                         // strcmp

// ============================================================================
#pragma mark - 通用宏与工具函数
// ============================================================================

// 统一的 NSLog 前缀，方便在设备控制台过滤
#define DYLog(fmt, ...) NSLog((@"[DYMonitor] " fmt), ##__VA_ARGS__)

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

// ----------------------------------------------------------------------------
// C 函数符号重绑定工具（轻量级 fishhook 实现，仅用系统 API）
// 说明：用于 Hook CFNetworkCopySystemProxySettings 这类 C 函数。
//      原理：遍历所有已加载镜像，找到目标符号的 lazy / non-lazy 指针，
//      将其替换为我们的实现，从而拦截进程内所有调用方。
// ----------------------------------------------------------------------------

typedef struct {
    const char *name;         // 要 hook 的符号名
    void *replacement;        // 替换函数地址
    void **original;          // 保存原函数地址的指针（可为 NULL）
} DYRebinding;

// 查找 section 内的符号指针并替换
static void DYRebindIndirectSymbolPointers(DYRebinding *rebindings, int count,
                                           uint32_t *indirectSymbols,
                                           struct nlist_64 *symtab,
                                           const char *strtab,
                                           void **symbolPointers, uint32_t count2) {
    for (uint32_t i = 0; i < count2; i++) {
        uint32_t indirect = indirectSymbols[i];
        if (indirect == INDIRECT_SYMBOL_ABS || indirect == INDIRECT_SYMBOL_LOCAL) continue;
        uint32_t symIndex = indirect;
        if (symIndex >= (uint32_t)(-1)) continue;
        struct nlist_64 *nl = &symtab[symIndex];
        if (nl->n_un.n_strx == 0) continue;
        const char *name = strtab + nl->n_un.n_strx;
        // 去掉符号前的下划线（C 符号通常带 _ 前缀）
        if (name[0] == '_') name++;
        for (int j = 0; j < count; j++) {
            if (strcmp(name, rebindings[j].name) == 0) {
                void *oldFunc = symbolPointers[i];
                if (rebindings[j].original) *rebindings[j].original = oldFunc;
                symbolPointers[i] = rebindings[j].replacement;
            }
        }
    }
}

// 处理单个镜像的符号重绑定
static void DYProcessImage(struct mach_header_64 *header, intptr_t slide,
                           DYRebinding *rebindings, int count) {
    struct segment_command_64 *linkeditSeg = NULL;
    struct symtab_command *symtabCmd = NULL;
    struct dysymtab_command *dysymtabCmd = NULL;

    uint8_t *ptr = (uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)ptr;
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)ptr;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkeditSeg = seg;
            }
        } else if (cmd->cmd == LC_SYMTAB) {
            symtabCmd = (struct symtab_command *)ptr;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtabCmd = (struct dysymtab_command *)ptr;
        }
        ptr += cmd->cmdsize;
    }

    if (!linkeditSeg || !symtabCmd || !dysymtabCmd) return;

    uint8_t *linkeditBase = (uint8_t *)header + slide + linkeditSeg->fileoff - linkeditSeg->vmaddr;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkeditBase + symtabCmd->symoff);
    const char *strtab = (const char *)(linkeditBase + symtabCmd->stroff);
    uint32_t *indirectSymtab = (uint32_t *)(linkeditBase + dysymtabCmd->indirectsymoff);

    // 遍历所有 section，找 lazy / non-lazy / got 符号指针表
    ptr = (uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)ptr;
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)ptr;
            struct section_64 *sect = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if ((sect[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sect[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
                    (sect[j].flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                    void **symbolPointers = (void **)((uint8_t *)header + slide + sect[j].addr);
                    uint32_t count2 = sect[j].size / sizeof(void *);
                    uint32_t *indirect = &indirectSymtab[sect[j].reserved1];
                    if ((sect[j].flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                        count2 = sect[j].size / sect[j].reserved2;
                    }
                    DYRebindIndirectSymbolPointers(rebindings, count, indirect,
                                                   symtab, strtab, symbolPointers, count2);
                }
            }
        }
        ptr += cmd->cmdsize;
    }
}

// 对所有已加载镜像执行重绑定
static void DYRebindSymbols(DYRebinding *rebindings, int count) {
    // 先对已有镜像执行
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (header->magic == MH_MAGIC_64) {
            DYProcessImage((struct mach_header_64 *)header, slide, rebindings, count);
        }
    }
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
    dispatch_queue_t _queue; // 串行队列，保证线程安全
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
        _queue = dispatch_queue_create("com.dymonitor.logqueue", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)logWithCategory:(NSString *)category message:(NSString *)message {
    if (!message) return;
    NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@",
                      DYTimestampString(), category ?: @"未知", message];
    // 同步到串行队列
    dispatch_async(_queue, ^{
        @autoreleasepool {
            [self->_logs addObject:line];
            // 限制最多保留 5000 条，避免内存无限增长
            if (self->_logs.count > 5000) {
                [self->_logs removeObjectsInRange:NSMakeRange(0, self->_logs.count - 5000)];
            }
            NSString *copiedLine = [line copy];
            // UI 刷新必须在主线程
            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSNotificationCenter defaultCenter] postNotificationName:DYLogDidUpdateNotification
                                                                    object:nil
                                                                  userInfo:@{@"line": copiedLine}];
            });
        }
    });
    // 同时输出到 NSLog，方便 Xcode / 设备控制台调试
    DYLog(@"%@", line);
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

        // 3) Hook C 函数 CFNetworkCopySystemProxySettings（符号重绑定）
        DYRebinding rebindings[] = {
            { "CFNetworkCopySystemProxySettings",
              (void *)DYHookedCFNetworkCopySystemProxySettings,
              (void **)&DYOriginalCFNetworkCopySystemProxySettings },
        };
        DYRebindSymbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
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
#pragma mark - 悬浮监控面板
// ============================================================================

// 自定义 UIWindow：只有命中 panelView 区域时才捕获触摸，其余事件透传给 App
@interface DYPanelWindow : UIWindow
@property (nonatomic, weak) UIView *panelView;
@end

@implementation DYPanelWindow

- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    if (!self.panelView) return NO;
    CGPoint localPoint = [self.panelView convertPoint:point fromView:nil];
    return [self.panelView pointInside:localPoint withEvent:event];
}

@end

// ----------------------------------------------------------------------------
@interface DYFloatingPanel : UIView <UITextViewDelegate, UIDocumentPickerDelegate, UIGestureRecognizerDelegate>
@property (nonatomic, strong) UITextView *logTextView;
@property (nonatomic, strong) UIButton *saveButton;
@property (nonatomic, strong) UIButton *clearButton;
@property (nonatomic, strong) UIButton *closeButton;
@property (nonatomic, strong) UIButton *bypassToggleButton; // 抓包检测拦截开关
@property (nonatomic, strong) DYPanelWindow *panelWindow;
@property (nonatomic, assign) BOOL isVisible;
@property (nonatomic, strong) UILongPressGestureRecognizer *longPressGesture; // 长按拖动
@property (nonatomic, assign) CGPoint initialTouchPoint; // 长按时手指相对面板左上角的偏移量
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
    self.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
    self.layer.cornerRadius = 12.0;
    self.layer.borderWidth = 1.0;
    self.layer.borderColor = [[UIColor grayColor] colorWithAlphaComponent:0.5].CGColor;
    self.clipsToBounds = YES;

    // 标题栏（长按此区域可拖动面板）
    UIView *titleBar = [[UIView alloc] init];
    titleBar.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
    titleBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:titleBar];

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text = @"行为监控面板";
    titleLabel.textColor = [UIColor whiteColor];
    titleLabel.font = [UIFont boldSystemFontOfSize:14];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [titleBar addSubview:titleLabel];

    // 关闭按钮
    self.closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.closeButton setTitle:@"✕" forState:UIControlStateNormal];
    [self.closeButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.closeButton.titleLabel.font = [UIFont systemFontOfSize:16];
    self.closeButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.closeButton addTarget:self action:@selector(handleClose) forControlEvents:UIControlEventTouchUpInside];
    [titleBar addSubview:self.closeButton];

    // 日志显示区（可滚动）
    self.logTextView = [[UITextView alloc] init];
    self.logTextView.editable = NO;
    self.logTextView.scrollEnabled = YES;
    self.logTextView.backgroundColor = [UIColor clearColor];
    self.logTextView.textColor = [UIColor colorWithRed:0.4 green:1.0 blue:0.4 alpha:1.0];
    self.logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logTextView.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:self.logTextView];

    // 保存按钮
    self.saveButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.saveButton setTitle:@"保存日志" forState:UIControlStateNormal];
    [self.saveButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.saveButton.backgroundColor = [UIColor colorWithRed:0.0 green:0.5 blue:1.0 alpha:1.0];
    self.saveButton.layer.cornerRadius = 6.0;
    self.saveButton.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    self.saveButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.saveButton addTarget:self action:@selector(handleSave) forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:self.saveButton];

    // 清空按钮
    self.clearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.clearButton setTitle:@"清空" forState:UIControlStateNormal];
    [self.clearButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.clearButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1.0];
    self.clearButton.layer.cornerRadius = 6.0;
    self.clearButton.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    self.clearButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.clearButton addTarget:self action:@selector(handleClear) forControlEvents:UIControlEventTouchUpInside];
    [self addSubview:self.clearButton];

    // 抓包检测拦截开关按钮（默认开启，绿色=开，灰色=关）
    self.bypassToggleButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.bypassToggleButton.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    self.bypassToggleButton.layer.cornerRadius = 6.0;
    self.bypassToggleButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.bypassToggleButton addTarget:self action:@selector(handleBypassToggle) forControlEvents:UIControlEventTouchUpInside];
    [self updateBypassToggleAppearance];
    [self addSubview:self.bypassToggleButton];

    // Auto Layout
    [NSLayoutConstraint activateConstraints:@[
        // titleBar
        [titleBar.topAnchor constraintEqualToAnchor:self.topAnchor],
        [titleBar.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
        [titleBar.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        [titleBar.heightAnchor constraintEqualToConstant:36],

        [titleLabel.leadingAnchor constraintEqualToAnchor:titleBar.leadingAnchor constant:12],
        [titleLabel.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],

        [self.closeButton.trailingAnchor constraintEqualToAnchor:titleBar.trailingAnchor constant:-8],
        [self.closeButton.centerYAnchor constraintEqualToAnchor:titleBar.centerYAnchor],
        [self.closeButton.widthAnchor constraintEqualToConstant:32],
        [self.closeButton.heightAnchor constraintEqualToConstant:32],

        // logTextView
        [self.logTextView.topAnchor constraintEqualToAnchor:titleBar.bottomAnchor constant:4],
        [self.logTextView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:6],
        [self.logTextView.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-6],
        [self.logTextView.bottomAnchor constraintEqualToAnchor:self.bypassToggleButton.topAnchor constant:-6],

        // bypassToggleButton（抓包检测拦截开关，独占一行）
        [self.bypassToggleButton.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:10],
        [self.bypassToggleButton.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-10],
        [self.bypassToggleButton.bottomAnchor constraintEqualToAnchor:self.saveButton.topAnchor constant:-8],
        [self.bypassToggleButton.heightAnchor constraintEqualToConstant:30],

        // saveButton
        [self.saveButton.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:10],
        [self.saveButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-10],
        [self.saveButton.heightAnchor constraintEqualToConstant:34],
        [self.saveButton.trailingAnchor constraintEqualToAnchor:self.clearButton.leadingAnchor constant:-8],

        // clearButton
        [self.clearButton.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-10],
        [self.clearButton.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-10],
        [self.clearButton.heightAnchor constraintEqualToConstant:34],
        [self.clearButton.widthAnchor constraintEqualToAnchor:60],
        [self.saveButton.widthAnchor constraintEqualToAnchor:self.clearButton.widthAnchor],
    ]];

    // 长按拖动手势（长按标题栏后可拖动整个面板，避免误触）
    self.longPressGesture = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPressDrag:)];
    self.longPressGesture.minimumPressDuration = 0.2; // 长按 0.2 秒触发
    self.longPressGesture.allowableMovement = 15.0;   // 允许轻微移动
    self.longPressGesture.delegate = self;
    [titleBar addGestureRecognizer:self.longPressGesture];

    // 监听日志更新通知
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onLogUpdate:)
                                                 name:DYLogDidUpdateNotification
                                               object:nil];
}

- (void)onLogUpdate:(NSNotification *)note {
    NSDictionary *userInfo = note.userInfo;
    if ([userInfo[@"clear"] boolValue]) {
        self.logTextView.text = @"";
        return;
    }
    NSString *line = userInfo[@"line"];
    if (!line) return;
    NSString *current = self.logTextView.text ?: @"";
    NSString *newText = current.length > 0
        ? [NSString stringWithFormat:@"%@\n%@", current, line]
        : line;
    self.logTextView.text = newText;
    // 自动滚动到底部
    NSRange bottom = NSMakeRange(newText.length - 1, 1);
    [self.logTextView scrollRangeToVisible:bottom];
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
    CGFloat panelH = MAX(screenBounds.size.width, screenBounds.size.height) * 0.38;

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

// 抓包检测拦截开关：切换全局 gBypassEnabled，并刷新按钮外观
- (void)handleBypassToggle {
    gBypassEnabled = !gBypassEnabled;
    [self updateBypassToggleAppearance];
    [[DYLogManager sharedManager] logWithCategory:@"系统"
        message:[NSString stringWithFormat:@"抓包检测拦截已%@", gBypassEnabled ? @"开启" : @"关闭"]];
}

// 根据开关状态刷新按钮标题与颜色
- (void)updateBypassToggleAppearance {
    NSString *title = [NSString stringWithFormat:@"拦截应用检测抓包：%@", gBypassEnabled ? @"开" : @"关"];
    [self.bypassToggleButton setTitle:title forState:UIControlStateNormal];
    if (gBypassEnabled) {
        self.bypassToggleButton.backgroundColor = [UIColor colorWithRed:0.0 green:0.6 blue:0.2 alpha:1.0];
    } else {
        self.bypassToggleButton.backgroundColor = [UIColor colorWithRed:0.4 green:0.4 blue:0.4 alpha:1.0];
    }
    [self.bypassToggleButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
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
