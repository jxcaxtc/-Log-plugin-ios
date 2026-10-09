# DYMonitor — 进程内行为监控 dylib

> 仅供本地安全研究与学习使用，禁止违规分发，严禁用于绕过任何官方校验、侵犯他人合法权益或从事任何违反法律法规的行为。

一个独立的 iOS dylib，采用 **Theos + library.mk** 构建，纯 Objective-C runtime method swizzle 实现（不依赖 Logos / libhooker / substrate / CydiaSubstrate）。所有逻辑运行在**当前注入的宿主 App 进程内**，属于进程内 Hook，无法跨进程。

## 功能

1. **手势触发**：在 App 任意界面**双指双击**屏幕，呼出/隐藏悬浮监控面板。
2. **悬浮监控面板**（UIView 浮层，常驻最上层）：
   - 实时滚动打印宿主 App 行为日志，带时间戳。
   - **弹窗监控**：区分并标记 `自定义 UIView 弹窗` / `UIAlertController` / `UIActionSheet`，捕获弹窗文本内容。
   - **文件 IO 监控**：捕获文件的读取、创建、写入、删除、移动/重命名、复制，记录完整路径与操作类型。
   - **抓包 / VPN 探测屏蔽**：篡改 `NWPath.usesVirtualInterface`、`NWParameters.prohibitVirtualInterface`、`CFNetworkCopySystemProxySettings` 返回值，欺骗 App 本地抓包/VPN 检测。面板上有【拦截应用检测抓包】开关控制。
   - **拓展预留**：所有监控模块均遵循 `DYMonitor` 协议，新增网络 / XPC / 剪贴板等监控只需实现协议并在 `startMonitors` 中注册。
3. **保存日志**：面板内【保存日志】按钮调用系统 `UIDocumentPickerViewController`（系统自带"文件"App），允许将全部日志导出为 `.txt` 保存到 iCloud / 本机任意位置。

## 约束

- 纯进程内 swizzle，无法监控其他 App。
- 不使用任何私有 entitlement，普通开发者签名 / SideStore 侧载即可运行。
- 全部 `@autoreleasepool` 包裹，避免内存泄露。
- 日志同时输出到 `NSLog`，便于 Xcode / 设备控制台调试。
- 悬浮面板支持屏幕旋转与拖拽。

## 项目结构

```
.
├── Test.m                      # 全部源码（单文件）
├── Makefile                    # Theos 构建配置
├── control                     # Theos 包元信息
└── .github/workflows/build.yml # GitHub Actions 自动编译
```

## 构建

### 本地构建（需 macOS + Theos）

```bash
# 安装 Theos（参考 https://theos.dev/docs/installation）
export THEOS="$HOME/theos"

# 编译
make clean
make
```

产物位于 `.theos/obj/libTest.dylib`。

### GitHub Actions 自动构建

推送代码到 `main` / `master` 分支即触发 `.github/workflows/build.yml`，构建完成后可在 Actions 页面下载 `libTest.dylib` 产物。

## 注入 IPA（insert_dylib）

```bash
# 1. 重签前将 dylib 嵌入 IPA
insert_dylib --weak --inplace @executable_path/libTest.dylib <App二进制>

# 2. 将 libTest.dylib 放入 App bundle（与可执行文件同目录）

# 3. 用普通开发者证书重签整个 App
```

> 通过 `@executable_path` 加载，确保 dylib 随 App 包分发，无需越狱。

## 新增监控模块（拓展）

1. 新建类实现 `<DYMonitor>` 协议：

```objc
@interface DYNetworkMonitor : NSObject <DYMonitor>
@end
```

2. 在 `startMonitoring` 中执行 swizzle。
3. 在 `DYMonitorManager startMonitors` 中注册：

```objc
DYNetworkMonitor *netMonitor = [[DYNetworkMonitor alloc] init];
[netMonitor startMonitoring];
```

日志通过 `[[DYLogManager sharedManager] logWithCategory:@"网络" message:...]` 输出即可自动显示在面板。
