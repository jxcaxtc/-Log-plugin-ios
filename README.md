# 应用助手 2.0（iOS 进程内行为监控 dylib）

> ⚠️ 仅供本地安全研究与学习使用，禁止违规分发，严禁用于绕过任何官方校验、侵犯他人合法权益或从事任何违反法律法规的行为。使用者需自行承担一切法律责任。

一个独立的 iOS 进程内行为监控 dylib。通过 Hook 宿主 App 的弹窗、文件 IO、Keychain、UserDefaults、加密、数据库等 API，实时捕获 App 的运行时行为，并以悬浮面板形式展示。

- 构建方式：**Theos + library.mk**
- 实现方式：纯 **Objective-C runtime method swizzle** + **fishhook（GOT 符号重绑定）**
- 进程边界：仅作用于当前注入的宿主 App 进程（进程内 Hook，无法跨进程）
- 越狱 / 非越狱均可：普通开发者签名 + `insert_dylib` 侧载即可运行

---

## ✨ 功能总览

| 分类 | 功能 | 说明 |
|---|---|---|
| **触发方式** | 双指双击 | 在 App 任意界面双指双击呼出/隐藏悬浮监控面板 |
| **弹窗监控** | `UIAlertController` / `UIActionSheet` / 自定义 UIView 弹窗 / 独立 Window 弹窗 | 全局 hook `UIView.addSubview:` + `presentViewController:` + `makeKeyAndVisible`，5 维启发式识别弹窗，输出调用类、目标类、类型、标题、消息、按钮文本 |
| **文件 IO** | 读取 / 写入 / 创建 / 删除 / 移动 / 复制 | 监控 `NSFileManager`、`NSData`、`NSString` 的文件操作 |
| **Keychain** | `SecItemAdd` / `SecItemCopyMatching` / `SecItemUpdate` / `SecItemDelete` | 记录具体的查询条件、新增/更新的键值 |
| **UserDefaults** | `objectForKey:` / `setObject:forKey:` / `removeObjectForKey:` | 监控读写的 key 和 value |
| **加密捕获** | `CCCrypt` / `CC_SHA*` / `CC_MD*` / `SecRandomCopyBytes` 等 | 捕获加密前后的明文、密钥、哈希输入 |
| **数据库** | `sqlite3_exec` / `sqlite3_prepare*` / `sqlite3_open` | 记录 SQL 语句和数据库路径 |
| **抓包/VPN 探测屏蔽** | 篡改 `NWPath` / `CFNetworkCopySystemProxySettings` 返回值 | 欺骗 App 的本地抓包检测，可在面板开关控制 |
| **自定义 Hook** | ObjC 方法 swizzle + C 函数 fishhook + plist 持久化 + JSON 导入导出 | 用户可自定义 hook 任意 ObjC 方法（支持 0-2 参数）或 C 函数，启动时逐条输出 ✅ 生效 / ❌ 未生效 + 错误原因 |
| **彩色日志** | ✅ 绿 / ❌ 红 / ⚠️ 黄 / 弹窗蓝 / 加密紫 / 数据库青 | 根据日志前缀 emoji 自动着色 |
| **深浅色适配** | 全系统动态色 + `traitCollectionDidChange` 刷新 | 面板、日志区、边框、阴影全部跟随系统外观 |
| **日志管理** | 100ms 批量节流 + O(1) 增量追加 + 行数上限保护（默认 3000，用户可自定义 100-50000） | 高频日志不 OOM、不卡顿 |
| **导出** | `UIDocumentPickerViewController` | 一键导出全部日志为 `.txt` 到 iCloud / 本机 |
| **全局总开关** | 设置页顶部 | 关闭后所有日志直接短路，Hook 仍正常运行 |

---

## 🖼 界面

- **主界面（悬浮面板）**：顶部搜索框 + 日志实时滚动区 + 底部「保存日志 / 清空」按钮 + 右上角「设置」入口
- **设置页（全屏 iOS Settings 风格）**：全局总开关 / 拦截抓包 / 加密捕获 / 只看加密 / Keychain / UserDefaults / 日志行数 / 自定义 Hook / 关于应用
- **关于弹窗（半屏 Sheet）**：从底部弹出，展示版本号、功能说明
- **自定义 Hook 管理页**：增删改规则、导入导出 JSON、逐条显示 ✅/❌ 生效状态

---

## 📦 项目结构

```
.
├── Test.m                      # 全部源码（单文件，约 3000 行）
├── fishhook.h / fishhook.c     # Facebook fishhook（BSD 协议，GOT 符号重绑定）
├── Makefile                    # Theos 构建配置，TARGET := iphone:clang:latest:17.0
├── control                     # Theos 包元信息
└── .github/workflows/build.yml # GitHub Actions CI 自动编译
```

支持架构：`arm64` / `arm64e`
最低系统版本：**iOS 17.0**

---

## 🔨 构建

### GitHub Actions（推荐）

推送代码到 `main` 分支自动触发构建。在 Actions 页面下载 `Test.dylib` artifact 即可。

### 本地构建（macOS + Theos）

```bash
# 安装 Theos（参考 https://theos.dev/docs/installation）
export THEOS="$HOME/theos"

# 编译
make clean
make
```

产物路径：`.theos/obj/debug/arm64/Test.dylib`

---

## 📲 注入 App（非越狱）

```bash
# 1. 将 dylib 嵌入 App 二进制
insert_dylib --weak --inplace @executable_path/Test.dylib <App可执行文件>

# 2. 将 Test.dylib 放入 .app bundle（与可执行文件同目录）

# 3. 用普通开发者证书重签整个 App
codesign -f -s "Apple Development: xxx" --all-encrypted=<App.app>

# 4. 通过 AltStore / Sideloadly / TrollStore 等工具安装到设备
```

---

## 🎯 使用

1. 注入并安装 App
2. 启动 App，**双指双击**屏幕任意位置 → 弹出悬浮面板
3. 面板实时滚动显示宿主 App 行为日志
4. 点击右上角 ⚙️ 进入设置页：
   - 开关各项监控模块
   - 设置日志行数上限
   - 进入「自定义 Hook」添加自己的 hook 规则
5. 需要时点击「保存日志」导出

### 自定义 Hook 规则格式（JSON 导入导出）

```json
[
  {
    "type": "objc",
    "cls": "NSUserDefaults",
    "name": "objectForKey:",
    "isClassMethod": false,
    "enabled": true
  },
  {
    "type": "c",
    "name": "SecItemAdd",
    "enabled": true
  }
]
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `type` | string | `"objc"`（ObjC 方法）或 `"c"`（C 函数） |
| `cls` | string | ObjC 类名（仅 type=objc 需要） |
| `name` | string | ObjC 方法签名或 C 函数名 |
| `isClassMethod` | bool | ObjC: `true` = +方法，`false` = -方法 |
| `enabled` | bool | 是否启用 |

> ObjC hook 支持 **0–2 个参数**的方法（即 `numberOfArguments` ≤ 4 含 self 和 _cmd）。
> C hook 当前只做 `dlsym` 符号存在性确认 + 注册记录（因 ARC 下 block→C 函数指针不合法）。

---

## 🔧 技术要点

- **弹窗监控三层拦截**：
  1. `UIViewController.presentViewController:` swizzle（UIAlertController 等标准模态）
  2. `UIView.addSubview:` 全局 swizzle（所有加到任意父视图的自定义弹窗）
  3. `UIWindow.makeKeyAndVisible` swizzle（独立 Window 弹窗）
  - 5 维启发式识别弹窗：superview 是 Window / 类名关键字匹配 / 面积 ≥ 屏幕 20% / zPosition ≥ 999 / 半透明遮罩
  - 条件满足任意 2 条即判定为弹窗
- **fishhook**：GOT 表符号重绑定，用于 C 函数 hook（加密、Keychain、抓包检测等）
- **内存保护**：100ms 批量节流 + `NSMutableAttributedString` 增量追加 + 单条/总条数/显示行数三重上限
- **深色模式**：全系统动态色 + `traitCollectionDidChange` 回调中手动刷新 `layer.borderColor`、`layer.shadowColor` 等静态 CGColor 属性
- **ARC 兼容**：所有 C 函数指针用 C 静态数组存储（ARC 下 ObjC 容器不能存 C 函数指针）；递归 block 改为迭代队列消除 retain cycle

---

## 📄 License

代码仅供安全研究与学习使用，未经作者授权不得用于任何商业或违法场景。
