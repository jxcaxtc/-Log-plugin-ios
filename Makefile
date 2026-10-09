# ============================================================================
# Theos Makefile —— 行为监控 dylib
# 构建产物：libTest.dylib（仅编译 dylib，不打包 deb）
# 构建方式：make          —— 编译生成 libTest.dylib
#           make package  —— 不可用（无 control 文件，本项目不产出 deb）
# ============================================================================

# 目标平台：iOS，使用 clang，最低支持 iOS 17.0
TARGET := iphone:clang:latest:17.0

# 架构：覆盖现代 iOS 设备
ARCHS = arm64 arm64e

# 引入 Theos 通用配置
include $(THEOS)/makefiles/common.mk

# 库名称（最终产物 libTest.dylib）
LIBRARY_NAME = Test

# 源文件（fishhook.c 是纯 C，-fobjc-arc 对 .c 文件无影响）
Test_FILES = Test.m fishhook.c

# 编译参数
#   -fobjc-arc              : 启用 ARC
#   -Wno-deprecated-declarations : 忽略 UIActionSheet 等废弃 API 警告
Test_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

# 链接框架（CommonCrypto 是系统 TBD 库，放 LIBRARIES 不是 FRAMEWORKS）
Test_FRAMEWORKS = UIKit Foundation Network CFNetwork
# sqlite3 + CommonCrypto 都是 lib*.tbd，作为系统库链接
Test_LIBRARIES = sqlite3 commoncrypto

# -lobjc 是 Theos 默认链接的，不用重复指定

# 引入 library.mk 规则
include $(THEOS_MAKE_PATH)/library.mk
