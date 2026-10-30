# mcmac — Minecraft iOS → macOS

将本目录的 `Minecraft_ipa_ios_1.26.13.0.ipa` 制作为 Apple Silicon Mac 可运行的兼容应用。保留原始 IPA；游戏资源和程序不上传。

这是对现有 iOS ARM64 程序进行二进制兼容适配，不是拥有 Minecraft 源码后的重新编译，也不支持 Intel Mac。

## 仓库内容

本仓库只包含移植方法、兼容层源码（`compat/`）、构建脚本（`scripts/`）和测试源码（`tests/`）。不包含 Minecraft 游戏程序、IPA、资源、存档、账号数据或构建后的应用。请自行提供有权使用的 IPA；构建器不提供下载或解密功能，遇到加密的可执行文件会拒绝处理。

## 使用

先克隆仓库，并将自行准备的 `Minecraft_ipa_ios_1.26.13.0.ipa` 放在项目根目录：

```sh
git clone https://github.com/rhotov/mcmac.git
cd mcmac
```

也可以直接指定本地 IPA 路径：

```sh
bash scripts/build.sh /path/to/Minecraft.ipa
```

以下默认命令以根目录中的 IPA 为输入。已验证的版本是 1.26.13.0，其他版本可能需要调整。


构建后的应用位于 `dist/Minecraft.app`。双击打开即可。

重新构建需要 Apple Silicon Mac、Python 3.10 或以上版本和 Xcode Command Line Tools：

```sh
bash scripts/build.sh
```

构建器不会覆盖已有输出。需要另一个输出时：

```sh
bash scripts/build.sh --output dist/Minecraft-rebuilt.app --report build/report-rebuilt.json
```

构建后，构建清单和逐个程序的校验信息位于 `build/report.json`。本机研究产生的静态分析证据不随仓库分发。

只读检查原始 IPA、成品程序哈希及签名：

```sh
python3 scripts/verify_build.py
```

## 适配内容

- 核对安装包路径、ARM64 架构和加密标记。
- 适配 Mac Catalyst 加载平台及系统框架路径。
- 使用本机 Swift 并发运行库。
- 将游戏的通用密码和密钥存储适配到 macOS 加密钥匙串。
- 适配 Xbox 登录库的 RSA／EC 设备密钥生成、持久化和按标签查找／删除，修复登录页出现前的钥匙串权限错误。
- 修复键鼠设备初始化、主事件循环和退出兼容性。
- 统一窗口、游戏画布和指针坐标，并同步窗口缩放。
- 为本地运行重新签名，并启用应用沙盒、联网和用户选取文件访问。

默认构建允许联网。追加 `--offline` 可构建不具备联网权限的版本。

应用保留 `com.mojang.minecraftpe` 标识，存档位于 `~/Library/Containers/com.mojang.minecraftpe/Data/Documents/`。构建器不删除已有存档。

## 验证范围

2026-10-30 在本机 Apple Silicon、macOS 27.2 上验证：启动和重启、主菜单和世界列表、本地世界生成、键盘移动与跳跃、暂停、保存后重启载入，以及窗口／全屏切换。用户已用实体鼠标确认按钮正常且点击位置对齐，并确认实际全屏显示正常。

保留了名为 `MCMac Port Test` 的验证世界。2026-10-30 用户已在修复版中自行完成 Microsoft／Xbox 登录，随后只读检查确认主菜单显示已登录玩家资料，登录按钮消失。登录会话在重启后的恢复、多人联机、Realms 和商店购买尚未验证。

此次 Drowned 故障的直接证据是 Xbox 登录库生成持久设备密钥时返回 `-34018`，并非购买收据验证失败。兼容层补齐 `SecKeyGeneratePair`／`SecKeyCreateRandomKey`，保留真实密钥的签名能力，并通过现有加密钥匙串桥接保存；同时接纳客户端的 `kSecReturnData` 生成元数据及按标签清理密钥的查询。EC／RSA 测试覆盖生成、重载签名、重复项错误、部分失败回滚和按标签查找／删除。不支持的密钥访问控制或硬件令牌语义仍交给原系统 API。

本机实际运行检查记录未随仓库分发，独立于构建报告。`build/report.json` 中的 `runtime_verified` 是构建器输出时的状态，不能代替运行记录。

登录修复前的应用、运行记录和登录诊断记录仅保存在本地，不随仓库分发。本项目未实现不同平台购买凭证的转换或导入。

如需诊断窗口尺寸，可在启动程序时设置环境变量 `MCMAC_DIAGNOSTICS=1`；默认不输出这些尺寸诊断。

## 参考

- [Apple：在 macOS 上运行 iOS 应用](https://developer.apple.com/documentation/apple-silicon/running-your-ios-apps-in-macos)
- [PlayCover 的 Mach-O 兼容转换实现](https://github.com/PlayCover/PlayCover/blob/24bbed786fe1d5acfb0ffc2e619e126bdc09f22b/PlayCover/Utils/Macho.swift)
- [Minecraft macOS 兼容性研究参考](https://github.com/bedrock-mc/mcbe-macos)
- [HyniSign：iOS 侧载客户端的 Xbox 设备密钥登录问题参考](https://github.com/vanhoof/HyniSign)
- [Minecraft：Drowned 登录错误说明](https://help.minecraft.net/hc/en-us/articles/29237699240717)

以上开源项目用于核对兼容策略；本项目的构建不依赖安装 PlayCover。
