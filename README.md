# mcmac — Minecraft iOS → macOS

将本目录的 `MCPE-iOS-26.60-universal.ipa` 制作为 Apple Silicon Mac 可运行的 Minecraft 26.60 兼容应用。保留原始 IPA；游戏资源和程序不上传。

这是对现有 iOS ARM64 程序进行二进制兼容适配，不是拥有 Minecraft 源码后的重新编译，也不支持 Intel Mac。

## 仓库内容

本仓库只包含移植方法、兼容层源码（`compat/`）、构建脚本（`scripts/`）和测试源码（`tests/`）。不包含 Minecraft 游戏程序、IPA、资源、存档、账号数据或构建后的应用。请自行提供有权使用的 IPA；构建器不提供下载或解密功能，遇到加密的可执行文件会拒绝处理。

## 使用

先克隆仓库，并将自行准备的 `MCPE-iOS-26.60-universal.ipa` 放在项目根目录：

```sh
git clone https://github.com/rhotov/mcmac.git
cd mcmac
```

也可以直接指定本地 IPA 路径：

```sh
bash scripts/build.sh /path/to/Minecraft.ipa
```

以下默认命令以根目录中的 `MCPE-iOS-26.60-universal.ipa` 为输入。26.60 已通过构建、输入哈希、签名校验以及启动、主菜单和世界列表检查；多人联机仍待验证，其他版本可能需要调整。

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
- 在游戏控制器处接收已由 GameController 处理的按键，修复键盘操作触发 macOS 错误提示音的问题，保留文字输入和 Command 快捷键。
- 统一窗口、游戏画布和指针坐标，并同步窗口缩放。
- 由游戏渲染器统一调整 Metal 画布尺寸，避免全屏切换误触发设备丢失和纹理／字体重载。
- 为本地运行重新签名，并启用应用沙盒、联网和用户选取文件访问。

默认构建允许联网。追加 `--offline` 可构建不具备联网权限的版本。

应用保留 `com.mojang.minecraftpe` 标识，存档位于 `~/Library/Containers/com.mojang.minecraftpe/Data/Documents/`。构建器不删除已有存档。

## 验证范围

2026-11-04，修复键盘操作时的系统错误提示音。修复前按 `W` 捕获到 `UIApplication pressesBegan:withEvent:` → `UINSInputView forwardUINSEventToAppKit:` → `NSWindow keyDown:` → `NSBeep` 调用栈：游戏的 GameController 输入已生效，但 UIKit 使用默认响应链继续转发同一次按键。兼容层现在只在游戏控制器继承默认响应方法、游戏键盘回调存在且对应按键受支持时接收该事件，不重复调用游戏输入回调；文本输入、模态界面、非活动窗口和 Command 快捷键保持原路径。

修复版已更新到 `dist/Minecraft.app`，通过输入 IPA、8 个程序哈希及深度签名校验。实际运行检查覆盖主菜单按键、本地世界移动、背包、搜索框输入与光标/删除操作、Command-A 全选、Escape 暂停和保存退出；监测期间 `NSBeep` 调用次数为 0。`bash scripts/test_keyboard_routing.sh` 可运行输入边界回归检查。实测使用自动发送的按键，实体键盘和中文输入法组合输入仍需另行验证。本次测试前已备份本地世界；旧应用、存档备份和诊断记录位于 `build/keyboard-diagnosis/`，不随仓库分发。

2026-10-30，26.60（应用版本 `1.26.60`，构建号 `1.26.60.04`）已更新到 `dist/Minecraft.app`，并通过原始 IPA 哈希、8 个程序哈希及应用签名的独立校验。构建启用了联网权限。已验证启动、退出后重启、主菜单显示 `v26.60`、菜单点击、原有世界列表，以及已有 Microsoft／Xbox 登录资料恢复。此次未进入世界，备份中的全部 10 个世界文件与升级后文件的哈希一致。新版游戏内键鼠、世界载入和保存、多人联机、Realms 及商店购买尚未验证。

同日修复 26.60 全屏切换时的画布尺寸竞争：关闭 MTKView 自动调整画布，移除兼容层直接写入 drawableSize 的操作，保留游戏尺寸通知，让渲染器同时更新交换链及其内部尺寸。修复前实测渲染器缓存为 4988×2806、画布已变为 3826×1996，触发 `Swapchain mismatches initialized resolution.` 和资源重建；修复后诊断版三轮全屏往返未出现该错误或重载，抽查的字体／按钮纹理绑定与内容哈希稳定。正式版重新构建后验证了启动和全屏切换，GPU 目标、视口及裁剪尺寸一致，用户确认实际全屏画面正常。自动窗口采集仍出现过留白或缺字的过渡画面，其与真实显示的差异未作完整归因；本次结论限于已确认的尺寸竞争触发路径，不代表所有渲染场景均已验证。

本机对比记录位于 `build/gpu-diagnosis/diagnosis.txt` 和 `build/runtime-validation-gpu-fix.json`。使用运行时绘制调用、纹理绑定及部分纹理像素快照进行对比，未取得可回放的完整异常 GPU 帧。修复前应用保存在 `build/gpu-diagnosis/before-fix/Minecraft.app`，诊断探针不包含在正式应用中。

本机升级前的 26.13 应用、Documents 存档和校验记录保存在 `build/upgrade-backup-26.13-20261030-194919/`，不随仓库分发。独立运行检查保存在 `build/runtime-validation-26.60.json`。

此前 26.13 的运行验证记录：2026-10-30 在本机 Apple Silicon、macOS 27.2 上验证启动和重启、主菜单和世界列表、本地世界生成、键盘移动与跳跃、暂停、保存后重启载入，以及窗口／全屏切换。用户已用实体鼠标确认按钮正常且点击位置对齐，并确认实际全屏显示正常。

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
