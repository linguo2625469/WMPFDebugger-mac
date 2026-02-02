# WMPFDebugger-mac

macOS 版本的微信小程序调试工具（支持 Intel x64 和 Apple Silicon arm64）

## 项目简介

本项目基于以下两个优秀的开源项目修改而成：

- [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) - Windows 版本的微信小程序调试工具
- [WMPFDebugger-arm](https://github.com/chain00x/WMPFDebugger-arm) - macOS ARM 版本的适配

本项目在 WMPFDebugger-arm 的基础上，实现了以下改进：

- ✅ **双架构支持**：同时支持 macOS Intel (x64) 和 Apple Silicon (arm64/M芯片)
- ✅ **完善的版本管理**：通过配置文件管理不同版本的偏移地址，便于维护和扩展
- ✅ **自动架构检测**：自动检测系统架构并加载对应的配置
- ✅ **自动版本检测**：自动检测 WeChatAppEx 版本并加载对应的配置文件

## 工作原理

这个工具通过 patch 一些 Chrome 调试协议（CDP）的过滤器和其他的条件判断来强制小程序连接到外部调试器（也就是远程调试，LanDebug 模式）。这个调试协议是基于 protobuf 实现的私有协议，通过逆向开发者工具提取相应的协议实现，该工具实现了一个简单的小程序调试协议转换为标准 Chrome 调试协议，从而允许我们使用标准基于 chromium 浏览器的内嵌开发者工具来调试任意小程序。

## 系统要求

- **操作系统**：macOS（支持 Intel x64 和 Apple Silicon arm64）
- **Node.js**：至少 LTS v22 版本
- **包管理器**：yarn
- **浏览器**：基于 Chromium 的浏览器（如 Chrome、Edge 等）
- **微信**：已安装并运行微信 macOS 版本

## 安装

**第 1 步** 克隆仓库并安装依赖

```bash
git clone https://github.com/your-username/WMPFDebugger-mac
cd WMPFDebugger-mac
yarn
```

## 使用方法

**第 2 步** 运行调试服务器

```bash
npx ts-node src/index.ts
```

该命令会：
- 启动调试服务器（端口 9421）
- 启动 CDP 代理服务器（端口 62000）
- 自动检测 WeChatAppEx 版本和系统架构
- 自动注入 hook 脚本到小程序运行时

> **重要提示**：在此步骤之后，你需要**先启动小程序**（第 3 步），**再打开开发者工具**（第 4 步）。如果操作顺序相反，你可能需要重新执行步骤 2-4。

**第 3 步** 打开任意你想调试的小程序

在微信中打开任意小程序，确保小程序正常运行。

**第 4 步** 打开 Chrome DevTools

在浏览器中访问以下地址：

```
devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
```

即可开始调试。你可以修改 `src/index.ts` 中的 `CDP_PORT` 常量来更改端口号（默认为 62000）。

## 支持的版本

当前支持的 WMPF 版本：

- **18788** (最新)
- **18152**

> **如何检查你的 WeChatAppEx 版本**：
> 
> 在终端运行以下命令：
> ```bash
> defaults read /Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist CFBundleVersion
> ```
> 版本号是输出中第二个数字（例如：`4.18788.xxx` 中的 `18788`）

## 版本管理

本项目使用配置文件管理不同版本的偏移地址。配置文件位于 `frida/config/` 目录下，命名格式为 `addresses.{版本号}.json`。

每个配置文件包含：
- `Version`：版本号
- `Arch`：架构配置
  - `arm64`：Apple Silicon (M芯片) 的偏移地址
  - `x64`：Intel 处理器的偏移地址

系统会自动：
1. 检测当前运行的 WeChatAppEx 版本
2. 检测系统架构（arm64 或 x64）
3. 加载对应的配置文件

如果需要添加新版本支持，请在 `frida/config/` 目录下创建新的配置文件。

## 项目结构

```
WMPFDebugger-mac/
├── frida/
│   ├── config/              # 版本配置文件目录
│   │   ├── addresses.18152.json
│   │   └── addresses.18788.json
│   └── hook.js             # Frida hook 脚本
├── src/
│   ├── index.ts            # 主程序入口
│   └── third-party/        # 第三方协议实现（来自微信开发者工具）
│       ├── RemoteDebugCodex.js
│       ├── RemoteDebugConstants.js
│       ├── RemoteDebugUtils.js
│       └── WARemoteDebugProtobuf.js
├── package.json
├── tsconfig.json
└── README.md
```

## 故障排除

### 无法找到 WeChatAppEx 进程

确保：
- 微信已启动
- 至少打开过一个小程序（这样才会启动 WeChatAppEx 进程）

### 连接失败

1. 确保先启动小程序，再打开 DevTools
2. 检查端口是否被占用
3. 尝试重启微信和调试服务器

### 版本不支持

如果提示版本不支持，说明当前 WeChatAppEx 版本还没有对应的配置文件。你可以：
1. 提交 Issue 请求添加新版本支持
2. 参考现有配置文件格式，自行添加新版本配置


## 致谢

- [evi0s/WMPFDebugger](https://github.com/evi0s/WMPFDebugger) - 原始 Windows 版本
- [chain00x/WMPFDebugger-arm](https://github.com/chain00x/WMPFDebugger-arm) - macOS ARM 版本适配

## 许可证

本项目采用 GPL-2.0 许可证开源。

## 免责声明

**本库只能作为学习用途，造成的任何问题与本库开发者无关，如侵犯到你的权益，请联系删除**

该程序以 GPLv2 许可证开源，参考许可证第十一及十二条：

本程序为免费授权，故在适用法律范围内不提供品质担保。除非另作书面声明，版权持有人及其他程式提供者"概"不提供任何显式或隐式的品质担保，品质担保所指包括而不仅限于有经济价值和适合特定用途的保证。全部风险，如程序的质量和性能问题，皆由你承担。若程序出现缺陷，你将承担所有必要的修复和更正服务的费用。

除非适用法律或书面协议要求，任何版权持有人或本程序按本协议可能存在的第三方修改和再发布者，都不对你的损失负有责任，包括由于使用或者不能使用本程序造成的任何一般的、特殊的、偶发的或重大的损失（包括而不仅限于数据丢失、数据失真、你或第三方的后续损失、其他程序无法与本程序协同运作），即使那些人声称会对此负责。

此外，在 `src/third-party` 中，所有代码从微信开发者工具提取，因此腾讯控股有限公司拥有对该代码的所有版权。
