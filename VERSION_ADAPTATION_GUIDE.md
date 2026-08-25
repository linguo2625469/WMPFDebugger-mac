# WeChatAppEx 版本适配指南

当微信更新导致 WeChatAppEx 版本变化时，按以下步骤重新定位 hook 偏移。

## 1. 确认版本号

```bash
defaults read /Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist CFBundleVersion
# 输出类似 6.25498，取 25498 作为版本号
```

## 2. 提取二进制文件

```bash
lipo -thin arm64 -output /tmp/WeChatAppEx_arm64 "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx"
```

## 3. 定位四个 hook 偏移

使用 `frida/find_xrefs.py` 自动分析。脚本通过 ADRP+ADD 精确地址验证找到引用目标字符串的函数入口。

### 3.1 修改 find_xrefs.py 中的目标字符串偏移

字符串在二进制中的文件偏移可能随版本变化。用 `strings` + `grep` 确认：

```bash
# 确认字符串存在及其文件偏移
python3 -c "
import sys
with open('/tmp/WeChatAppEx_arm64','rb') as f: data=f.read()
for s in [
    b'virtual void applet::AppletIndexContainer::OnLoadStart',
    b'SendToClientFilter',
    b'WAPCAdapterAppIndex.js'
]:
    idx = data.find(s)
    print(f'0x{idx:x}: {s.decode()[:60]}')
"
```

将找到的偏移更新到 `find_xrefs.py` 的 `TARGETS` 字典中。

### 3.2 运行 find_xrefs.py

```bash
python3 frida/find_xrefs.py
```

输出示例：
```
[onLoadStart] target at 0xa2460f1
  EXACT MATCH: ADRP at 0x571d690, func: 0x571d5b0

[cdpFilter] target at 0xadec65e
  EXACT MATCH: ADRP at 0x92eef58, func: 0x92eee38

[resourceCache1] target at 0x9f4560d
  EXACT MATCH: ADRP at 0x5782768, func: 0x5781c54

=== BL Call Analysis ===
[onLoadStart] func @ 0x571d5b0, 16 BL calls
  BL[15]: target=0x92f25e4 (runtime=0x92ee5e4) <-- LoadStartHookOffset2

[cdpFilter] xref func @ 0x92eee38, 1 BL calls
  BL[0]: target=0x92eed54 (runtime=0x92ead54) <-- CDPFilterHookOffset
```

### 3.3 四个偏移的含义

| 偏移 | 来源 | 说明 |
|------|------|------|
| LoadStartHookOffset | OnLoadStart 函数本身（第一个 x-ref） | 修改 X1 寄存器，强制开启调试 |
| LoadStartHookOffset2 | OnLoadStart 函数内**最后一个 BL 调用目标** | 修改 scene 值为 1101 |
| CDPFilterHookOffset | SendToClientFilter x-ref 函数内**第一个 BL 调用目标** | 将 v8[2] 从 6 改为 0 |
| ResourceCachePolicyHookOffset | WAPCAdapterAppIndex.js 的**第一个引用** | 返回值改为 0x0 |

### 3.4 文件偏移转运行时偏移

find_xrefs.py 输出的 runtime 值已经做了转换：

```
运行时偏移 = 文件偏移 - 0x4000
```

0x4000 是 Mach-O 文件头大小。`__TEXT` 段在文件中从 0x4000 开始，运行时映射到模块基址。

## 4. 反汇编确认 StructOffset 和 TargetOffset

**这是最关键的一步。** StructOffset 和 TargetOffset 不能从字符串搜索得到，必须反汇编 LoadStartHookOffset2 函数的 ARM64 指令。

### 4.1 反汇编脚本

```python
import struct

with open('/tmp/WeChatAppEx_arm64', 'rb') as f:
    data = f.read()

HEADER_OFFSET = 0x4000

def read_u32(data, offset):
    return struct.unpack('<I', data[offset:offset+4])[0]

# LoadStartHookOffset2 的文件偏移 = 运行时偏移 + 0x4000
func_file_offset = 0x92ee5e4 + HEADER_OFFSET  # 替换为实际值

for i in range(200):
    off = func_file_offset + i * 4
    if off >= len(data) - 4: break
    instr = read_u32(data, off)
    runtime_off = off - HEADER_OFFSET

    if instr == 0xD65F03C0:  # RET
        print(f'0x{runtime_off:08x}: RET'); break
    if (instr & 0xFC000000) == 0x14000000:  # B
        print(f'0x{runtime_off:08x}: B'); break

    # LDR X (64-bit)
    if (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        print(f'0x{runtime_off:08x}: LDR X{rt}, [X{rn}, #{imm12*8}]'); continue

    # LDR W (32-bit)
    if (instr & 0xFFC00000) == 0xB9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        print(f'0x{runtime_off:08x}: LDR W{rt}, [X{rn}, #{imm12*4}]'); continue

    # CMP (immediate)
    if (instr & 0xFF800000) == 0x71000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        print(f'0x{runtime_off:08x}: CMP W{rn}, #{imm12}'); continue
```

### 4.2 识别指针链

输出中寻找如下模式：

```
LDR X8, [X0, #8]       → v4 = a1 + 8        （固定，不变）
LDR X9, [X8, #1488]    → qword1 = v4 + 1488  （StructOffset）
LDR X9, [X9, #16]      → qword2 = qword1 + 16（固定，不变）
LDR W9, [X9, #456]     → scene = qword2 + 456 （TargetOffset）
CMP W9, #1101          → 与 1101 比较
```

- **StructOffset** = 第二条 LDR 的立即数（如 1488）
- **TargetOffset** = 第四条 LDR 的立即数（如 456）
- +8 和 +16 通常不变

## 5. 创建配置文件

创建 `frida/config/addresses.<version>.json`：

```json
{
  "Version": 25498,
  "Arch": {
    "arm64": {
      "LoadStartHookOffset": "0x57195b0",
      "LoadStartHookOffset2": "0x92ee5e4",
      "CDPFilterHookOffset": "0x92ead54",
      "ResourceCachePolicyHookOffset": "0x577dc54",
      "StructOffset": 1488,
      "TargetOffset": 456
    }
  }
}
```

## 6. 验证偏移

运行验证脚本确认每个偏移指向有效的函数序言：

```python
python3 -c "
import struct
with open('/tmp/WeChatAppEx_arm64','rb') as f: data=f.read()
HEADER=0x4000
def r32(o): return struct.unpack('<I',data[o:o+4])[0]
for name,off in [('LoadStart',0x57195b0),('LoadStart2',0x92ee5e4),('CDPFilter',0x92ead54),('ResourceCache',0x577dc54)]:
    instr=r32(off+HEADER)
    ok = (instr&0xFF000000)==0xD1000000 or (instr&0xFFC00000)==0xA9800000 or instr in (0xD503237F,0xD503245F)
    print(f'{name}: 0x{instr:08x} {\"OK\" if ok else \"FAIL\"}')"
```

## 7. 测试

```bash
cd /Users/akko/MyProject/WMPFDebugger-mac && node src/index.js
```

然后打开一个小程序，观察日志：

- `[hook] AppletIndexContainer::OnLoadStart triggered` — LoadStart hook 触发
- `[hook] scene: 1008 (structOffset=1488, targetOffset=456)` — 读取到有效 scene 值
- `[hook] hook scene 1008 -> 1101` — 成功修改 scene 值
- `[hook] CDPFilter triggered` — CDPFilter hook 触发
- `[hook] ResourceCachePolicy triggered` — ResourceCache hook 触发

浏览器访问 `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000` 应显示 DevTools。

## 8. 常见问题

### scene 值是垃圾数字
StructOffset 或 TargetOffset 不对。重新执行第 4 步反汇编，确认 LDR 指令的立即数。

### qword1 为 null
StructOffset 不对。v4+offset 处的指针为空，说明偏移指向了错误的 struct 字段。

### CDPFilter 不触发
scene 值没有被成功修改为 1101。CDPFilter 只在 scene=1101 时才会被调用。

### 动态字符串扫描返回 0 个匹配
WeChatAppEx 的字符串可能分布在不同的内存段。确保扫描 `r--`、`rw-`、`r-x` 三种保护属性的内存区域，并用 16MB 分块扫描。

### self-test 报 "not a function"
`Module.findExportByName` 在某些环境下可能不可用。这不影响主 hook 功能，可以忽略。
