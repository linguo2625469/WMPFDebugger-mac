#!/usr/bin/env python3
"""在 WeChatAppEx Framework ARM64 中查找字符串精确交叉引用，定位函数入口偏移。

改进：
1. ADRP+ADD 精确地址验证
2. CDPFilter: 找到 x-ref 函数内第一个 BL 调用目标（参考 ARM ADAPTATION.md）
3. LoadStartHookOffset2: 找到 OnLoadStart 函数内最后一个 BL 调用目标（参考 ARM README）
4. 文件偏移 → 运行时偏移：减去 0x4000（Mach-O header 大小）
"""

import struct

BINARY = "/tmp/WeChatAppEx_arm64"

# Mach-O 文件头偏移：__TEXT 段在文件中从 0x4000 开始，但运行时映射到模块基址
HEADER_OFFSET = 0x4000

# 目标字符串的文件偏移（已确认与运行时偏移差 0x4000）
TARGETS = {
    "onLoadStart": 0xa2460f1,       # "virtual void applet::AppletIndexContainer::OnLoadStart(bool, const std::string &)"
    "cdpFilter": 0xadec65e,          # "SendToClientFilter"
    "resourceCache1": 0x9f4560d,     # "WAPCAdapterAppIndex.js" (第一个，参考 ARM README)
    "resourceCache2": 0xa233f78,     # "WAPCAdapterAppIndex.js" (第二个，参考 ADAPTATION.md)
}

def read_u32(data, offset):
    return struct.unpack("<I", data[offset:offset+4])[0]

def is_adrp(instr):
    return (instr & 0x9F000000) == 0x90000000

def is_add_imm(instr):
    return (instr & 0xFF800000) == 0x91000000

def is_bl(instr):
    """BL 指令: 0x94xxxxxx"""
    return (instr & 0xFC000000) == 0x94000000

def adrp_info(instr, pc):
    immlo = (instr >> 29) & 0x3
    immhi = (instr >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm = imm - 0x200000
    pc_page = pc & ~0xFFF
    rd = instr & 0x1F
    return (pc_page + (imm << 12), rd)

def add_info(instr):
    imm12 = (instr >> 10) & 0xFFF
    rn = (instr >> 5) & 0x1F
    rd = instr & 0x1F
    return (imm12, rn, rd)

def bl_target(instr, pc):
    """BL 指令的目标地址"""
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 = imm26 - 0x04000000
    return pc + (imm26 * 4)

def is_function_prologue(instr):
    if (instr & 0xFF000000) == 0xD1000000: return True  # SUB sp, sp, #imm
    if (instr & 0xFFC00000) == 0xA9800000: return True  # STP
    if instr == 0xD503237F: return True  # PACIBSP
    if instr == 0xD503245F: return True  # BTI c
    return False

def is_function_end(instr):
    if instr == 0xD65F03C0: return True  # RET
    if (instr & 0xFC000000) == 0x14000000: return True  # B
    return False

def find_function_entry(data, addr):
    """从指令地址向后查找函数入口"""
    MAX_SEARCH = 0x10000
    for i in range(0, MAX_SEARCH, 4):
        check = addr - i
        if check < 0: break
        instr = read_u32(data, check)
        if is_function_prologue(instr):
            if i >= 4:
                prev = read_u32(data, check - 4)
                if is_function_end(prev):
                    return check
                if prev == 0xD503201F and check - 8 >= 0:
                    prev2 = read_u32(data, check - 8)
                    if is_function_end(prev2):
                        return check
            if check == 0:
                return check
    return None

def scan_bl_calls(data, func_entry, max_scan=0x10000):
    """扫描函数体内的 BL 调用，返回目标地址列表"""
    targets = []
    for i in range(0, max_scan, 4):
        addr = func_entry + i
        if addr >= len(data) - 4: break
        instr = read_u32(data, addr)

        # 遇到 RET 或无条件 B 则停止
        if instr == 0xD65F03C0: break
        if (instr & 0xFC000000) == 0x14000000: break

        if is_bl(instr):
            target = bl_target(instr, addr)
            targets.append(target)

    return targets

def to_runtime(offset):
    """文件偏移 → 运行时偏移（减去 Mach-O header）"""
    return offset - HEADER_OFFSET

def main():
    with open(BINARY, "rb") as f:
        data = f.read()

    scan_end = min(0xaf28000, len(data))
    print(f"Scanning 0x0 to 0x{scan_end:x}")

    results = {}

    for key, str_addr in TARGETS.items():
        print(f"\n[{key}] target at 0x{str_addr:x}")
        found = []

        i = 0
        while i < scan_end - 8:
            instr = read_u32(data, i)
            if is_adrp(instr):
                target_page, rd = adrp_info(instr, i)
                if target_page == (str_addr & ~0xFFF):
                    exact_match = False
                    for j in range(1, 6):
                        if i + j*4 >= len(data): break
                        next_instr = read_u32(data, i + j*4)
                        if is_add_imm(next_instr):
                            imm12, rn, _ = add_info(next_instr)
                            if rn == rd:
                                exact_addr = target_page + imm12
                                if exact_addr == str_addr:
                                    exact_match = True
                                break
                        if (next_instr & 0xFC000000) == 0x14000000: break
                        if (next_instr & 0xFF000000) == 0x54000000: break

                    if exact_match:
                        func_entry = find_function_entry(data, i)
                        if func_entry is not None and func_entry not in found:
                            found.append(func_entry)
                            print(f"  EXACT MATCH: ADRP at 0x{i:x}, func: 0x{func_entry:x}")
            i += 4

        results[key] = sorted(found)
        print(f"  Total: {len(found)} function(s)")

    # --- 分析 BL 调用 ---
    print("\n=== BL Call Analysis ===")

    onLoadStart_funcs = results.get("onLoadStart", [])
    cdpFilter_funcs = results.get("cdpFilter", [])

    # OnLoadStart: 最后一个 BL 调用 = LoadStartHookOffset2
    loadStartHookOffset2 = None
    if onLoadStart_funcs:
        onLoadStart_entry = onLoadStart_funcs[0]
        bl_calls = scan_bl_calls(data, onLoadStart_entry)
        print(f"\n[onLoadStart] func @ 0x{onLoadStart_entry:x}, {len(bl_calls)} BL calls")
        for idx, target in enumerate(bl_calls):
            marker = " <-- LoadStartHookOffset2" if idx == len(bl_calls) - 1 else ""
            print(f"  BL[{idx}]: target=0x{target:x} (runtime=0x{to_runtime(target):x}){marker}")
        if bl_calls:
            loadStartHookOffset2 = to_runtime(bl_calls[-1])

    # CDPFilter: 第一个 BL 调用 = CDPFilterHookOffset
    cdpFilterHookOffset = None
    if cdpFilter_funcs:
        cdp_entry = cdpFilter_funcs[0]
        bl_calls = scan_bl_calls(data, cdp_entry)
        print(f"\n[cdpFilter] xref func @ 0x{cdp_entry:x}, {len(bl_calls)} BL calls")
        for idx, target in enumerate(bl_calls):
            marker = " <-- CDPFilterHookOffset" if idx == 0 else ""
            print(f"  BL[{idx}]: target=0x{target:x} (runtime=0x{to_runtime(target):x}){marker}")
        if bl_calls:
            cdpFilterHookOffset = to_runtime(bl_calls[0])
        else:
            # fallback: 使用 x-ref 函数本身
            print(f"  No BL calls found, using xref func itself")
            cdpFilterHookOffset = to_runtime(cdp_entry)

    # ResourceCache: 优先用第一个引用（ARM README），fallback 第二个
    resourceCacheHookOffset = None
    rc1_funcs = results.get("resourceCache1", [])
    rc2_funcs = results.get("resourceCache2", [])
    if rc1_funcs:
        rc_entry = rc1_funcs[0]
        resourceCacheHookOffset = to_runtime(rc_entry)
        print(f"\n[resourceCache1] func @ 0x{rc_entry:x} (runtime=0x{resourceCacheHookOffset:x})")
    elif rc2_funcs:
        rc_entry = rc2_funcs[0]
        resourceCacheHookOffset = to_runtime(rc_entry)
        print(f"\n[resourceCache2] func @ 0x{rc_entry:x} (runtime=0x{resourceCacheHookOffset:x})")
    else:
        print(f"\n[resourceCache] NOT FOUND in either reference")

    # --- 生成配置 ---
    print("\n=== Suggested Config (runtime offsets) ===")
    print("{")
    print('  "Version": 25498,')
    print('  "Arch": {')
    print('    "arm64": {')

    if onLoadStart_funcs:
        loadStartHookOffset = to_runtime(onLoadStart_funcs[0])
        print(f'      "LoadStartHookOffset": "0x{loadStartHookOffset:x}",')

    if loadStartHookOffset2:
        print(f'      "LoadStartHookOffset2": "0x{loadStartHookOffset2:x}",')

    if cdpFilterHookOffset:
        print(f'      "CDPFilterHookOffset": "0x{cdpFilterHookOffset:x}",')

    if resourceCacheHookOffset:
        print(f'      "ResourceCachePolicyHookOffset": "0x{resourceCacheHookOffset:x}",')

    print(f'      "StructOffset": 1368')
    print('    }')
    print('  }')
    print("}")

if __name__ == "__main__":
    main()
