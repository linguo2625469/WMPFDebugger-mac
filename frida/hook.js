const VERBOSE = true

const getMainModule = () => {
  return Process.findModuleByName('WeChatAppEx Framework')
}

// ---- 动态偏移查找 ----

const TARGET_STRINGS = {
  onLoadStart: 'virtual void applet::AppletIndexContainer::OnLoadStart(bool, const std::string &)',
  cdpFilter: 'SendToClientFilter',
  resourceCache: 'WAPCAdapterAppIndex.js',
}

// 将字符串转为用于 Memory.scan 的 hex 模式
const strToHexPattern = (str) => {
  const bytes = []
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i)
    if (code > 0xff) {
      // 非 ASCII 字符，跳过（目标字符串都是 ASCII）
      return null
    }
    bytes.push(code.toString(16).padStart(2, '0'))
  }
  return bytes.join(' ')
}

// 在模块中搜索字符串地址
const findStringAddresses = (module, str) => {
  const pattern = strToHexPattern(str)
  if (!pattern) return []

  const results = []
  const moduleEnd = module.base.add(module.size)
  const CHUNK_SIZE = 16 * 1024 * 1024 // 16MB chunks

  const protections = ['r--', 'rw-', 'r-x']
  for (const prot of protections) {
    const ranges = Process.enumerateRanges({ protection: prot, coalesce: true })
    for (const range of ranges) {
      if (range.base.compare(module.base) < 0) continue
      if (range.base.compare(moduleEnd) >= 0) continue

      // 分块扫描
      const totalSize = Number(range.size)
      for (let offset = 0; offset < totalSize; offset += CHUNK_SIZE) {
        const chunkSize = Math.min(CHUNK_SIZE, totalSize - offset)
        try {
          const matches = Memory.scanSync(range.base.add(offset), chunkSize, pattern)
          for (const m of matches) {
            // Memory.scanSync 返回 {address, size} 对象
            const addr = (m && typeof m === 'object' && m.address) ? m.address : m
            results.push(addr)
          }
        } catch (e) {
          // 跳过不可读的块
        }
      }

      if (results.length > 0) {
        console.log(`[frida]   found ${results.length} matches in this range`)
        return results
      }
    }
  }

  return results
}

// 判断是否是指令对齐的地址
const isInstructionAligned = (addr) => {
  return addr.toInt32() % 4 === 0
}

// 判断是否是 ARM64 函数序言
const isFunctionPrologue = (addr) => {
  try {
    const instr = addr.readU32()

    // SUB sp, sp, #imm (0xD1xxxxxx)
    if ((instr & 0xFF000000) === 0xD1000000) return true

    // STP (store pair) - 常见的函数序言指令
    // 0xA9xxxxxx: STP with writeback
    if ((instr & 0xFFC00000) === 0xA9800000) return true

    // PACIBSP (pointer auth)
    if (instr === 0xD503237F) return true

    // BTI c
    if (instr === 0xD503245F) return true

    return false
  } catch (e) {
    return false
  }
}

// 判断是否是函数结束指令
const isFunctionEnd = (addr) => {
  try {
    const instr = addr.readU32()
    // RET = 0xD65F03C0
    if (instr === 0xD65F03C0) return true
    // B (无条件跳转) = 0x14xxxxxx, 0x17xxxxxx
    if ((instr & 0xFC000000) === 0x14000000) return true
    // BR xN (寄存器跳转，常见于尾调用/跳板) = 0xD61F0000 | Rn << 5
    if ((instr & 0xFFFFFC1F) === 0xD61F0000) return true
    return false
  } catch (e) {
    return false
  }
}

// 从指定地址向后查找函数入口点
const findFunctionEntry = (addr, moduleBase) => {
  const MAX_SEARCH = 0x10000 // 64KB

  for (let i = 0; i < MAX_SEARCH; i += 4) {
    const checkAddr = addr.sub(i)

    if (isFunctionPrologue(checkAddr)) {
      // 验证前一个指令是函数结束指令
      if (i >= 4) {
        const prevAddr = checkAddr.sub(4)
        if (isFunctionEnd(prevAddr)) {
          return checkAddr
        }
        // 如果前面是 NOP，再往前看
        try {
          if (prevAddr.readU32() === 0xD503201F) {
            const prev2 = checkAddr.sub(8)
            if (isFunctionEnd(prev2)) {
              return checkAddr
            }
          }
        } catch (e) {}
      }
      // 如果是模块起始位置，也接受
      if (checkAddr.compare(moduleBase) === 0) {
        return checkAddr
      }
    }
  }

  return null
}

// 在代码段中搜索 ADRP 指令引用目标字符串页面的位置
const findXrefFunctions = (module, strAddr) => {
  const strPage = strAddr.and(ptr(0xFFFFFFFFFFFFF000))
  const results = []

  const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true })

  for (const range of ranges) {
    if (range.base.compare(module.base) < 0) continue
    if (range.base.compare(module.base.add(module.size)) >= 0) continue

    const start = range.base
    const end = range.base.add(range.size)

    for (let addr = start; addr.compare(end) < 0; addr = addr.add(4)) {
      try {
        const instr = addr.readU32()

        // ADRP: (instr & 0x9F000000) == 0x90000000
        if ((instr & 0x9F000000) === 0x90000000) {
          const immlo = (instr >>> 29) & 0x3
          const immhi = (instr >>> 5) & 0x7FFFF
          let imm = (immhi << 2) | immlo

          // 符号扩展 21-bit
          if (imm & 0x100000) {
            imm = imm - 0x200000
          }

          const pcPage = addr.and(ptr(0xFFFFFFFFFFFFF000))
          const targetPage = pcPage.add(imm * 4096)

          if (targetPage.equals(strPage)) {
            const funcEntry = findFunctionEntry(addr, module.base)
            if (funcEntry && !results.some(r => r.equals(funcEntry))) {
              results.push(funcEntry)
            }
          }
        }
      } catch (e) {
        // 跳过不可读的地址
        continue
      }
    }
  }

  return results
}

// 解析 BL 指令的目标地址
// BL: 0x94xxxxxx, imm26 符号扩展后左移2位 + PC
const resolveBLTarget = (addr) => {
  try {
    const instr = addr.readU32()
    if ((instr & 0xFC000000) !== 0x94000000) return null

    let imm26 = instr & 0x03FFFFFF
    if (imm26 & 0x02000000) {
      imm26 = imm26 - 0x04000000  // 符号扩展 26-bit
    }
    return addr.add(imm26 * 4)
  } catch (e) {
    return null
  }
}

// 扫描函数体内的 BL 调用，返回目标地址列表
// 参考 ARM ADAPTATION.md: CDPFilter 取第一个 BL 调用，LoadStartHookOffset2 取最后一个
const scanBLCalls = (funcEntry, maxScan) => {
  const targets = []
  const scanLimit = maxScan || 0x10000

  for (let offset = 0; offset < scanLimit; offset += 4) {
    const addr = funcEntry.add(offset)
    try {
      const instr = addr.readU32()

      // 遇到 RET 或无条件 B 则停止
      if (instr === 0xD65F03C0) break  // RET
      if ((instr & 0xFC000000) === 0x14000000) break  // B

      // BL 指令
      if ((instr & 0xFC000000) === 0x94000000) {
        const target = resolveBLTarget(addr)
        if (target && !target.isNull()) {
          targets.push(target)
        }
      }
    } catch (e) {
      break
    }
  }

  return targets
}

// 动态查找所有需要的偏移
const findOffsetsDynamically = (module) => {
  console.log('[frida] 动态查找偏移中...')
  console.log(`[frida] Module base: ${module.base}, size: ${module.size}`)

  const moduleBase = module.base
  const moduleEnd = moduleBase.add(module.size)

  // 统计可扫描的区间
  let rangeCount = 0
  for (const prot of ['r--', 'rw-', 'r-x']) {
    const ranges = Process.enumerateRanges({ protection: prot, coalesce: true })
    for (const range of ranges) {
      if (range.base.compare(moduleBase) < 0) continue
      if (range.base.compare(moduleEnd) >= 0) continue
      rangeCount++
    }
  }
  console.log(`[frida] 模块内可扫描区间数: ${rangeCount}`)

  const result = {
    LoadStartHookOffset: null,
    LoadStartHookOffset2: null,
    CDPFilterHookOffset: null,
    ResourceCachePolicyHookOffset: null,
    StructOffset: 1368  // 默认值，大多数版本使用 1368
  }

  // 先找到字符串地址
  const strAddresses = {}
  for (const [key, targetStr] of Object.entries(TARGET_STRINGS)) {
    console.log(`[frida] 搜索字符串: ${key}`)
    const addrs = findStringAddresses(module, targetStr)
    // 安全检查
    const addrList = Array.isArray(addrs) ? addrs.map(a => {
      // Memory.scanSync 可能返回 {address: string} 或 NativePointer
      if (a && typeof a === 'object' && a.address) {
        return ptr(a.address)
      }
      return ptr(a)
    }) : []
    if (addrList.length > 0) {
      const offsets = addrList.map(a => a.sub(moduleBase).toString(16))
      console.log(`[frida] 找到 ${addrList.length} 个匹配: ${offsets.join(', ')}`)
    } else {
      console.log(`[frida] 找到 0 个匹配`)
    }
    strAddresses[key] = addrList
  }

  // 对每个字符串，找到引用它的函数
  for (const [key, addrs] of Object.entries(strAddresses)) {
    if (addrs.length === 0) {
      console.warn(`[frida] 未找到字符串: ${key}`)
      continue
    }

    // 使用第一个找到的字符串地址
    const strAddr = addrs[0]
    console.log(`[frida] 查找引用 ${key} 的函数 (str @ ${strAddr.sub(moduleBase).toString(16)})...`)

    const funcs = findXrefFunctions(module, strAddr)
    const offsets = funcs.map(f => f.sub(moduleBase)).sort((a, b) => a.compare(b))

    console.log(`[frida] 找到 ${offsets.length} 个引用函数: ${offsets.map(o => '0x' + o.toString(16)).join(', ')}`)

    if (offsets.length > 0) {
      switch (key) {
        case 'onLoadStart': {
          // LoadStartHookOffset = OnLoadStart 函数本身 (第一个 x-ref)
          result.LoadStartHookOffset = '0x' + offsets[0].toString(16)
          console.log(`[frida] OnLoadStart: 0x${offsets[0].toString(16)}`)

          // LoadStartHookOffset2 = OnLoadStart 函数内最后一个 BL 调用的目标
          // 参考 ARM README: "上个函数的最后调用的函数"
          const onLoadStartFunc = funcs[0]
          const blCalls = scanBLCalls(onLoadStartFunc)
          if (blCalls.length > 0) {
            const lastBL = blCalls[blCalls.length - 1]
            result.LoadStartHookOffset2 = '0x' + lastBL.sub(moduleBase).toString(16)
            console.log(`[frida] OnLoadStart2 (last BL): 0x${lastBL.sub(moduleBase).toString(16)} (共 ${blCalls.length} 个 BL 调用)`)
          } else {
            console.warn('[frida] OnLoadStart 函数内未找到 BL 调用，使用 fallback')
          }
          break
        }
        case 'cdpFilter': {
          // CDPFilterHookOffset = x-ref 函数内第一个 BL 调用的目标
          // 参考 ARM ADAPTATION.md: "The hook target function is the very first function called in the x-refed function"
          const xrefFunc = funcs[0]
          const blCalls = scanBLCalls(xrefFunc)
          if (blCalls.length > 0) {
            const firstBL = blCalls[0]
            result.CDPFilterHookOffset = '0x' + firstBL.sub(moduleBase).toString(16)
            console.log(`[frida] CDPFilter xref: 0x${offsets[0].toString(16)}, first BL: 0x${firstBL.sub(moduleBase).toString(16)}`)
          } else {
            // fallback: 使用 x-ref 函数本身
            console.warn('[frida] x-ref 函数内未找到 BL 调用，使用 x-ref 函数本身作为 CDPFilter')
            result.CDPFilterHookOffset = '0x' + offsets[0].toString(16)
          }
          break
        }
        case 'resourceCache': {
          // ResourceCache: 第一个引用，直接返回 0x0
          // 参考 ARM README: "搜索WAPCAdapterAppIndex.js，第一个引用，直接返回0x0"
          result.ResourceCachePolicyHookOffset = '0x' + offsets[0].toString(16)
          console.log(`[frida] ResourceCache: 0x${offsets[0].toString(16)}`)
          break
        }
      }
    }
  }

  // 尝试 StructOffset = 1376（ARM 和 18152 版本使用），fallback 1368
  if (!result.LoadStartHookOffset2) {
    console.warn('[frida] 未找到 LoadStartHookOffset2，尝试 StructOffset=1376')
    result.StructOffset = 1376
  }

  return result
}

// ---- 兜底配置（参考 WMPFDebugger 项目的做法，当动态查找失败时使用） ----

const FALLBACK_CONFIG = {
  Version: 18788,
  LoadStartHookOffset: '0x4F6454C',
  LoadStartHookOffset2: '0x83BC8C8',
  CDPFilterHookOffset: '0x83AE884',
  ResourceCachePolicyHookOffset: '0x4FCAD90',
  StructOffset: 1368
}

// ---- Hook 函数 ----

const patchResourceCachePolicy = (base, offset) => {
  Interceptor.attach(base.add(offset), {
    onEnter() {
      console.log(`[hook] ResourceCachePolicy triggered`)
      send({ type: 'hook', name: 'ResourceCachePolicy', event: 'onEnter' })
    },
    onLeave(retval) {
      console.log(`[hook] ResourceCachePolicy onLeave, retval: ${retval}, patching to 0x0`)
      send({ type: 'hook', name: 'ResourceCachePolicy', event: 'onLeave', retval: String(retval) })
      retval.replace(0x0)
    }
  })
}

const patchCDPFilter = (base, offset) => {
  Interceptor.attach(base.add(offset), {
    onEnter(args) {
      console.log(`[hook] CDPFilter triggered, arg0: ${args[0]}`)
      send({ type: 'hook', name: 'CDPFilter', event: 'onEnter', arg0: String(args[0]) })
    },
    onLeave(retval) {
      console.log(`[hook] CDPFilter onLeave, retval: ${retval}`)
      send({ type: 'hook', name: 'CDPFilter', event: 'onLeave', retval: String(retval) })
      if (retval && !retval.isNull()) {
        const v8_2_address = retval.add(8)
        const val = v8_2_address.readU32()
        console.log(`[hook] CDPFilter v8[2]=${val}`)
        if (val == 6) {
          console.log(`[hook] CDPFilter patching v8[2] from 6 to 0`)
          v8_2_address.writeU32(0x0)
        }
      }
    }
  })
}

// 反汇编发现的偏移（版本 25498）
// LDR X8, [X0, #8]      → v4 = a1 + 8
// LDR X9, [X8, #1488]   → qword1 = v4 + 1488
// LDR X9, [X9, #16]     → qword2 = qword1 + 16
// LDR W9, [X9, #456]    → scene = qword2 + 456
// CMP W9, #1101

const onLoadStartHook = (a1, structOffset, targetOffset) => {
  try {
    const result = a1
    console.log(`[hook] onLoadStartHook: a1=${a1}`)
    send({ type: 'hook', name: 'onLoadStart', event: 'enter', a1: String(a1) })

    const v4 = result.add(8).readPointer()
    console.log(`[hook] onLoadStartHook: a1=${a1}, v4=${v4}`)

    if (!v4 || v4.isNull()) {
      console.log('[hook] v4 is null')
      return
    }

    // 用反汇编发现的偏移读取指针链
    const qword1 = v4.add(structOffset).readPointer()
    console.log(`[hook] qword1(v4+${structOffset})=${qword1}`)

    if (!qword1 || qword1.isNull()) {
      console.log(`[hook] qword1 is null at offset ${structOffset}`)
      return
    }

    const qword2 = qword1.add(16).readPointer()
    console.log(`[hook] qword2(qword1+16)=${qword2}`)

    if (!qword2 || qword2.isNull()) {
      console.log('[hook] qword2 is null')
      return
    }

    const targetAddress = qword2.add(targetOffset)
    const currentValue = targetAddress.readInt()
    console.log(`[hook] scene: ${currentValue} (structOffset=${structOffset}, targetOffset=${targetOffset})`)

    const allowedValues = [
      1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308
    ]
    if (allowedValues.includes(currentValue)) {
      console.log(`[hook] hook scene ${currentValue} -> 1101`)
      targetAddress.writeInt(1101)
      send({ type: 'hook', name: 'onLoadStart', event: 'scenePatched', oldValue: currentValue, newValue: 1101 })
    } else {
      console.log(`[hook] scene value ${currentValue} not in allowed list, skipping`)
    }
  } catch (error) {
    console.error('[hook] onLoadStartHook error:', error.message, error.stack)
    send({ type: 'hook', name: 'onLoadStart', event: 'error', error: error.message })
  }
}

const interceptorLoadStart = (base, offset) => {
  Interceptor.attach(base.add(offset), {
    onEnter() {
      console.log('[hook] AppletIndexContainer::OnLoadStart triggered')
      send({ type: 'hook', name: 'LoadStart', event: 'onEnter' })
      const arch = Process.arch
      if (arch === 'arm64') {
        this.context.x1 = (this.context.x1 & ~0xff) | 0x1
      } else if (arch === 'x64' || arch === 'x86_64') {
        this.context.rsi = (this.context.rsi & ~0xff) | 0x1
      } else {
        console.warn(`[interceptor] 未支持的架构: ${arch}，跳过寄存器修改`)
      }
    },
    onLeave() {}
  })
}

const interceptorLoadStart2 = (base, offset, structOffset, targetOffset) => {
  Interceptor.attach(base.add(offset), {
    onEnter(args) {
      console.log('[hook] OnLoadStart2 triggered')
      send({ type: 'hook', name: 'LoadStart2', event: 'onEnter' })
      onLoadStartHook(args[0], structOffset, targetOffset)
    },
    onLeave() {}
  })
}

// ---- 配置解析 ----

const parseConfig = () => {
  const rawConfig = `@@CONFIG@@`
  if (rawConfig.includes('@@')) {
    return null // 没有配置，需要动态查找
  }
  return JSON.parse(rawConfig)
}

const resolveArchConfig = (config) => {
  if (config && typeof config === 'object' && config.LoadStartHookOffset) {
    return config
  }

  const arch = Process.arch
  const table = config?.Arch || config?.ARCH || config?.arch || null
  if (!table || typeof table !== 'object') return null

  const candidates = [arch]
  if (arch === 'x86_64') candidates.push('x64')
  if (arch === 'amd64') candidates.push('x64')
  if (arch === 'ia32') candidates.push('x86')

  for (const key of candidates) {
    const picked = table[key]
    if (picked && typeof picked === 'object' && picked.LoadStartHookOffset) {
      return { ...picked, Version: config.Version ?? picked.Version, __arch: key }
    }
  }
  return null
}

const validateConfig = (config) => {
  const required = [
    'LoadStartHookOffset',
    'LoadStartHookOffset2',
    'CDPFilterHookOffset',
    'ResourceCachePolicyHookOffset',
    'StructOffset'
  ]
  const missing = required.filter((k) => config?.[k] === undefined || config?.[k] === null)
  if (missing.length) {
    throw new Error(`配置缺少字段: ${missing.join(', ')}`)
  }
  // TargetOffset 可选，默认 488
  if (config.TargetOffset === undefined) {
    config.TargetOffset = 488
  }
}

// ---- 主函数 ----

const verifyHookOffset = (base, offset, name) => {
  try {
    const addr = base.add(offset)
    const instr = addr.readU32()
    const hex = '0x' + (instr >>> 0).toString(16).padStart(8, '0')

    // 判断是否是函数序言（注意 JS 位运算结果是 signed 32-bit，比较时需统一转 unsigned）
    const uInstr = instr >>> 0
    const isSUB = ((uInstr & 0xFF000000) >>> 0) === 0xD1000000
    const isSTP = ((uInstr & 0xFFC00000) >>> 0) === 0xA9800000
    const isPACIBSP = uInstr === 0xD503237F
    const isBTI = uInstr === 0xD503245F
    const isPrologue = isSUB || isSTP || isPACIBSP || isBTI

    const prologueStr = isSUB ? 'SUB sp' : isSTP ? 'STP' : isPACIBSP ? 'PACIBSP' : isBTI ? 'BTI c' : '?'
    console.log(`[frida] verify ${name}: @0x${offset.toString(16)} instr=${hex} (${prologueStr}) ${isPrologue ? 'OK' : 'NOT a prologue!'}`)
    return isPrologue
  } catch (e) {
    console.log(`[frida] verify ${name}: @0x${offset.toString(16)} ERROR: ${e.message}`)
    return false
  }
}

// ---- 自检：hook 一个频繁调用的函数，验证 Interceptor 是否正常工作 ----
let selfTestCount = 0
const installSelfTest = () => {
  try {
    // Frida 17+ 移除了 Module.findExportByName 静态方法，做兼容处理
    let mallocPtr = null
    if (typeof Module.findExportByName === 'function') {
      mallocPtr = Module.findExportByName(null, 'malloc')
    } else if (typeof Module.getGlobalExportByName === 'function') {
      mallocPtr = Module.getGlobalExportByName('malloc')
    }
    if (mallocPtr) {
      Interceptor.attach(mallocPtr, {
        onEnter(args) {
          selfTestCount++
          if (selfTestCount === 1) {
            send({ type: 'self-test', msg: 'malloc hook triggered! Interceptor is working.' })
            console.log('[self-test] malloc hook works! Interceptor is functional.')
          }
          // 每 1000 次报告一次
          if (selfTestCount % 1000 === 0) {
            console.log(`[self-test] malloc called ${selfTestCount} times`)
          }
        }
      })
      console.log('[self-test] Installed malloc hook for self-testing')
    } else {
      console.warn('[self-test] Could not find malloc export')
    }
  } catch (e) {
    console.error('[self-test] Failed to install self-test hook:', e.message)
  }
}

// ---- 心跳定时器，确认脚本在运行 ----
const startHeartbeat = () => {
  let beatCount = 0
  setInterval(() => {
    beatCount++
    console.log(`[heartbeat] #${beatCount} script alive, selfTestCount=${selfTestCount}`)
  }, 5000)
}

const main = () => {
  console.log('[frida] === Script starting ===')
  const mainModule = getMainModule()

  if (!mainModule) {
    console.error('[frida] WeChatAppEx Framework module not found')
    return
  }

  // 安装自检 hook
  installSelfTest()

  // 启动心跳
  startHeartbeat()

  let config = null
  const rawConfig = parseConfig()

  if (rawConfig) {
    config = resolveArchConfig(rawConfig)
  }

  if (!config) {
    console.log('[frida] 未找到版本配置文件，尝试动态查找偏移...')
    config = findOffsetsDynamically(mainModule)
  }

  if (!config || !config.LoadStartHookOffset) {
    console.warn('[frida] 动态查找失败，使用兜底配置（版本 18788），可能不兼容当前版本')
    config = FALLBACK_CONFIG
  }

  try {
    validateConfig(config)
  } catch (e) {
    console.error(`[frida] 配置校验失败: ${e.message}`)
    console.error('[frida] 动态查找到的配置:', JSON.stringify(config))
    return
  }

  console.log(
    `[frida] Loaded config for version: ${config.Version || 'dynamic'} (arch: ${config.__arch || Process.arch})`
  )
  console.log(`[frida] Module base: ${mainModule.base}`)
  console.log(`[frida] LoadStartHookOffset: ${config.LoadStartHookOffset}`)
  console.log(`[frida] LoadStartHookOffset2: ${config.LoadStartHookOffset2}`)
  console.log(`[frida] CDPFilterHookOffset: ${config.CDPFilterHookOffset}`)
  console.log(`[frida] ResourceCachePolicyHookOffset: ${config.ResourceCachePolicyHookOffset}`)
  console.log(`[frida] StructOffset: ${config.StructOffset}`)
  console.log(`[frida] TargetOffset: ${config.TargetOffset}`)

  // 运行时验证每个偏移，并 dump 前 4 条指令
  console.log('[frida] --- Verifying offsets ---')
  const base = mainModule.base
  const verifyResults = {
    loadStart: verifyHookOffset(base, config.LoadStartHookOffset, 'LoadStart'),
    loadStart2: verifyHookOffset(base, config.LoadStartHookOffset2, 'LoadStart2'),
    cdpFilter: verifyHookOffset(base, config.CDPFilterHookOffset, 'CDPFilter'),
    resourceCache: verifyHookOffset(base, config.ResourceCachePolicyHookOffset, 'ResourceCache'),
  }

  // 安装所有 hook
  console.log('[frida] --- Installing hooks ---')
  try {
    interceptorLoadStart(mainModule.base, config.LoadStartHookOffset)
    console.log('[frida] LoadStart hook installed OK')
  } catch (e) {
    console.error('[frida] LoadStart hook install FAILED:', e.message)
  }

  try {
    interceptorLoadStart2(mainModule.base, config.LoadStartHookOffset2, config.StructOffset, config.TargetOffset)
    console.log('[frida] LoadStart2 hook installed OK')
  } catch (e) {
    console.error('[frida] LoadStart2 hook install FAILED:', e.message)
  }

  try {
    patchResourceCachePolicy(mainModule.base, config.ResourceCachePolicyHookOffset)
    console.log('[frida] ResourceCache hook installed OK')
  } catch (e) {
    console.error('[frida] ResourceCache hook install FAILED:', e.message)
  }

  try {
    patchCDPFilter(mainModule.base, config.CDPFilterHookOffset)
    console.log('[frida] CDPFilter hook installed OK')
  } catch (e) {
    console.error('[frida] CDPFilter hook install FAILED:', e.message)
  }

  console.log('[frida] --- All hooks installed ---')
  console.log('[frida] === Waiting for hooks to trigger... ===')
  console.log('[frida] === 请打开一个小程序来触发 OnLoadStart hook ===')
}

main()