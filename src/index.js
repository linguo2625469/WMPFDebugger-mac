const { promises } = require("node:fs");
const { EventEmitter } = require("node:events");
const path = require("node:path");
const WebSocket = require("ws");
const { execSync } = require("child_process");

// 假设这些是 CommonJS 模块
const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

class DebugMessageEmitter extends EventEmitter {}

// 默认调试端口，请勿更改
const DEBUG_PORT = 9421;
// CDP 端口，可按需更改
// 通过导航到 devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${CDP_PORT} 使用此端口
const CDP_PORT = 62000;
// 调试开关
const DEBUG = false;

const debugMessageEmitter = new DebugMessageEmitter();

const bufferToHexString = (buffer) => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

// --- 全局变量用于存储服务器和 Frida 会话实例 ---
let debugWSS = null;
let proxyWSS = null;
let fridaSessions = [];

const debug_server = () => {
    const wss = new WebSocket.Server({ port: DEBUG_PORT });
    console.log(`[server] debug server running on ws://localhost:${DEBUG_PORT}`);

    let messageCounter = 0;

    const onMessage = (message) => {
        DEBUG &&
            console.log(
                `[client] received raw message (hex): ${bufferToHexString(message)}`
            );
        let unwrappedData = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            DEBUG && console.log(`[client] [DEBUG] decoded data:`);
            DEBUG && console.dir(unwrappedData);
        } catch (e) {
            console.error(`[client] err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            // 需要代理到 CDP 客户端
            debugMessageEmitter.emit("cdpmessage", unwrappedData.data.payload);
        }
    };

    wss.on("connection", (ws) => {
        console.log("[conn] miniapp client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            console.error("[client] err:", err);
        });
        ws.on("close", () => {
            console.log("[client] client disconnected");
        });
    });

    debugMessageEmitter.on("proxymessage", (message) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // 编码 CDP 并发送到小程序
                    const rawPayload = {
                        jscontext_id: "",
                        op_id: Math.round(100 * Math.random()),
                        payload: message.toString(),
                    };
                    DEBUG && console.log(rawPayload);
                    const wrappedData = codex.wrapDebugMessageData(
                        rawPayload,
                        "chromeDevtools",
                        0
                    );
                    const outData = {
                        seq: ++messageCounter,
                        category: "chromeDevtools",
                        data: wrappedData.buffer,
                        compressAlgo: 0,
                        originalSize: wrappedData.originalSize,
                    };
                    const encodedData =
                        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                            outData
                        ).finish();
                    client.send(encodedData, { binary: true });
                }
            });
    });

    return wss; // 返回实例以便后续管理
};

const proxy_server = () => {
    const wss = new WebSocket.Server({ port: CDP_PORT });
    console.log(`[server] proxy server running on ws://localhost:${CDP_PORT}`);

    const onMessage = (message) => {
        debugMessageEmitter.emit("proxymessage", message);
    };

    wss.on("connection", (ws) => {
        console.log("[conn] CDP client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            console.error("[client] CDP err:", err);
        });
        ws.on("close", () => {
            console.log("[client] CDP client disconnected");
        });
    });

    debugMessageEmitter.on("cdpmessage", (message) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // 发送 CDP 消息到 devtools
                    client.send(message);
                }
            });
    });

    return wss; // 返回实例以便后续管理
};

// 动态获取 WeChatAppEx 进程 PID 的函数
const getWeChatAppExPID = () => {
    try {
        // 注意：路径可能需要根据你的实际安装位置调整
        const command = `pgrep -f '/MacOS/WeChatAppEx.app/Contents/MacOS/WeChatAppEx'`;
        const output = execSync(command, { encoding: "utf-8" }).trim();
        const pids = output
            .split("\n")
            .map((pid) => parseInt(pid.trim(), 10))
            .filter((pid) => !isNaN(pid));

        if (pids.length === 0) {
            throw new Error("No WeChatAppEx processes found");
        }

        // 返回所有找到的 PID
        console.log(`[frida] Found WeChatAppEx PIDs: ${pids.join(", ")}`);
        return pids;
    } catch (error) {
        console.error(`[frida] Error getting WeChatAppEx PID: ${error}`);
        throw error;
    }
};


// macOS ARM 特定：获取 WeChatAppEx 版本号
const getWeChatAppExVersion = () => {
    try {
        const command = `defaults read /Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist CFBundleVersion`;
        const output = execSync(command, { encoding: 'utf-8' }).trim();
        const version = output.split('.')[1];
        if (!version || isNaN(Number(version))) {
            throw new Error(`Invalid version: ${output}`);
        }
        return version;
    } catch (error) {
        console.log(`[frida] 获取版本失败，使用默认版本 17078`);
        return '17078';
    }
};

const frida_server = async () => {
    // 动态导入 frida ES Module
    const fridaModule = await import("frida");
    const localDevice = await fridaModule.getLocalDevice();

    // 获取所有 WeChatAppEx 进程的 PID
    const pids = getWeChatAppExPID();
    const wmpfVersion = getWeChatAppExVersion()

    // 查找 hook 脚本
    // 使用 __dirname 获取当前脚本所在目录更可靠
    const projectRoot = path.join(__dirname, "..");
    
    // 解析命令行参数，查找 --script 参数
    let scriptPath = "frida/hook.js"; // 默认脚本
    let configPath = `frida/config/addresses.${wmpfVersion}.json`;
    
    let scriptContent = null;
    let configContent = null;
    try {
        // 使用绝对路径或相对于项目根目录的路径
        const absoluteScriptPath = path.isAbsolute(scriptPath) ? scriptPath : path.join(projectRoot, scriptPath);
        scriptContent = (
            await promises.readFile(absoluteScriptPath)
        ).toString();
        console.log(`[frida] Loaded script from: ${absoluteScriptPath}`);

        configContent = (
            await promises.readFile(path.isAbsolute(configPath) ? configPath : path.join(projectRoot, configPath))
        ).toString();
    } catch (e) {
        console.error(`[frida] Error loading script: ${e}`);
        throw new Error("[frida] hook script not found");
    }

    if (scriptContent && configContent) {
        scriptContent = scriptContent.replace('@@CONFIG@@', configContent)
      }

    // 附加到所有找到的进程并加载脚本
    const sessionsAndScripts = [];
    
    for (const pid of pids) {
        try {
            console.log(`[frida] Attaching to WeChatAppEx process PID: ${pid}`);
            // 附加到进程
            const session = await localDevice.attach(pid);
            
            // 加载脚本
            const script = await session.createScript(scriptContent);
            script.message.connect((message) => {
                console.log(`[frida client] PID ${pid}:`, message);
            });
            
            await script.load();
            console.log(`[frida] Successfully attached to PID ${pid}`);
            
            sessionsAndScripts.push({ session, script, pid });
        } catch (error) {
            console.error(`[frida] Error attaching to PID ${pid}: ${error}`);
            // 继续尝试其他进程
        }
    }
    
    if (sessionsAndScripts.length === 0) {
        throw new Error("[frida] Failed to attach to any WeChatAppEx process");
    }
    
    console.log(`[frida] Successfully attached to ${sessionsAndScripts.length} WeChatAppEx processes`);
    return sessionsAndScripts;
};

// --- 关闭服务器和清理资源的函数 ---
const shutdown = async () => {
    console.log("\n[shutdown] Shutting down servers and cleaning up...");

    const closePromises = [];

    // 关闭所有 Frida 会话和脚本
    if (fridaSessions.length > 0) {
        console.log(`[shutdown] Detaching ${fridaSessions.length} Frida sessions...`);
        
        for (const { session, script, pid } of fridaSessions) {
            try {
                // 先卸载脚本
                if (script) {
                    console.log(`[shutdown] Unloading script from PID ${pid}...`);
                    await script.unload();
                }
                
                // 然后分离会话
                if (session) {
                    console.log(`[shutdown] Detaching from PID ${pid}...`);
                    await session.detach();
                }
            } catch (error) {
                console.error(`[shutdown] Error cleaning up PID ${pid}: ${error}`);
            }
        }
        
        // 清空会话数组
        fridaSessions = [];
        console.log("[shutdown] All Frida sessions detached.");
    }

    // 关闭 Debug WebSocket Server
    if (debugWSS) {
        console.log("[shutdown] Closing debug WebSocket connections...");
        // 关闭所有活动客户端连接
        debugWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate(); // 强制关闭客户端连接
            }
        });
        console.log("[shutdown] Closing debug WebSocket server...");
        closePromises.push(
            new Promise((resolve, reject) => {
                debugWSS.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing debug WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Debug WebSocket server closed."
                        );
                    }
                    resolve(); // 总是 resolve 以继续关闭流程
                });
            })
        );
        debugWSS = null; // 清除引用
    }

    // 关闭 Proxy WebSocket Server
    if (proxyWSS) {
        console.log("[shutdown] Closing proxy WebSocket connections...");
        proxyWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate();
            }
        });
        console.log("[shutdown] Closing proxy WebSocket server...");
        closePromises.push(
            new Promise((resolve, reject) => {
                proxyWSS.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing proxy WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Proxy WebSocket server closed."
                        );
                    }
                    resolve();
                });
            })
        );
        proxyWSS = null; // 清除引用
    }

    // 等待所有 WebSocket 服务器关闭
    if (closePromises.length > 0) {
        try {
            await Promise.all(closePromises);
        } catch (err) {
            console.error(
                "[shutdown] Error waiting for WebSocket servers to close:",
                err
            );
        }
    }

    console.log("[shutdown] Shutdown complete. Exiting.");
    process.exit(0); // 强制退出，确保清理完毕
};
// --- 主函数 ---

const main = async () => {
    try {
        // 启动服务器并保存实例引用
        debugWSS = debug_server();
        proxyWSS = proxy_server();
        const fridaObjects = await frida_server();
        fridaSessions = fridaObjects; // 保存所有会话和脚本引用

        // 添加 SIGINT (Ctrl+C) 和 SIGTERM 监听器
        process.on("SIGINT", () => {
            console.log("\n[signal] Received SIGINT (Ctrl+C)");
            shutdown(); // 开始关闭流程
        });

        process.on("SIGTERM", () => {
            console.log("\n[signal] Received SIGTERM");
            shutdown();
        });

        // 可选：监听未捕获的异常，防止程序意外崩溃而不清理
        process.on('uncaughtException', (err) => {
            console.error('[main] Uncaught Exception:', err);
            shutdown(); // 出现严重错误也尝试清理
        });

        console.log(
            "[main] Servers started. Press Ctrl+C to stop.\n" +
            `Debug endpoint: ws://localhost:${DEBUG_PORT}\n` +
            `CDP endpoint:   ws://localhost:${CDP_PORT}`
        );
    } catch (error) {
        console.error("[main] Error starting services:", error);
        process.exit(1); // 启动失败则退出
    }
};

// --- 程序入口 ---
(async () => {
    await main();
})();
