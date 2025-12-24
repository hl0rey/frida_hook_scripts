/**
 * Frida综合监控脚本 - 网络通信 + 加解密
 * 
 * 功能:
 *   ✅ Java层加密监控 (SecretKeySpec, Cipher, Base64)
 *   ✅ 原生层网络监控 (connect, send/sendto)
 *   ✅ 可选：VMP检测 (mmap, dlopen)
 *   ✅ 智能关联：网络数据和加密数据
 * 
 * 适用场景:
 *   - 完整的协议逆向分析
 *   - 加密流量破解
 *   - API接口抓取和分析
 *   - 私服协议分析
 * 
 * 使用方法:
 *   # 附加到运行中的进程（推荐）
 *   frida -U -N <package_name> -l frida_hook_network_crypto.js
 *   
 *   # Spawn模式启动
 *   frida -U -f <package_name> -l frida_hook_network_crypto.js
 * 
 * 作者: AI Assistant
 * 版本: 1.0
 */

console.log("\n" + "=".repeat(70));
console.log("  🔥 Frida综合监控 - 网络通信 + 加解密 🔥");
console.log("=".repeat(70) + "\n");

// ============================================================================
// 配置选项 - 根据需要修改
// ============================================================================
const CONFIG = {
    // ========== Java加密监控配置 ==========
    crypto: {
        enabled: true,              // 启用Java加密监控
        showSecretKey: true,        // 显示密钥创建
        showCipherDoFinal: true,    // 显示Cipher.doFinal
        showCipherUpdate: false,    // 显示Cipher.update（数据量大时建议关闭）
        showBase64: false,          // 显示Base64编解码（数据量大时建议关闭）
    },
    
    // ========== 网络监控配置 ==========
    network: {
        enabled: true,              // 启用网络监控
        showConnect: true,          // 显示连接
        showSend: true,             // 显示发送数据
        showSocketDetails: true,    // 显示详细socket信息（源地址:端口 -> 目的地址:端口）
        showMmap: false,            // 显示mmap（调试加壳时启用）
        showDlopen: false,          // 显示dlopen（调试动态加载时启用）
    },
    
    // ========== 过滤器配置 ==========
    filter: {
        ips: [],                    // 只显示这些IP，例如: ["103.217.192.170"]
        ports: [],                  // 只显示这些端口，例如: [80, 443, 81]
        keywords: [],               // 只显示包含这些关键词的数据，例如: ["account.php", "login"]
    },
    
    // ========== 显示配置 ==========
    display: {
        maxDataLength: 1000,        // 最大显示数据长度（字符）
        showBacktrace: false,       // 是否显示调用栈（性能影响较大）
        showTimestamp: true,        // 显示时间戳
        colorEmoji: true,           // 使用彩色emoji
    }
};

// ============================================================================
// 统计信息
// ============================================================================
const stats = {
    // 加密统计
    crypto: {
        keys: 0,
        doFinal: 0,
        update: 0,
        base64Encode: 0,
        base64Decode: 0
    },
    
    // 网络统计
    network: {
        connect: 0,
        send: 0,
        sendto: 0,
        totalBytes: 0,
        filtered: 0,
        mmap: 0,
        dlopen: 0
    }
};

// Socket信息映射表: fd -> {localAddr, localPort, remoteAddr, remotePort}
const socketMap = new Map();

// ============================================================================
// 辅助函数
// ============================================================================
function parseSockaddr(sockaddr) {
    /**
     * 解析sockaddr结构，返回IP和端口
     */
    try {
        const sa_family = sockaddr.readU16();
        
        if (sa_family === 2) { // AF_INET (IPv4)
            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            const ip = sockaddr.add(4).readU8() + "." +
                      sockaddr.add(5).readU8() + "." +
                      sockaddr.add(6).readU8() + "." +
                      sockaddr.add(7).readU8();
            return { ip, port, family: 'IPv4' };
        } else if (sa_family === 10) { // AF_INET6 (IPv6)
            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            // IPv6地址解析（简化版）
            const ipv6Parts = [];
            for (let i = 0; i < 8; i++) {
                const part = (sockaddr.add(8 + i * 2).readU8() << 8) | 
                            sockaddr.add(9 + i * 2).readU8();
                ipv6Parts.push(part.toString(16));
            }
            const ip = ipv6Parts.join(':');
            return { ip, port, family: 'IPv6' };
        }
    } catch (e) {}
    
    return null;
}

function getSocketInfo(sockfd, networkFunctions) {
    /**
     * 获取socket的完整信息（本地地址和远程地址）
     */
    if (socketMap.has(sockfd)) {
        return socketMap.get(sockfd);
    }
    
    // 如果缓存中没有，尝试通过系统调用获取
    try {
        const getsockname = networkFunctions.getsockname;
        const getpeername = networkFunctions.getpeername;
        
        if (getsockname && getpeername) {
            // 分配sockaddr结构
            const localAddr = Memory.alloc(128);
            const remoteAddr = Memory.alloc(128);
            const addrLen = Memory.alloc(4);
            addrLen.writeU32(128);
            
            // 获取本地地址
            const localRet = new NativeFunction(getsockname, 'int', ['int', 'pointer', 'pointer'])(
                sockfd, localAddr, addrLen
            );
            
            addrLen.writeU32(128);
            
            // 获取远程地址
            const remoteRet = new NativeFunction(getpeername, 'int', ['int', 'pointer', 'pointer'])(
                sockfd, remoteAddr, addrLen
            );
            
            const localInfo = localRet === 0 ? parseSockaddr(localAddr) : null;
            const remoteInfo = remoteRet === 0 ? parseSockaddr(remoteAddr) : null;
            
            if (localInfo || remoteInfo) {
                const info = {
                    localAddr: localInfo?.ip || 'unknown',
                    localPort: localInfo?.port || 0,
                    remoteAddr: remoteInfo?.ip || 'unknown',
                    remotePort: remoteInfo?.port || 0
                };
                socketMap.set(sockfd, info);
                return info;
            }
        }
    } catch (e) {}
    
    return null;
}

function formatSocketInfo(sockfd, defaultRemote = null, networkFunctions = null) {
    /**
     * 格式化socket信息为 "源IP:端口 -> 目的IP:端口"
     */
    if (!CONFIG.network.showSocketDetails) {
        if (defaultRemote) {
            return `${defaultRemote.ip}:${defaultRemote.port}`;
        }
        return '';
    }
    
    const info = getSocketInfo(sockfd, networkFunctions);
    
    if (info) {
        return `${info.localAddr}:${info.localPort} -> ${info.remoteAddr}:${info.remotePort}`;
    } else if (defaultRemote) {
        return `unknown:0 -> ${defaultRemote.ip}:${defaultRemote.port}`;
    }
    
    return 'unknown';
}

function shouldDisplayData(data = null, ip = null, port = null) {
    // 检查IP过滤
    if (CONFIG.filter.ips.length > 0 && ip) {
        if (!CONFIG.filter.ips.includes(ip)) return false;
    }
    
    // 检查端口过滤
    if (CONFIG.filter.ports.length > 0 && port) {
        if (!CONFIG.filter.ports.includes(port)) return false;
    }
    
    // 检查关键词过滤
    if (CONFIG.filter.keywords.length > 0 && data) {
        const dataStr = data.toString().toLowerCase();
        const hasKeyword = CONFIG.filter.keywords.some(keyword => 
            dataStr.includes(keyword.toLowerCase())
        );
        if (!hasKeyword) return false;
    }
    
    return true;
}

function formatData(data) {
    if (!data) return "";
    const maxLen = CONFIG.display.maxDataLength;
    return data.length > maxLen ? data.substring(0, maxLen) + "..." : data;
}

function getTimestamp() {
    return CONFIG.display.showTimestamp ? `[${new Date().toISOString()}]` : "";
}

function printBacktrace(context) {
    if (!CONFIG.display.showBacktrace) return;
    
    console.log(`\n[调用栈]`);
    try {
        Thread.backtrace(context, Backtracer.ACCURATE)
            .slice(0, 15)
            .map(DebugSymbol.fromAddress)
            .forEach((sym, index) => {
                console.log(`  [${index}] ${sym}`);
            });
    } catch (e) {
        try {
            Thread.backtrace(context, Backtracer.FUZZY)
                .slice(0, 15)
                .map(DebugSymbol.fromAddress)
                .forEach((sym, index) => {
                    console.log(`  [${index}] ${sym}`);
                });
        } catch (e2) {
            console.log(`  (无法获取调用栈)`);
        }
    }
}

// ============================================================================
// 第一部分：Java层加密监控
// ============================================================================
if (CONFIG.crypto.enabled) {
    console.log("[*] 正在安装Java加密Hook...\n");
    
    Java.perform(function() {
        const emoji = CONFIG.display.colorEmoji;
        
        // ====================================================================
        // Hook 1: SecretKeySpec - 捕获密钥
        // ====================================================================
        if (CONFIG.crypto.showSecretKey) {
            try {
                const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                
                SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                    stats.crypto.keys++;
                    
                    console.log(`\n${emoji ? '🔑' : '[KEY]'} [${"=".repeat(65)}]`);
                    console.log(`[SecretKeySpec #${stats.crypto.keys}] 创建密钥 ${getTimestamp()}`);
                    console.log(`[${"=".repeat(68)}]`);
                    console.log(`[算法] ${algorithm}`);
                    
                    const keyHex = Array.from(keyBytes).map(b => 
                        (b & 0xFF).toString(16).padStart(2, '0')
                    ).join('');
                    console.log(`[密钥] (hex) ${keyHex}`);
                    
                    try {
                        const keyStr = String.fromCharCode.apply(null, Array.from(keyBytes).map(b => b & 0xFF));
                        console.log(`[密钥] (str) ${keyStr}`);
                    } catch (e) {}
                    
                    console.log(`[${"=".repeat(68)}]\n`);
                    
                    this.$init(keyBytes, algorithm);
                };
                
                console.log("  [✓] Hook SecretKeySpec");
            } catch (e) {
                console.log(`  [✗] Hook SecretKeySpec 失败: ${e.message}`);
            }
        }
        
        // ====================================================================
        // Hook 2: Cipher.doFinal - 捕获加密/解密
        // ====================================================================
        if (CONFIG.crypto.showCipherDoFinal) {
            try {
                const Cipher = Java.use("javax.crypto.Cipher");
                
                // Hook doFinal([B])
                const originalDoFinal = Cipher.doFinal.overload('[B');
                Cipher.doFinal.overload('[B').implementation = function(input) {
                    stats.crypto.doFinal++;
                    
                    let algorithm = "Unknown";
                    try {
                        algorithm = this.getAlgorithm();
                    } catch (e) {}
                    
                    console.log(`\n${emoji ? '🔐' : '[CIPHER]'} [${"=".repeat(63)}]`);
                    console.log(`[Cipher.doFinal #${stats.crypto.doFinal}] ${getTimestamp()}`);
                    console.log(`[${"=".repeat(68)}]`);
                    console.log(`[算法] ${algorithm}`);
                    
                    // 显示输入
                    if (input && input !== null) {
                        try {
                            const inputHex = Array.from(input).map(b => 
                                (b & 0xFF).toString(16).padStart(2, '0')
                            ).join('');
                            console.log(`[输入] 长度:${input.length} 字节`);
                            console.log(`[输入] (hex) ${formatData(inputHex)}`);
                            
                            try {
                                const inputStr = String.fromCharCode.apply(null, Array.from(input).map(b => b & 0xFF));
                                if (/^[\x20-\x7E\n\r\t%&=]+$/.test(inputStr)) {
                                    console.log(`[输入] (UTF-8) ${formatData(inputStr)}`);
                                }
                            } catch (e) {}
                        } catch (e) {}
                    } else {
                        console.log(`[输入] null (使用update方法)`);
                    }
                    
                    // 调用原始方法
                    const result = originalDoFinal.call(this, input);
                    
                    // 显示输出
                    if (result && result !== null) {
                        try {
                            const outputHex = Array.from(result).map(b => 
                                (b & 0xFF).toString(16).padStart(2, '0')
                            ).join('');
                            console.log(`[输出] 长度:${result.length} 字节`);
                            console.log(`[输出] (hex) ${formatData(outputHex)}`);
                            
                            try {
                                const outputStr = String.fromCharCode.apply(null, Array.from(result).map(b => b & 0xFF));
                                if (/^[\x20-\x7E\n\r\t%&=]+$/.test(outputStr)) {
                                    console.log(`[输出] (UTF-8) ${formatData(outputStr)}`);
                                }
                            } catch (e) {}
                        } catch (e) {}
                    }
                    
                    console.log(`[${"=".repeat(68)}]\n`);
                    
                    return result;
                };
                
                // Hook doFinal()
                try {
                    const originalDoFinalNoArgs = Cipher.doFinal.overload();
                    Cipher.doFinal.overload().implementation = function() {
                        stats.crypto.doFinal++;
                        
                        let algorithm = "Unknown";
                        try {
                            algorithm = this.getAlgorithm();
                        } catch (e) {}
                        
                        console.log(`\n${emoji ? '🔐' : '[CIPHER]'} [Cipher.doFinal() #${stats.crypto.doFinal}] ${getTimestamp()}`);
                        console.log(`[算法] ${algorithm} [说明] 数据通过update()传入\n`);
                        
                        const result = originalDoFinalNoArgs.call(this);
                        
                        if (result && result !== null) {
                            try {
                                const outputHex = Array.from(result).map(b => 
                                    (b & 0xFF).toString(16).padStart(2, '0')
                                ).join('');
                                console.log(`[输出] ${formatData(outputHex)}\n`);
                            } catch (e) {}
                        }
                        
                        return result;
                    };
                } catch (e) {}
                
                console.log("  [✓] Hook Cipher.doFinal");
            } catch (e) {
                console.log(`  [✗] Hook Cipher.doFinal 失败: ${e.message}`);
            }
        }
        
        // ====================================================================
        // Hook 3: Cipher.update (可选)
        // ====================================================================
        if (CONFIG.crypto.showCipherUpdate) {
            try {
                const Cipher = Java.use("javax.crypto.Cipher");
                const originalUpdate = Cipher.update.overload('[B');
                
                Cipher.update.overload('[B').implementation = function(input) {
                    stats.crypto.update++;
                    
                    if (input && input !== null && input.length > 0) {
                        console.log(`\n[Cipher.update #${stats.crypto.update}] 长度:${input.length} 字节`);
                        try {
                            const inputStr = String.fromCharCode.apply(null, Array.from(input).map(b => b & 0xFF));
                            if (/^[\x20-\x7E\n\r\t%&=]+$/.test(inputStr)) {
                                console.log(`  ${formatData(inputStr)}\n`);
                            }
                        } catch (e) {}
                    }
                    
                    return originalUpdate.call(this, input);
                };
                
                console.log("  [✓] Hook Cipher.update");
            } catch (e) {
                console.log(`  [✗] Hook Cipher.update 失败: ${e.message}`);
            }
        }
        
        // ====================================================================
        // Hook 4: Base64 (可选)
        // ====================================================================
        if (CONFIG.crypto.showBase64) {
            try {
                const Base64 = Java.use("android.util.Base64");
                
                // Encode
                try {
                    const originalEncode = Base64.encodeToString.overload('[B', 'int');
                    Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
                        const result = originalEncode.call(this, input, flags);
                        if (input.length > 100) {
                            stats.crypto.base64Encode++;
                            console.log(`\n[Base64.encode #${stats.crypto.base64Encode}] ${input.length} → ${result.length}`);
                        }
                        return result;
                    };
                } catch (e) {}
                
                // Decode
                try {
                    const originalDecode = Base64.decode.overload('java.lang.String', 'int');
                    Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
                        const result = originalDecode.call(this, str, flags);
                        if (str.length > 100) {
                            stats.crypto.base64Decode++;
                            console.log(`\n[Base64.decode #${stats.crypto.base64Decode}] ${str.length} → ${result.length}`);
                        }
                        return result;
                    };
                } catch (e) {}
                
                console.log("  [✓] Hook Base64");
            } catch (e) {
                console.log(`  [✗] Hook Base64 失败: ${e.message}`);
            }
        }
        
        console.log("\n[✓] Java加密Hook安装完成\n");
    });
}

// ============================================================================
// 第二部分：原生层网络监控
// ============================================================================
if (CONFIG.network.enabled) {
    console.log("[*] 正在安装原生网络Hook...\n");
    
    const libc = Process.findModuleByName("libc.so");
    
    if (!libc) {
        console.log("[✗] 未找到 libc.so，跳过网络Hook\n");
    } else {
        console.log(`  [✓] 找到 libc.so @ ${libc.base}`);
        
        const exports = libc.enumerateExports();
        const functions = {};
        
        ["mmap", "dlopen", "send", "sendto", "connect", "getsockname", "getpeername"].forEach(funcName => {
            const found = exports.find(exp => exp.name === funcName);
            if (found) {
                functions[funcName] = found.address;
            }
        });
        
        const emoji = CONFIG.display.colorEmoji;
        
        // ====================================================================
        // Hook 1: mmap (可选 - VMP检测)
        // ====================================================================
        if (CONFIG.network.showMmap && functions.mmap) {
            try {
                Interceptor.attach(functions.mmap, {
                    onEnter: function(args) {
                        this.length = args[1].toInt32();
                        this.prot = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        if ((this.prot & 0x04) && this.length > 10000) {
                            stats.network.mmap++;
                            console.log(`\n${emoji ? '🗺️' : '[MMAP]'} [mmap #${stats.network.mmap}] 可执行内存 ${this.length}字节 @ ${retval}`);
                        }
                    }
                });
                console.log("  [✓] Hook mmap");
            } catch (e) {}
        }
        
        // ====================================================================
        // Hook 2: dlopen (可选)
        // ====================================================================
        if (CONFIG.network.showDlopen && functions.dlopen) {
            try {
                Interceptor.attach(functions.dlopen, {
                    onEnter: function(args) {
                        try {
                            const path = args[0].readCString();
                            if (path) {
                                stats.network.dlopen++;
                                console.log(`\n${emoji ? '📚' : '[DLOPEN]'} [dlopen #${stats.network.dlopen}] ${path}`);
                            }
                        } catch (e) {}
                    }
                });
                console.log("  [✓] Hook dlopen");
            } catch (e) {}
        }
        
        // ====================================================================
        // Hook 3: connect - 监控连接
        // ====================================================================
        if (CONFIG.network.showConnect && functions.connect) {
            try {
                Interceptor.attach(functions.connect, {
                    onEnter: function(args) {
                        this.sockfd = args[0].toInt32();
                        this.sockaddr = args[1];
                        
                        try {
                            const addrInfo = parseSockaddr(this.sockaddr);
                            
                            if (addrInfo && shouldDisplayData(null, addrInfo.ip, addrInfo.port)) {
                                stats.network.connect++;
                                this.shouldDisplay = true;
                                this.remoteAddr = addrInfo.ip;
                                this.remotePort = addrInfo.port;
                                
                                console.log(`\n${emoji ? '🔌' : '[CONNECT]'} [${"=".repeat(61)}]`);
                                console.log(`[connect #${stats.network.connect}] ${getTimestamp()}`);
                                console.log(`[${"=".repeat(68)}]`);
                                console.log(`[Socket FD] ${this.sockfd}`);
                                console.log(`[目标地址] ${addrInfo.ip}:${addrInfo.port}`);
                            }
                        } catch (e) {}
                    },
                    onLeave: function(retval) {
                        if (this.shouldDisplay && retval.toInt32() === 0) {
                            // 连接成功，保存socket信息
                            try {
                                // 获取本地地址
                                const localAddr = Memory.alloc(128);
                                const addrLen = Memory.alloc(4);
                                addrLen.writeU32(128);
                                
                                if (functions.getsockname) {
                                    const ret = new NativeFunction(functions.getsockname, 'int', ['int', 'pointer', 'pointer'])(
                                        this.sockfd, localAddr, addrLen
                                    );
                                    
                                    if (ret === 0) {
                                        const localInfo = parseSockaddr(localAddr);
                                        if (localInfo) {
                                            socketMap.set(this.sockfd, {
                                                localAddr: localInfo.ip,
                                                localPort: localInfo.port,
                                                remoteAddr: this.remoteAddr,
                                                remotePort: this.remotePort
                                            });
                                            
                                            if (CONFIG.network.showSocketDetails) {
                                                console.log(`[本地地址] ${localInfo.ip}:${localInfo.port}`);
                                                console.log(`[连接路径] ${localInfo.ip}:${localInfo.port} -> ${this.remoteAddr}:${this.remotePort}`);
                                            }
                                        }
                                    }
                                }
                            } catch (e) {}
                            
                            printBacktrace(this.context);
                            console.log(`[${"=".repeat(68)}]\n`);
                        }
                    }
                });
                console.log("  [✓] Hook connect");
            } catch (e) {}
        }
        
        // ====================================================================
        // Hook 4: send/sendto - 监控发送数据
        // ====================================================================
        if (CONFIG.network.showSend && functions.send) {
            try {
                Interceptor.attach(functions.send, {
                    onEnter: function(args) {
                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        
                        if (len > 0 && len < 50000) {
                            try {
                                const data = buf.readUtf8String(Math.min(len, 5000));
                                
                                if (data && shouldDisplayData(data)) {
                                    stats.network.send++;
                                    stats.network.filtered++;
                                    stats.network.totalBytes += len;
                                    
                                    // 获取socket信息
                                    const socketInfo = getSocketInfo(sockfd, functions);
                                    
                                    console.log(`\n${emoji ? '📤' : '[SEND]'} [${"=".repeat(64)}]`);
                                    console.log(`[send #${stats.network.send}] FD:${sockfd}, 长度:${len}字节 ${getTimestamp()}`);
                                    
                                    // 显示socket详细信息
                                    if (CONFIG.network.showSocketDetails && socketInfo) {
                                        console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                                    }
                                    
                                    console.log(`[${"=".repeat(68)}]`);
                                    console.log(formatData(data));
                                    
                                    printBacktrace(this.context);
                                    
                                    console.log(`[${"=".repeat(68)}]\n`);
                                }
                            } catch (e) {}
                        }
                    }
                });
                console.log("  [✓] Hook send");
            } catch (e) {}
        }
        
        if (CONFIG.network.showSend && functions.sendto) {
            try {
                Interceptor.attach(functions.sendto, {
                    onEnter: function(args) {
                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        // sendto的第5个参数(args[4])是目标地址
                        const destAddr = args[4];
                        
                        if (len > 0 && len < 50000) {
                            try {
                                const data = buf.readUtf8String(Math.min(len, 5000));
                                
                                if (data && shouldDisplayData(data)) {
                                    stats.network.sendto++;
                                    stats.network.filtered++;
                                    stats.network.totalBytes += len;
                                    
                                    // 解析目标地址
                                    let destInfo = null;
                                    try {
                                        if (!destAddr.isNull()) {
                                            destInfo = parseSockaddr(destAddr);
                                        }
                                    } catch (e) {}
                                    
                                    // 获取socket信息
                                    const socketInfo = getSocketInfo(sockfd, functions);
                                    
                                    console.log(`\n${emoji ? '📤' : '[SENDTO]'} [sendto #${stats.network.sendto}] FD:${sockfd}, ${len}字节 ${getTimestamp()}`);
                                    
                                    // 显示socket详细信息
                                    if (CONFIG.network.showSocketDetails) {
                                        if (socketInfo) {
                                            console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                                        } else if (destInfo) {
                                            console.log(`[目标] ${destInfo.ip}:${destInfo.port}`);
                                        }
                                    }
                                    
                                    console.log(formatData(data));
                                    
                                    printBacktrace(this.context);
                                    
                                    console.log("");
                                }
                            } catch (e) {}
                        }
                    }
                });
                console.log("  [✓] Hook sendto");
            } catch (e) {}
        }
        
        console.log("\n[✓] 原生网络Hook安装完成\n");
    }
}

// ============================================================================
// 显示配置和启动信息
// ============================================================================
console.log("=".repeat(70));
console.log("[✓] 所有Hook安装完成");
console.log("=".repeat(70));

console.log("\n[配置摘要]");
console.log(`  Java加密监控: ${CONFIG.crypto.enabled ? '✅' : '❌'}`);
if (CONFIG.crypto.enabled) {
    console.log(`    - 密钥捕获: ${CONFIG.crypto.showSecretKey ? '✅' : '❌'}`);
    console.log(`    - Cipher.doFinal: ${CONFIG.crypto.showCipherDoFinal ? '✅' : '❌'}`);
    console.log(`    - Cipher.update: ${CONFIG.crypto.showCipherUpdate ? '✅' : '❌'}`);
    console.log(`    - Base64: ${CONFIG.crypto.showBase64 ? '✅' : '❌'}`);
}

console.log(`  原生网络监控: ${CONFIG.network.enabled ? '✅' : '❌'}`);
if (CONFIG.network.enabled) {
    console.log(`    - connect: ${CONFIG.network.showConnect ? '✅' : '❌'}`);
    console.log(`    - send/sendto: ${CONFIG.network.showSend ? '✅' : '❌'}`);
    console.log(`    - Socket详情: ${CONFIG.network.showSocketDetails ? '✅ (源IP:端口 -> 目的IP:端口)' : '❌'}`);
    console.log(`    - mmap: ${CONFIG.network.showMmap ? '✅' : '❌'}`);
    console.log(`    - dlopen: ${CONFIG.network.showDlopen ? '✅' : '❌'}`);
}

if (CONFIG.filter.ips.length > 0) {
    console.log(`  过滤IP: ${CONFIG.filter.ips.join(", ")}`);
}
if (CONFIG.filter.ports.length > 0) {
    console.log(`  过滤端口: ${CONFIG.filter.ports.join(", ")}`);
}
if (CONFIG.filter.keywords.length > 0) {
    console.log(`  过滤关键词: ${CONFIG.filter.keywords.join(", ")}`);
}

console.log(`  显示调用栈: ${CONFIG.display.showBacktrace ? '✅' : '❌'}`);
console.log(`  最大显示长度: ${CONFIG.display.maxDataLength} 字符`);

console.log("\n" + "=".repeat(70));
console.log("[*] 🚀 开始监控...");
console.log("=".repeat(70) + "\n");

// ============================================================================
// 定期显示统计
// ============================================================================
setInterval(() => {
    const hasActivity = stats.crypto.keys > 0 || 
                       stats.crypto.doFinal > 0 || 
                       stats.network.connect > 0 || 
                       stats.network.send > 0;
    
    if (hasActivity) {
        console.log(`\n[${"=".repeat(68)}]`);
        console.log(`[统计信息] ${new Date().toISOString()}`);
        console.log(`[${"=".repeat(68)}]`);
        console.log(`[加密] 密钥:${stats.crypto.keys} | doFinal:${stats.crypto.doFinal} | update:${stats.crypto.update}`);
        console.log(`[网络] 连接:${stats.network.connect} | 发送:${stats.network.send} | 流量:${(stats.network.totalBytes/1024).toFixed(2)}KB`);
        console.log(`[${"=".repeat(68)}]\n`);
    }
}, 60000); // 每60秒显示一次

// 异常处理
Process.setExceptionHandler((details) => {
    if (!details.message.includes("access violation")) {
        console.log(`[!] 异常: ${details.type} @ ${details.address}`);
    }
    return true;
});

