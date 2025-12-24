/**
 * Frida通用网络Hook脚本
 * 
 * 功能:
 *   - 捕获所有TCP/UDP网络连接
 *   - 监控HTTP/HTTPS请求和响应
 *   - 记录send/recv数据内容
 *   - 监控可执行内存分配（VMP/加壳检测）
 *   - 监控动态库加载
 * 
 * 适用场景:
 *   - Android/iOS应用网络流量分析
 *   - 协议逆向工程
 *   - API接口抓取
 *   - 数据包分析
 * 
 * 使用方法:
 *   frida -U -N <package_name> -l frida_universal_network_hook.js
 *   frida -U -f <package_name> -l frida_universal_network_hook.js
 * 
 * 配置选项:
 *   修改下方的 CONFIG 对象来调整过滤条件
 */

console.log("\n" + "=".repeat(70));
console.log("  Frida通用网络Hook脚本");
console.log("=".repeat(70) + "\n");

// ============================================================================
// 配置选项
// ============================================================================
const CONFIG = {
    // 显示选项
    showConnect: true,          // 显示connect()调用
    showSend: true,             // 显示send()调用
    showSendto: true,           // 显示sendto()调用
    showMmap: false,            // 显示mmap()调用（调试加壳）
    showDlopen: false,          // 显示dlopen()调用（调试动态加载）
    showSocketDetails: true,    // 显示详细的socket信息（源地址:端口 -> 目的地址:端口）
    
    // 过滤选项
    minDataLength: 0,           // 最小数据长度（字节），0=不过滤
    maxDataLength: 50000,       // 最大数据长度（字节），避免大文件传输
    
    // 显示选项
    maxDisplayLength: 1000,     // 最大显示长度（字符）
    showHex: false,             // 是否显示十六进制
    showBacktrace: false,       // 是否显示调用栈（性能影响）
    
    // 特定过滤（留空表示不过滤）
    filterIPs: [],              // 只显示这些IP的流量，例如: ["192.168.1.1", "10.0.0.1"]
    filterPorts: [],            // 只显示这些端口的流量，例如: [80, 443, 8080]
    filterKeywords: [],         // 只显示包含这些关键词的数据，例如: ["http", "api"]
};

const stats = {
    mmapExec: 0,
    dlopen: 0,
    totalSend: 0,
    totalSendto: 0,
    totalConnect: 0,
    totalBytes: 0
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

function getSocketInfo(sockfd) {
    /**
     * 获取socket的完整信息（本地地址和远程地址）
     */
    if (socketMap.has(sockfd)) {
        return socketMap.get(sockfd);
    }
    
    // 如果缓存中没有，尝试通过系统调用获取
    try {
        const getsockname = functions.getsockname;
        const getpeername = functions.getpeername;
        
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

function formatSocketInfo(sockfd, defaultRemote = null) {
    /**
     * 格式化socket信息为 "源IP:端口 -> 目的IP:端口"
     */
    if (!CONFIG.showSocketDetails) {
        if (defaultRemote) {
            return `${defaultRemote.ip}:${defaultRemote.port}`;
        }
        return '';
    }
    
    const info = getSocketInfo(sockfd);
    
    if (info) {
        return `${info.localAddr}:${info.localPort} -> ${info.remoteAddr}:${info.remotePort}`;
    } else if (defaultRemote) {
        return `unknown:0 -> ${defaultRemote.ip}:${defaultRemote.port}`;
    }
    
    return 'unknown';
}

function shouldDisplay(data, ip = null, port = null) {
    // 检查数据长度
    if (data && data.length) {
        if (data.length < CONFIG.minDataLength || data.length > CONFIG.maxDataLength) {
            return false;
        }
    }
    
    // 检查IP过滤
    if (CONFIG.filterIPs.length > 0 && ip) {
        if (!CONFIG.filterIPs.includes(ip)) {
            return false;
        }
    }
    
    // 检查端口过滤
    if (CONFIG.filterPorts.length > 0 && port) {
        if (!CONFIG.filterPorts.includes(port)) {
            return false;
        }
    }
    
    // 检查关键词过滤
    if (CONFIG.filterKeywords.length > 0 && data) {
        const dataStr = data.toString().toLowerCase();
        const hasKeyword = CONFIG.filterKeywords.some(keyword => 
            dataStr.includes(keyword.toLowerCase())
        );
        if (!hasKeyword) {
            return false;
        }
    }
    
    return true;
}

function formatData(data, maxLength = CONFIG.maxDisplayLength) {
    if (!data) return "";
    
    const dataStr = data.substring(0, maxLength);
    const suffix = data.length > maxLength ? "..." : "";
    
    return dataStr + suffix;
}

function formatHex(bytes, maxLength = 200) {
    if (!bytes || bytes.length === 0) return "";
    
    const hexStr = Array.from(bytes).map(b => 
        (b & 0xFF).toString(16).padStart(2, '0')
    ).join('');
    
    return hexStr.substring(0, maxLength) + (hexStr.length > maxLength ? "..." : "");
}

function printBacktrace(context) {
    if (!CONFIG.showBacktrace) return;
    
    console.log(`[调用栈]`);
    try {
        Thread.backtrace(context, Backtracer.ACCURATE)
            .slice(0, 10)
            .map(DebugSymbol.fromAddress)
            .forEach((sym, index) => {
                console.log(`  [${index}] ${sym}`);
            });
    } catch (e) {
        console.log(`  [!] 获取调用栈失败: ${e.message}`);
    }
}

// ============================================================================
// 第一步：查找libc.so并枚举所有导出函数
// ============================================================================
console.log("[*] 查找 libc.so...");

const libc = Process.findModuleByName("libc.so");

if (!libc) {
    console.log("[✗] 未找到 libc.so");
    throw new Error("libc.so not found");
}

console.log(`[✓] 找到 libc.so @ ${libc.base}\n`);

// 枚举所有导出函数
console.log("[*] 枚举导出函数...");
const exports = libc.enumerateExports();
console.log(`[✓] 找到 ${exports.length} 个导出函数\n`);

// ============================================================================
// 第二步：查找我们需要的函数
// ============================================================================
const functions = {};

const targetFunctions = ["mmap", "dlopen", "send", "sendto", "sendmsg", "connect", "write", "getsockname", "getpeername"];

targetFunctions.forEach(funcName => {
    const found = exports.find(exp => exp.name === funcName);
    if (found) {
        functions[funcName] = found.address;
        console.log(`[✓] ${funcName} @ ${found.address}`);
    } else {
        console.log(`[✗] ${funcName}: 未找到`);
    }
});

console.log("");

// ============================================================================
// Hook 1: 监控可执行内存分配（VMP解密代码/加壳检测）
// ============================================================================
if (CONFIG.showMmap && functions.mmap) {
    console.log("[*] Hook mmap...");
    
    try {
        Interceptor.attach(functions.mmap, {
            onEnter: function(args) {
                this.length = args[1].toInt32();
                this.prot = args[2].toInt32();
            },
            onLeave: function(retval) {
                // PROT_EXEC = 0x04
                if ((this.prot & 0x04) && this.length > 10000) {
                    stats.mmapExec++;
                    
                    console.log(`\n[${"=".repeat(68)}]`);
                    console.log(`[mmap] 可执行内存分配 #${stats.mmapExec}`);
                    console.log(`[${"=".repeat(68)}]`);
                    console.log(`[地址] ${retval}`);
                    console.log(`[大小] ${this.length} 字节 (${(this.length/1024).toFixed(2)} KB)`);
                    console.log(`[保护] 0x${this.prot.toString(16)}`);
                    
                    // 读取前32字节
                    try {
                        const bytes = retval.readByteArray(32);
                        console.log(`[前32字节] ${formatHex(new Uint8Array(bytes))}`);
                    } catch (e) {}
                    
                    console.log(`[${"=".repeat(68)}]\n`);
                }
            }
        });
        console.log("[✓] Hook mmap 成功\n");
    } catch (e) {
        console.log(`[✗] Hook mmap 失败: ${e.message}\n`);
    }
}

// ============================================================================
// Hook 2: 监控动态库加载
// ============================================================================
if (CONFIG.showDlopen && functions.dlopen) {
    console.log("[*] Hook dlopen...");
    
    try {
        Interceptor.attach(functions.dlopen, {
            onEnter: function(args) {
                try {
                    const path = args[0].readCString();
                    this.path = path;
                    
                    if (path) {
                        stats.dlopen++;
                        console.log(`\n[dlopen #${stats.dlopen}] ${path}`);
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.path) {
                    console.log(`[dlopen] 返回句柄: ${retval}\n`);
                }
            }
        });
        console.log("[✓] Hook dlopen 成功\n");
    } catch (e) {
        console.log(`[✗] Hook dlopen 失败: ${e.message}\n`);
    }
}

// ============================================================================
// Hook 3: 监控网络连接（connect）
// ============================================================================
if (CONFIG.showConnect && functions.connect) {
    console.log("[*] Hook connect...");
    
    try {
        Interceptor.attach(functions.connect, {
            onEnter: function(args) {
                this.sockfd = args[0].toInt32();
                this.sockaddr = args[1];
                
                try {
                    const addrInfo = parseSockaddr(this.sockaddr);
                    
                    if (addrInfo && shouldDisplay(null, addrInfo.ip, addrInfo.port)) {
                        stats.totalConnect++;
                        this.shouldDisplay = true;
                        this.remoteAddr = addrInfo.ip;
                        this.remotePort = addrInfo.port;
                        
                        console.log(`\n[${"=".repeat(68)}]`);
                        console.log(`[connect #${stats.totalConnect}]`);
                        console.log(`[${"=".repeat(68)}]`);
                        console.log(`[时间] ${new Date().toISOString()}`);
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
                                    
                                    if (CONFIG.showSocketDetails) {
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
        console.log("[✓] Hook connect 成功\n");
    } catch (e) {
        console.log(`[✗] Hook connect 失败: ${e.message}\n`);
    }
}

// ============================================================================
// Hook 4: 监控网络发送（send）
// ============================================================================
if (CONFIG.showSend && functions.send) {
    console.log("[*] Hook send...");
    
    try {
        Interceptor.attach(functions.send, {
            onEnter: function(args) {
                const sockfd = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                
                if (len > CONFIG.minDataLength && len < CONFIG.maxDataLength) {
                    try {
                        const data = buf.readUtf8String(Math.min(len, 5000));
                        
                        if (data && shouldDisplay(data)) {
                            stats.totalSend++;
                            stats.totalBytes += len;
                            
                            // 获取socket信息
                            const socketInfo = getSocketInfo(sockfd);
                            
                            console.log(`\n[${"=".repeat(68)}]`);
                            console.log(`[send #${stats.totalSend}] FD:${sockfd}, 长度:${len}字节`);
                            console.log(`[时间] ${new Date().toISOString()}`);
                            
                            // 显示socket详细信息
                            if (CONFIG.showSocketDetails && socketInfo) {
                                console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                            }
                            
                            console.log(`[${"=".repeat(68)}]`);
                            console.log(formatData(data));
                            
                            if (CONFIG.showHex) {
                                const bytes = buf.readByteArray(Math.min(len, 200));
                                console.log(`\n[十六进制] ${formatHex(new Uint8Array(bytes))}`);
                            }
                            
                            printBacktrace(this.context);
                            
                            console.log(`[${"=".repeat(68)}]\n`);
                        }
                    } catch (e) {
                        // 数据不是UTF-8，尝试显示十六进制
                        if (CONFIG.showHex) {
                            try {
                                const socketInfo = getSocketInfo(sockfd);
                                const bytes = buf.readByteArray(Math.min(len, 200));
                                
                                stats.totalSend++;
                                stats.totalBytes += len;
                                
                                console.log(`\n[send #${stats.totalSend}] FD:${sockfd}, 长度:${len}字节 (二进制数据)`);
                                
                                if (CONFIG.showSocketDetails && socketInfo) {
                                    console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                                }
                                
                                console.log(`[十六进制] ${formatHex(new Uint8Array(bytes))}\n`);
                            } catch (e2) {}
                        }
                    }
                }
            }
        });
        console.log("[✓] Hook send 成功\n");
    } catch (e) {
        console.log(`[✗] Hook send 失败: ${e.message}\n`);
    }
}

// ============================================================================
// Hook 5: 监控网络发送（sendto，用于UDP）
// ============================================================================
if (CONFIG.showSendto && functions.sendto) {
    console.log("[*] Hook sendto...");
    
    try {
        Interceptor.attach(functions.sendto, {
            onEnter: function(args) {
                const sockfd = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                // sendto的第5个参数(args[4])是目标地址
                const destAddr = args[4];
                
                if (len > CONFIG.minDataLength && len < CONFIG.maxDataLength) {
                    try {
                        const data = buf.readUtf8String(Math.min(len, 5000));
                        
                        if (data && shouldDisplay(data)) {
                            stats.totalSendto++;
                            stats.totalBytes += len;
                            
                            // 解析目标地址
                            let destInfo = null;
                            try {
                                if (!destAddr.isNull()) {
                                    destInfo = parseSockaddr(destAddr);
                                }
                            } catch (e) {}
                            
                            // 获取socket信息
                            const socketInfo = getSocketInfo(sockfd);
                            
                            console.log(`\n[${"=".repeat(68)}]`);
                            console.log(`[sendto #${stats.totalSendto}] FD:${sockfd}, 长度:${len}字节`);
                            console.log(`[时间] ${new Date().toISOString()}`);
                            
                            // 显示socket详细信息
                            if (CONFIG.showSocketDetails) {
                                if (socketInfo) {
                                    console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                                } else if (destInfo) {
                                    console.log(`[目标] ${destInfo.ip}:${destInfo.port}`);
                                }
                            }
                            
                            console.log(`[${"=".repeat(68)}]`);
                            console.log(formatData(data));
                            
                            if (CONFIG.showHex) {
                                const bytes = buf.readByteArray(Math.min(len, 200));
                                console.log(`\n[十六进制] ${formatHex(new Uint8Array(bytes))}`);
                            }
                            
                            printBacktrace(this.context);
                            
                            console.log(`[${"=".repeat(68)}]\n`);
                        }
                    } catch (e) {
                        // 数据不是UTF-8
                        if (CONFIG.showHex) {
                            try {
                                const bytes = buf.readByteArray(Math.min(len, 200));
                                const socketInfo = getSocketInfo(sockfd);
                                
                                stats.totalSendto++;
                                stats.totalBytes += len;
                                
                                console.log(`\n[sendto #${stats.totalSendto}] FD:${sockfd}, 长度:${len}字节 (二进制数据)`);
                                
                                if (CONFIG.showSocketDetails && socketInfo) {
                                    console.log(`[Socket] ${socketInfo.localAddr}:${socketInfo.localPort} -> ${socketInfo.remoteAddr}:${socketInfo.remotePort}`);
                                }
                                
                                console.log(`[十六进制] ${formatHex(new Uint8Array(bytes))}\n`);
                            } catch (e2) {}
                        }
                    }
                }
            }
        });
        console.log("[✓] Hook sendto 成功\n");
    } catch (e) {
        console.log(`[✗] Hook sendto 失败: ${e.message}\n`);
    }
}

// ============================================================================
// 统计和提示
// ============================================================================
console.log("=".repeat(70));
console.log("[✓] Hook安装完成");
console.log("=".repeat(70));
console.log("[*] 开始监控网络流量...\n");

console.log("[配置]");
console.log(`  显示connect: ${CONFIG.showConnect}`);
console.log(`  显示send: ${CONFIG.showSend}`);
console.log(`  显示sendto: ${CONFIG.showSendto}`);
console.log(`  显示Socket详情: ${CONFIG.showSocketDetails} ${CONFIG.showSocketDetails ? '(源IP:端口 -> 目的IP:端口)' : ''}`);
console.log(`  最小数据长度: ${CONFIG.minDataLength} 字节`);
console.log(`  最大数据长度: ${CONFIG.maxDataLength} 字节`);
console.log(`  显示十六进制: ${CONFIG.showHex}`);
console.log(`  显示调用栈: ${CONFIG.showBacktrace}`);

if (CONFIG.filterIPs.length > 0) {
    console.log(`  过滤IP: ${CONFIG.filterIPs.join(", ")}`);
}
if (CONFIG.filterPorts.length > 0) {
    console.log(`  过滤端口: ${CONFIG.filterPorts.join(", ")}`);
}
if (CONFIG.filterKeywords.length > 0) {
    console.log(`  过滤关键词: ${CONFIG.filterKeywords.join(", ")}`);
}

console.log("\n" + "=".repeat(70));

// 定期显示统计
setInterval(() => {
    if (stats.totalSend > 0 || stats.totalConnect > 0 || stats.totalSendto > 0) {
        console.log(`\n[统计] connect:${stats.totalConnect} | send:${stats.totalSend} | sendto:${stats.totalSendto} | 总流量:${(stats.totalBytes/1024).toFixed(2)}KB\n`);
    }
}, 60000);

// 异常处理
Process.setExceptionHandler((details) => {
    if (!details.message.includes("access violation")) {
        console.log(`[!] 异常: ${details.type} @ ${details.address}`);
    }
    return true;
});

