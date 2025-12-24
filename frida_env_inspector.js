/**
 * Frida APK运行环境全面检测脚本
 * 
 * 功能:
 *   - SO库检测（已加载 + 动态监控）
 *   - Java包/类检测
 *   - Unity/Mono/IL2CPP检测
 *   - 游戏引擎识别
 *   - 加密/网络库识别
 *   - Root检测机制识别
 *   - 反调试检测
 *   - 设备信息
 *   - 进程信息
 *   - 导出完整报告
 * 
 * 使用方法:
 *   frida -U -N <package_name> -l frida_env_inspector.js
 *   或
 *   frida -U -f <package_name> -l frida_env_inspector.js
 * 
 * 作者: AI Assistant
 * 版本: 1.0
 */

console.log("\n" + "=".repeat(80));
console.log("  🔍 APK运行环境全面检测工具");
console.log("=".repeat(80) + "\n");

// ============================================================================
// 配置选项
// ============================================================================
const CONFIG = {
    // 检测选项
    detection: {
        checkModules: true,          // 检测SO库
        checkJavaPackages: true,     // 检测Java包
        checkUnity: true,            // 检测Unity
        checkGameEngines: true,      // 检测游戏引擎
        checkNetworkLibs: true,      // 检测网络库
        checkCryptoLibs: true,       // 检测加密库
        checkAntiDebug: true,        // 检测反调试
        checkRootDetection: true,    // 检测Root检测
        monitorLoading: true,        // 监控动态加载
    },
    
    // 过滤选项
    filter: {
        skipSystemModules: true,     // 跳过系统库
        skipSystemPackages: true,    // 跳过系统包
        minModuleSize: 1024,         // 最小模块大小（字节）
    },
    
    // 导出选项
    export: {
        enabled: true,               // 启用导出
        savePath: "/sdcard/",        // 保存路径
        filename: "app_env_report.json",  // 文件名
    },
    
    // 显示选项
    display: {
        showModuleDetails: true,     // 显示模块详情
        showExports: false,          // 显示导出函数（慢）
        maxExportsPerModule: 10,     // 每个模块最多显示的导出数
        colorOutput: true,           // 彩色输出
    },
};

// ============================================================================
// 全局数据收集
// ============================================================================
const reportData = {
    timestamp: new Date().toISOString(),
    device: {},
    process: {},
    modules: {
        loaded: [],
        dynamicallyLoaded: [],
        statistics: {
            total: 0,
            byType: {},
        }
    },
    java: {
        packages: [],
        classes: {
            total: 0,
            byPackage: {},
        }
    },
    detection: {
        unity: null,
        gameEngine: null,
        networkLibs: [],
        cryptoLibs: [],
        antiDebug: [],
        rootDetection: [],
    },
};

// ============================================================================
// 系统库/包黑名单
// ============================================================================
const SYSTEM_LIB_PATTERNS = [
    /^\/system\//,
    /^\/vendor\//,
    /^\/apex\//,
    /^libc\./,
    /^libm\./,
    /^libdl\./,
    /^libz\./,
    /^liblog\./,
    /^libandroid/,
    /^libOpenGL/,
    /^libEGL/,
    /^libvulkan/,
];

const SYSTEM_PACKAGE_PATTERNS = [
    /^java\./,
    /^javax\./,
    /^android\./,
    /^com\.android\./,
    /^dalvik\./,
    /^sun\./,
    /^com\.google\.android\./,
];

// ============================================================================
// 已知库特征
// ============================================================================
const KNOWN_LIBRARIES = {
    // 游戏引擎
    gameEngines: {
        'Unity IL2CPP': { pattern: /libil2cpp\.so$/, type: 'Unity' },
        'Unity Mono': { pattern: /libmono\.so$/, type: 'Unity' },
        'Unreal Engine': { pattern: /libUE4\.so$/, type: 'Unreal' },
        'Cocos2d-x': { pattern: /libcocos2d(cpp|lua)?\.so$/, type: 'Cocos' },
        'Godot': { pattern: /libgodot\.so$/, type: 'Godot' },
    },
    
    // 网络库
    networkLibs: {
        'OkHttp': { pattern: /okhttp/i, type: 'HTTP' },
        'Retrofit': { pattern: /retrofit/i, type: 'HTTP' },
        'Volley': { pattern: /volley/i, type: 'HTTP' },
        'BestHTTP': { pattern: /besthttp/i, type: 'HTTP' },
        'WebSocket': { pattern: /websocket/i, type: 'WebSocket' },
        'gRPC': { pattern: /grpc/i, type: 'RPC' },
        'Protobuf': { pattern: /protobuf/i, type: 'Serialization' },
    },
    
    // 加密库
    cryptoLibs: {
        'OpenSSL': { pattern: /libcrypto\.so$|libssl\.so$/, type: 'Crypto' },
        'BoringSSL': { pattern: /libboringssl\.so$/, type: 'Crypto' },
        'Conscrypt': { pattern: /conscrypt/i, type: 'Crypto' },
        'Bouncy Castle': { pattern: /bouncycastle/i, type: 'Crypto' },
        'Sodium': { pattern: /libsodium\.so$/, type: 'Crypto' },
    },
    
    // Lua相关
    luaLibs: {
        'XLua': { pattern: /libxlua\.so$/, type: 'Lua' },
        'Lua': { pattern: /liblua\d*\.so$/, type: 'Lua' },
        'LuaJIT': { pattern: /libluajit\.so$/, type: 'Lua' },
        'ToLua': { pattern: /libtolua\.so$/, type: 'Lua' },
    },
    
    // 保护/混淆
    protectionLibs: {
        'VMP': { pattern: /vmp|vmprotect/i, type: 'Obfuscation' },
        'iJiaMi': { pattern: /ijiami/i, type: 'Protection' },
        'Tencent': { pattern: /libshell|libtersafe/i, type: 'Protection' },
        'DexGuard': { pattern: /dexguard/i, type: 'Obfuscation' },
    },
};

// ============================================================================
// 工具函数
// ============================================================================

/**
 * 检查是否是系统库
 */
function isSystemLibrary(path) {
    if (!CONFIG.filter.skipSystemModules) return false;
    return SYSTEM_LIB_PATTERNS.some(pattern => pattern.test(path));
}

/**
 * 检查是否是系统包
 */
function isSystemPackage(packageName) {
    if (!CONFIG.filter.skipSystemPackages) return false;
    return SYSTEM_PACKAGE_PATTERNS.some(pattern => pattern.test(packageName));
}

/**
 * 识别库类型
 */
function identifyLibrary(module) {
    const identified = {
        categories: [],
        details: []
    };
    
    for (const [category, libs] of Object.entries(KNOWN_LIBRARIES)) {
        for (const [name, info] of Object.entries(libs)) {
            if (info.pattern.test(module.name) || info.pattern.test(module.path)) {
                identified.categories.push(category);
                identified.details.push({ name, type: info.type });
            }
        }
    }
    
    return identified.details.length > 0 ? identified : null;
}

/**
 * 格式化大小
 */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

/**
 * 获取模块类型
 */
function getModuleType(name) {
    if (name.endsWith('.so')) return 'Native';
    if (name.endsWith('.apk') || name.endsWith('.jar')) return 'DEX';
    if (name.endsWith('.oat')) return 'OAT';
    if (name.endsWith('.vdex')) return 'VDEX';
    return 'Unknown';
}

// ============================================================================
// 设备信息收集
// ============================================================================
function collectDeviceInfo() {
    console.log("[*] 收集设备信息...\n");
    
    try {
        Java.perform(function() {
            const Build = Java.use("android.os.Build");
            
            reportData.device = {
                manufacturer: Build.MANUFACTURER.value,
                brand: Build.BRAND.value,
                model: Build.MODEL.value,
                device: Build.DEVICE.value,
                product: Build.PRODUCT.value,
                hardware: Build.HARDWARE.value,
                board: Build.BOARD.value,
                androidVersion: Build.VERSION.RELEASE.value,
                sdkInt: Build.VERSION.SDK_INT.value,
                abi: Process.arch,
                pageSize: Process.pageSize,
                pointerSize: Process.pointerSize,
            };
            
            console.log("[设备信息]");
            console.log(`  制造商: ${reportData.device.manufacturer}`);
            console.log(`  品牌: ${reportData.device.brand}`);
            console.log(`  型号: ${reportData.device.model}`);
            console.log(`  Android版本: ${reportData.device.androidVersion} (SDK ${reportData.device.sdkInt})`);
            console.log(`  架构: ${reportData.device.abi}`);
            console.log("");
        });
    } catch (e) {
        console.log(`[!] 设备信息收集失败: ${e.message}\n`);
    }
}

// ============================================================================
// 进程信息收集
// ============================================================================
function collectProcessInfo() {
    console.log("[*] 收集进程信息...\n");
    
    try {
        Java.perform(function() {
            const ActivityThread = Java.use("android.app.ActivityThread");
            const currentApp = ActivityThread.currentApplication();
            const context = currentApp.getApplicationContext();
            
            reportData.process = {
                packageName: context.getPackageName(),
                pid: Process.id,
                platform: Process.platform,
                arch: Process.arch,
                mainModule: {
                    name: Process.mainModule.name,
                    base: Process.mainModule.base.toString(),
                    size: Process.mainModule.size,
                    path: Process.mainModule.path,
                }
            };
            
            console.log("[进程信息]");
            console.log(`  包名: ${reportData.process.packageName}`);
            console.log(`  PID: ${reportData.process.pid}`);
            console.log(`  平台: ${reportData.process.platform}`);
            console.log(`  架构: ${reportData.process.arch}`);
            console.log(`  主模块: ${reportData.process.mainModule.name}`);
            console.log(`  主模块路径: ${reportData.process.mainModule.path}`);
            console.log("");
        });
    } catch (e) {
        console.log(`[!] 进程信息收集失败: ${e.message}\n`);
    }
}

// ============================================================================
// SO库检测
// ============================================================================
function detectModules() {
    if (!CONFIG.detection.checkModules) return;
    
    console.log("=".repeat(80));
    console.log("[*] 检测已加载的SO库...");
    console.log("=".repeat(80) + "\n");
    
    const modules = Process.enumerateModules();
    
    console.log(`[*] 共找到 ${modules.length} 个模块\n`);
    
    let displayedCount = 0;
    
    modules.forEach((module, index) => {
        // 过滤系统库
        if (isSystemLibrary(module.path)) return;
        
        // 过滤小模块
        if (module.size < CONFIG.filter.minModuleSize) return;
        
        displayedCount++;
        
        // 识别库类型
        const identified = identifyLibrary(module);
        const moduleType = getModuleType(module.name);
        
        // 收集模块信息
        const moduleInfo = {
            index: displayedCount,
            name: module.name,
            base: module.base.toString(),
            size: module.size,
            sizeFormatted: formatSize(module.size),
            path: module.path,
            type: moduleType,
            identified: identified,
        };
        
        reportData.modules.loaded.push(moduleInfo);
        
        // 更新统计
        if (!reportData.modules.statistics.byType[moduleType]) {
            reportData.modules.statistics.byType[moduleType] = 0;
        }
        reportData.modules.statistics.byType[moduleType]++;
        
        // 显示模块信息
        console.log(`[${ displayedCount}] ${module.name}`);
        console.log(`    基址: ${module.base}`);
        console.log(`    大小: ${formatSize(module.size)}`);
        console.log(`    类型: ${moduleType}`);
        
        if (identified) {
            console.log(`    🎯 识别: ${identified.details.map(d => d.name).join(', ')}`);
            
            // 收集到检测结果
            identified.details.forEach(detail => {
                const category = identified.categories[0];
                if (category === 'networkLibs') {
                    reportData.detection.networkLibs.push(detail.name);
                } else if (category === 'cryptoLibs') {
                    reportData.detection.cryptoLibs.push(detail.name);
                } else if (category === 'gameEngines') {
                    if (!reportData.detection.gameEngine) {
                        reportData.detection.gameEngine = detail.name;
                    }
                }
            });
        }
        
        console.log(`    路径: ${module.path}`);
        
        // 显示部分导出
        if (CONFIG.display.showExports) {
            try {
                const exports = module.enumerateExports();
                const count = Math.min(exports.length, CONFIG.display.maxExportsPerModule);
                
                if (exports.length > 0) {
                    console.log(`    导出函数: ${exports.length} 个 (显示前${count}个)`);
                    for (let i = 0; i < count; i++) {
                        console.log(`      - ${exports[i].name}`);
                    }
                }
            } catch (e) {}
        }
        
        console.log("");
    });
    
    reportData.modules.statistics.total = displayedCount;
    
    console.log("=".repeat(80));
    console.log(`[✓] 模块检测完成: 共 ${displayedCount} 个应用模块`);
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// Java包/类检测
// ============================================================================
function detectJavaPackages() {
    if (!CONFIG.detection.checkJavaPackages) return;
    
    console.log("=".repeat(80));
    console.log("[*] 检测Java包和类...");
    console.log("=".repeat(80) + "\n");
    
    try {
        Java.perform(function() {
            console.log("[*] 枚举已加载的类... (可能需要一些时间)\n");
            
            const classes = Java.enumerateLoadedClassesSync();
            const packageMap = {};
            
            classes.forEach(className => {
                // 过滤系统包
                if (isSystemPackage(className)) return;
                
                // 提取包名
                const lastDot = className.lastIndexOf('.');
                if (lastDot === -1) return;
                
                const packageName = className.substring(0, lastDot);
                
                if (!packageMap[packageName]) {
                    packageMap[packageName] = [];
                }
                
                packageMap[packageName].push(className);
            });
            
            // 排序并显示
            const packages = Object.keys(packageMap).sort();
            
            console.log(`[✓] 找到 ${packages.length} 个应用包\n`);
            
            packages.forEach(pkg => {
                const classCount = packageMap[pkg].length;
                
                console.log(`[📦] ${pkg}`);
                console.log(`    类数量: ${classCount}`);
                
                // 显示前几个类
                const displayCount = Math.min(classCount, 5);
                for (let i = 0; i < displayCount; i++) {
                    const className = packageMap[pkg][i].split('.').pop();
                    console.log(`      - ${className}`);
                }
                
                if (classCount > displayCount) {
                    console.log(`      ... 还有 ${classCount - displayCount} 个类`);
                }
                
                console.log("");
                
                // 收集数据
                reportData.java.packages.push({
                    name: pkg,
                    classCount: classCount,
                    classes: packageMap[pkg],
                });
                
                reportData.java.classes.total += classCount;
                reportData.java.classes.byPackage[pkg] = classCount;
            });
            
            console.log("=".repeat(80));
            console.log(`[✓] Java包检测完成: ${packages.length} 个包, ${reportData.java.classes.total} 个类`);
            console.log("=".repeat(80) + "\n");
        });
    } catch (e) {
        console.log(`[!] Java包检测失败: ${e.message}\n`);
    }
}

// ============================================================================
// Unity检测
// ============================================================================
function detectUnity() {
    if (!CONFIG.detection.checkUnity) return;
    
    console.log("=".repeat(80));
    console.log("[*] 检测Unity环境...");
    console.log("=".repeat(80) + "\n");
    
    const il2cpp = Process.findModuleByName("libil2cpp.so");
    const mono = Process.findModuleByName("libmono.so");
    const unityLibrary = Process.findModuleByName("libunity.so");
    const mainModule = Process.findModuleByName("libmain.so");
    
    if (il2cpp) {
        reportData.detection.unity = {
            detected: true,
            type: 'IL2CPP',
            module: 'libil2cpp.so',
            base: il2cpp.base.toString(),
            size: formatSize(il2cpp.size),
        };
        
        console.log("[✅] 检测到 Unity IL2CPP");
        console.log(`    模块: libil2cpp.so`);
        console.log(`    基址: ${il2cpp.base}`);
        console.log(`    大小: ${formatSize(il2cpp.size)}`);
        console.log("");
    } else if (mono) {
        reportData.detection.unity = {
            detected: true,
            type: 'Mono',
            module: 'libmono.so',
            base: mono.base.toString(),
            size: formatSize(mono.size),
        };
        
        console.log("[✅] 检测到 Unity Mono");
        console.log(`    模块: libmono.so`);
        console.log(`    基址: ${mono.base}`);
        console.log(`    大小: ${formatSize(mono.size)}`);
        console.log("");
    } else {
        reportData.detection.unity = { detected: false };
        console.log("[!] 未检测到Unity环境\n");
    }
    
    if (unityLibrary) {
        console.log("[✅] 检测到 libunity.so");
        console.log(`    基址: ${unityLibrary.base}`);
        console.log(`    大小: ${formatSize(unityLibrary.size)}\n`);
    }
    
    if (mainModule) {
        console.log("[✅] 检测到 libmain.so (Unity主模块)");
        console.log(`    基址: ${mainModule.base}`);
        console.log(`    大小: ${formatSize(mainModule.size)}\n`);
    }
    
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// 反调试检测
// ============================================================================
function detectAntiDebug() {
    if (!CONFIG.detection.checkAntiDebug) return;
    
    console.log("=".repeat(80));
    console.log("[*] 检测反调试机制...");
    console.log("=".repeat(80) + "\n");
    
    const antiDebugIndicators = [];
    
    // 检查TracerPid
    try {
        const status = new File("/proc/self/status", "r");
        const content = status.read();
        status.close();
        
        if (content.includes("TracerPid")) {
            antiDebugIndicators.push("TracerPid检查");
        }
    } catch (e) {}
    
    // 检查常见反调试库
    const antiDebugLibs = ['libjiagu', 'libjiami', 'libshell', 'libtersafe', 'libvmp'];
    
    antiDebugLibs.forEach(libName => {
        if (Process.findModuleByName(libName + ".so")) {
            antiDebugIndicators.push(libName + ".so");
        }
    });
    
    reportData.detection.antiDebug = antiDebugIndicators;
    
    if (antiDebugIndicators.length > 0) {
        console.log("[⚠️] 检测到反调试机制:");
        antiDebugIndicators.forEach(indicator => {
            console.log(`    - ${indicator}`);
        });
        console.log("");
    } else {
        console.log("[✓] 未检测到明显的反调试机制\n");
    }
    
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// Root检测
// ============================================================================
function detectRootDetection() {
    if (!CONFIG.detection.checkRootDetection) return;
    
    console.log("=".repeat(80));
    console.log("[*] 检测Root检测机制...");
    console.log("=".repeat(80) + "\n");
    
    const rootIndicators = [];
    
    // 检查常见Root检测库
    const rootDetectionLibs = ['librootdetect', 'libsafetynet', 'libroothide'];
    
    rootDetectionLibs.forEach(libName => {
        if (Process.findModuleByName(libName + ".so")) {
            rootIndicators.push(libName + ".so");
        }
    });
    
    // 检查Magisk Hide
    if (Process.findModuleByName("libmagisk.so")) {
        rootIndicators.push("Magisk检测");
    }
    
    reportData.detection.rootDetection = rootIndicators;
    
    if (rootIndicators.length > 0) {
        console.log("[⚠️] 检测到Root检测机制:");
        rootIndicators.forEach(indicator => {
            console.log(`    - ${indicator}`);
        });
        console.log("");
    } else {
        console.log("[✓] 未检测到明显的Root检测机制\n");
    }
    
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// 动态加载监控
// ============================================================================
function monitorDynamicLoading() {
    if (!CONFIG.detection.monitorLoading) return;
    
    console.log("=".repeat(80));
    console.log("[*] 设置动态加载监控...");
    console.log("=".repeat(80) + "\n");
    
    // 监控dlopen
    const dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                this.path = args[0].readCString();
            },
            onLeave: function(retval) {
                if (this.path && !isSystemLibrary(this.path)) {
                    console.log(`[📥 dlopen] ${this.path}`);
                    
                    reportData.modules.dynamicallyLoaded.push({
                        method: 'dlopen',
                        path: this.path,
                        timestamp: new Date().toISOString(),
                    });
                }
            }
        });
        
        console.log("[✓] Hook dlopen 成功");
    }
    
    // 监控android_dlopen_ext
    const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function(args) {
                this.path = args[0].readCString();
            },
            onLeave: function(retval) {
                if (this.path && !isSystemLibrary(this.path)) {
                    console.log(`[📥 android_dlopen_ext] ${this.path}`);
                    
                    reportData.modules.dynamicallyLoaded.push({
                        method: 'android_dlopen_ext',
                        path: this.path,
                        timestamp: new Date().toISOString(),
                    });
                }
            }
        });
        
        console.log("[✓] Hook android_dlopen_ext 成功");
    }
    
    // 监控Java层动态加载
    try {
        Java.perform(function() {
            const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
            
            DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                console.log(`[📥 DexClassLoader] ${dexPath}`);
                
                reportData.modules.dynamicallyLoaded.push({
                    method: 'DexClassLoader',
                    path: dexPath,
                    timestamp: new Date().toISOString(),
                });
                
                return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
            };
            
            console.log("[✓] Hook DexClassLoader 成功");
        });
    } catch (e) {}
    
    console.log("\n=".repeat(80) + "\n");
}

// ============================================================================
// 导出报告
// ============================================================================
function exportReport() {
    if (!CONFIG.export.enabled) return;
    
    console.log("=".repeat(80));
    console.log("[*] 生成检测报告...");
    console.log("=".repeat(80) + "\n");
    
    try {
        const reportJson = JSON.stringify(reportData, null, 2);
        const filepath = CONFIG.export.savePath + CONFIG.export.filename;
        
        const file = new File(filepath, "w");
        file.write(reportJson);
        file.close();
        
        console.log(`[✅] 报告已保存: ${filepath}`);
        console.log(`[💾] 报告大小: ${formatSize(reportJson.length)}\n`);
        
        console.log("[提示] 拉取报告到本地:");
        console.log(`  adb pull ${filepath} ./\n`);
        
    } catch (e) {
        console.log(`[✗] 报告保存失败: ${e.message}\n`);
    }
    
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// 显示摘要
// ============================================================================
function displaySummary() {
    console.log("\n" + "=".repeat(80));
    console.log("  📊 检测摘要");
    console.log("=".repeat(80) + "\n");
    
    console.log("[设备]");
    console.log(`  ${reportData.device.manufacturer} ${reportData.device.model}`);
    console.log(`  Android ${reportData.device.androidVersion} (${reportData.device.abi})\n`);
    
    console.log("[进程]");
    console.log(`  包名: ${reportData.process.packageName}`);
    console.log(`  PID: ${reportData.process.pid}\n`);
    
    console.log("[模块]");
    console.log(`  已加载: ${reportData.modules.statistics.total} 个`);
    console.log(`  动态加载: ${reportData.modules.dynamicallyLoaded.length} 个`);
    if (Object.keys(reportData.modules.statistics.byType).length > 0) {
        console.log(`  类型分布:`);
        for (const [type, count] of Object.entries(reportData.modules.statistics.byType)) {
            console.log(`    - ${type}: ${count}`);
        }
    }
    console.log("");
    
    console.log("[Java]");
    console.log(`  包: ${reportData.java.packages.length} 个`);
    console.log(`  类: ${reportData.java.classes.total} 个\n`);
    
    if (reportData.detection.unity && reportData.detection.unity.detected) {
        console.log("[Unity]");
        console.log(`  类型: ${reportData.detection.unity.type}`);
        console.log(`  模块: ${reportData.detection.unity.module}\n`);
    }
    
    if (reportData.detection.gameEngine) {
        console.log("[游戏引擎]");
        console.log(`  ${reportData.detection.gameEngine}\n`);
    }
    
    if (reportData.detection.networkLibs.length > 0) {
        console.log("[网络库]");
        reportData.detection.networkLibs.forEach(lib => {
            console.log(`  - ${lib}`);
        });
        console.log("");
    }
    
    if (reportData.detection.cryptoLibs.length > 0) {
        console.log("[加密库]");
        reportData.detection.cryptoLibs.forEach(lib => {
            console.log(`  - ${lib}`);
        });
        console.log("");
    }
    
    if (reportData.detection.antiDebug.length > 0) {
        console.log("[反调试]");
        reportData.detection.antiDebug.forEach(method => {
            console.log(`  - ${method}`);
        });
        console.log("");
    }
    
    if (reportData.detection.rootDetection.length > 0) {
        console.log("[Root检测]");
        reportData.detection.rootDetection.forEach(method => {
            console.log(`  - ${method}`);
        });
        console.log("");
    }
    
    console.log("=".repeat(80));
    console.log("[✓] 检测完成");
    console.log("=".repeat(80) + "\n");
}

// ============================================================================
// 主程序
// ============================================================================
console.log("[*] 初始化检测...\n");

setTimeout(() => {
    // 收集基本信息
    collectDeviceInfo();
    collectProcessInfo();
    
    // 执行各项检测
    detectModules();
    detectJavaPackages();
    detectUnity();
    detectAntiDebug();
    detectRootDetection();
    
    // 设置动态监控
    monitorDynamicLoading();
    
    // 显示摘要
    displaySummary();
    
    // 导出报告
    exportReport();
    
    console.log("[提示] 脚本持续运行中，监控动态加载...");
    console.log("[提示] 按 Ctrl+C 退出\n");
    
}, 2000);

// 异常处理
Process.setExceptionHandler((details) => {
    if (!details.message.includes("access violation")) {
        console.log(`\n[!] 异常: ${details.type} @ ${details.address}\n`);
    }
    return true;
});

