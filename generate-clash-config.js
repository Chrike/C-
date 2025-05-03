// generate-clash-config.js
const fs = require('fs');
const yaml = require('js-yaml');
const path = require('path'); // Although path is not explicitly used in the final version, it's good practice to include if you might add path operations later.

// ==============================================================
// == COMPLETE JAVASCRIPT GENERATOR CODE START ==
// ==============================================================

/**
 * ClashVerge 代理规则配置生成脚本
 * MIT License ~
 * author : Phantasia https://github.com/MarchPhantasia
 */

// ==================== 用户配置区（可自由修改） ====================

/**
 * 常用配置选项
 */
const CONFIG = {
    // 测试连接URL
    testUrl: "https://www.gstatic.com/generate_204",

    // 自动测试间隔 (秒)
    testInterval: 300,

    // 自动选择容差 (毫秒)
    tolerance: 20,

    // 负载均衡策略："round-robin" | "sticky-sessions" | "consistent-hashing"
    balanceStrategy: "sticky-sessions"
};

/**
 * 用户自定义规则（高优先级）
 * 这些规则会被放置在所有其他规则之前，确保不会被其他规则覆盖
 */
const USER_RULES = [
    "DOMAIN-SUFFIX,v2ex.com,被墙网站",
    "DOMAIN-SUFFIX,nodeseek.com,被墙网站",
    "DOMAIN-SUFFIX,mnapi.com,DIRECT",
    "DOMAIN-SUFFIX,ieee.org,DIRECT",
    "DOMAIN-SUFFIX,anrunnetwork.com,DIRECT",
    "DOMAIN-SUFFIX,apifox.com,DIRECT",
    "DOMAIN-SUFFIX,crond.dev,DIRECT",
    "IP-CIDR,223.113.52.0/22,DIRECT,no-resolve",
    // 在此添加更多自定义规则...
];

const SAVED_RULES = [
    "RULE-SET,reject,广告拦截",
    "RULE-SET,cncidr,DIRECT,no-resolve",
    "RULE-SET,direct,DIRECT",
    "GEOSITE,gfw,被墙网站",
    "GEOIP,CN,国内网站",
    "MATCH,国外网站"
]

/**
 * 高质量节点关键词列表
 * 用于筛选名称中包含这些关键词的节点作为高质量节点
 */
const HIGH_QUALITY_KEYWORDS = [
    // 线路类型关键词
    "家宽", "家庭宽带", "IEPL", "Iepl", "iepl",
    "IPLC", "iplc", "Iplc", "专线", "高速",

    // 节点等级关键词
    "高级", "精品", "原生", "SVIP", "svip",
    "Svip", "VIP", "vip", "Vip", "Premium",
    "premium",

    // 特殊用途关键词
    "特殊", "特殊线路", "游戏", "Game", "game"

    // 在此添加更多关键词...
];

/**
 * 代理规则配置
 * name: 规则名称
 * gfw: 是否被墙 (true=默认走代理, false=默认直连)
 * urls: 规则集链接，可以是单个URL或URL数组
 * payload: 自定义规则内容，设置后urls将被忽略
 * extraProxies: 额外添加到此规则组的代理，例如REJECT用于广告拦截
 */
const PROXY_RULES = [
    // 广告拦截
    {
        name: "广告拦截",
        gfw: false,
        extraProxies: "REJECT",
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdvertisingLite/AdvertisingLite_Classical.yaml"
    },

    // 自定义规则示例
    {
        name: "linux.do",
        gfw: false,
        payload: "DOMAIN-SUFFIX,linux.do"
    },

    // 常用网站分组
    {
        name: "GitHub",
        gfw: false,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/GitHub/GitHub.yaml"
    },
    {
        name: "YouTube",
        gfw: true,
        urls: [
            "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml",
            "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTubeMusic/YouTubeMusic.yaml"
        ]
    },
    {
        name: "Google",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google_No_Resolve.yaml"
    },
    {
        name: "openAi",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI_No_Resolve.yaml"
    },
    {
        name: "Netflix",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Netflix/Netflix_No_Resolve.yaml"
    },
    {
        name: "Twitter",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Twitter/Twitter_No_Resolve.yaml"
    },
    {
        name: "TikTok",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TikTok/TikTok_No_Resolve.yaml"
    },
    {
        name: "Facebook",
        gfw: true,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Facebook/Facebook_No_Resolve.yaml"
    },
    {
        name: "OneDrive",
        gfw: false,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OneDrive/OneDrive_No_Resolve.yaml"
    },
    {
        name: "Microsoft",
        gfw: false,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Microsoft/Microsoft_No_Resolve.yaml"
    },
    {
        name: "Steam",
        gfw: false,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@release/rule/Clash/Steam/Steam_No_Resolve.yaml"
    },
    {
        name: "Cloudflare",
        gfw: false,
        urls: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Cloudflare/Cloudflare_No_Resolve.yaml"
    },

    // 在此添加更多规则...
];

/**
 * DNS 配置
 * 可根据需要修改DNS服务器
 */
const DNS_CONFIG = {
    // 国际可信DNS (加密)
    trustDnsList: [
        "tls://8.8.8.8", "tls://1.1.1.1", "tls://9.9.9.9",
        "https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"
    ],

    // 默认DNS (用于解析域名服务器，必须为IP，可加密)
    defaultDNS: ["tls://1.12.12.12", "tls://223.5.5.5"],

    // 中国大陆DNS服务器
    cnDnsList: [
        '119.29.29.29',                    // Tencent Dnspod
        '223.5.5.5',                       // Ali DNS
        '1.12.12.12',                      // China Telecom
        "114.114.114.114",
    ],

    // DNS隐私保护过滤器
    fakeIpFilter: [
        "+.lan", "+.local",
        // Windows网络连接检测
        "+.msftconnecttest.com", "+.msftncsi.com",
        // QQ/微信快速登录检测
        "localhost.ptlogin2.qq.com", "localhost.sec.qq.com",
        "localhost.work.weixin.qq.com",
    ],

    // 指定域名使用的DNS服务器
    // 格式: "域名或geosite": DNS服务器
    nameserverPolicy: {
        "geosite:private": "system",
        "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn": 'cnDnsList'
    },

    // 需要指定使用国外DNS的域名
    fallbackDomains: [
        "+.azure.com", "+.bing.com", "+.bingapis.com",
        "+.cloudflare.net", "+.docker.com", "+.docker.io",
        "+.facebook.com", "+.github.com", "+.githubusercontent.com",
        "+.google.com", "+.gstatic.com", "+.google.dev",
        "+.googleapis.cn", "+.googleapis.com", "+.googlevideo.com",
        "+.instagram.com", "+.meta.ai", "+.microsoft.com",
        "+.microsoftapp.net", "+.msn.com", "+.openai.com",
        "+.poe.com", "+.t.me", "+.twitter.com",
        "+.x.com", "+.youtube.com"
    ]
};

// ==================== 系统实现区（一般不需要修改） ====================

// 预编译高质量节点匹配的正则表达式
const HIGH_QUALITY_REGEX = new RegExp(HIGH_QUALITY_KEYWORDS.join("|"), "i");

// 构建DNS配置对象
const dns = buildDnsConfig(DNS_CONFIG);

// ==================== 辅助函数部分 ====================

/**
 * 构建DNS配置对象
 * @param {Object} config - DNS配置参数
 * @returns {Object} 完整的DNS配置对象
 */
function buildDnsConfig(config) {
    return {
        enable: true,
        listen: ":53", // Default DNS listen port
        ipv6: true, // Enable IPv6 DNS resolution
        "prefer-h3": true, // Prefer DoH3
        "use-hosts": true, // Use system hosts file
        "use-system-hosts": true, // Explicitly use system hosts (redundant with use-hosts often)
        "respect-rules": true, // DNS results respect rules
        "enhanced-mode": "fake-ip", // Use fake-ip mode
        "fake-ip-range": "198.18.0.1/16", // Fake IP range
        "fake-ip-filter": config.fakeIpFilter, // Domains to exclude from fake-ip
        "default-nameserver": config.defaultDNS, // Fallback DNS for nameserver resolution
        nameserver: config.trustDnsList, // Upstream DNS servers (trusted)
        "proxy-server-nameserver": config.cnDnsList, // DNS for resolving proxy server hostnames
        "nameserver-policy": config.nameserverPolicy, // Policy for specific domains/geosites
        fallback: config.trustDnsList, // Fallback DNS servers (used when direct connection fails)
        "fallback-filter": {
            geoip: true,
            "geoip-code": "CN",
            geosite: ["gfw"],
            ipcidr: ["240.0.0.0/4"], // Use fallback for these IPs
            domain: config.fallbackDomains // Use fallback for these domains
        }
    };
}

/**
 * 创建规则提供器配置 - 使用对象复用优化性能
 * @param {string} url - 规则集URL
 * @returns {Object} 规则提供器配置对象
 */
function createRuleProviderUrl(url) {
    return {
        type: "http",
        interval: 86400, // Update interval in seconds (1 day)
        behavior: "classical", // Rule behavior
        format: "yaml", // Rule format
        url // URL of the rule set
    };
}

/**
 * 创建payload对应的规则 - 优化数组操作
 * @param {string|string[]} payload - 规则内容
 * @param {string} name - 规则名称 (used as target proxy group)
 * @returns {string[]} 处理后的规则列表
 */
function createPayloadRules(payload, name) {
    const payloads = Array.isArray(payload) ? payload : [payload];
    const len = payloads.length;
    const rules = new Array(len);
    // Normalize group name (replace commas, etc.)
    const normalizedName = name.replace(/,/g, '-').replace(/\s/g, ''); // Replace commas and spaces

    for (let i = 0; i < len; i++) {
        const item = payloads[i];
        const p = item.split(",");
        let insertPos = p.length;

        // Check for no-resolve flag
        const last = p[p.length - 1];
        if (last && (last.toLowerCase() === "no-resolve")) {
            insertPos--;
        }

        // Insert the target proxy group name before the last element (or before no-resolve)
        p.splice(insertPos, 0, normalizedName);
        rules[i] = p.join(",");
    }

    return rules;
}


/**
 * 创建GFW（被墙）代理组
 * @param {string} name - 代理组名称
 * @param {string|string[]} addProxies - 额外代理 (e.g., REJECT)
 * @param {string} testUrl - 测试链接
 * @returns {Object} 代理组配置
 */
function createGfwProxyGroup(name, addProxies, testUrl) {
    addProxies = addProxies ? (Array.isArray(addProxies) ? addProxies : [addProxies]) : [];
    return {
        "name": name,
        "type": "select", // User can manually select
        "proxies": [
            ...addProxies, // Add extra proxies first (like REJECT)
            "自动选择(最低延迟)", // Default choice
            "负载均衡",
            "HighQuality", // High quality nodes group
            "DIRECT" // Direct connection as an option
        ],
        "include-all": true, // Include all proxies implicitly? Usually false for select, true for url-test/fallback/lb
        "url": testUrl, // URL for testing latency within the group
        // "interval": 300 // Interval for testing if needed for SELECT (less common)
    };
}

/**
 * 创建普通（非GFW）代理组
 * @param {string} name - 代理组名称
 * @param {string|string[]} addProxies - 额外代理
 * @param {string} testUrl - 测试链接
 * @returns {Object} 代理组配置
 */
function createProxyGroup(name, addProxies, testUrl) {
    addProxies = addProxies ? (Array.isArray(addProxies) ? addProxies : [addProxies]) : [];
    return {
        "name": name,
        "type": "select",
        "proxies": [
            ...addProxies,
            "DIRECT", // Default choice for non-GFW
            "自动选择(最低延迟)",
            "负载均衡",
            "HighQuality"
        ],
        "include-all": true, // As above
        "url": testUrl,
        // "interval": 300
    };
}

/**
 * 筛选高质量节点 - 使用正则表达式优化性能
 * @param {Array} proxies - 所有代理节点 [{name: "...", ...}, ...]
 * @returns {Array} 符合条件的高质量节点名称列表 ["proxy1", "proxy2"]
 */
function filterHighQualityProxies(proxies) {
    if (!proxies || !Array.isArray(proxies)) {
        console.warn("filterHighQualityProxies: Input proxies is not a valid array.");
        return [];
    }

    const result = [];
    const len = proxies.length;
    const regex = HIGH_QUALITY_REGEX; // Use pre-compiled regex

    for (let i = 0; i < len; i++) {
        const proxy = proxies[i];
        // Defensive check for proxy structure and name property
        if (proxy && typeof proxy.name === 'string' && regex.test(proxy.name)) {
            result.push(proxy.name);
        }
    }
    return result;
}


/**
 * 主函数：生成完整的Clash配置
 * @param {Object} config - 输入配置, expected to have a `proxies` array.
 * @returns {Object} 完整的Clash配置 (JavaScript Object)
 */
function main(config) {
    // Ensure proxies is an array, even if input is malformed or missing proxies
    const proxies = (config && Array.isArray(config.proxies)) ? config.proxies : [];
    if (proxies.length === 0) {
        console.warn("main: No proxies found in the input config. Generating configuration without external proxies.");
    }
    const testUrl = CONFIG.testUrl;

    // 筛选高质量节点 names
    const highQualityProxies = filterHighQualityProxies(proxies);
    console.log(`Found ${highQualityProxies.length} high quality proxies.`);

    // 初始化规则和代理组
    const rules = USER_RULES.slice(); // Start with high-priority user rules
    const proxyGroups = []; // For non-GFW rules
    const gfwProxyGroups = []; // For GFW rules

    // 规则集通用配置
    const ruleProviderCommon = {
        type: "http",
        format: "yaml",
        interval: 86400, // Check for updates daily
        // 'health-check': { // Optional health check for rule providers
        //   enable: true,
        //   url: CONFIG.testUrl,
        //   interval: 600,
        // },
    };

    // 初始化规则提供器 (Rule Providers)
    const ruleProviders = {
        reject: {
            ...ruleProviderCommon,
            behavior: "domain", // Match domain names
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
            path: "./ruleset/reject.yaml" // Local cache path
        },
        cncidr: {
            ...ruleProviderCommon,
            behavior: "ipcidr", // Match IP ranges
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
            path: "./ruleset/cncidr.yaml"
        },
        direct: {
            ...ruleProviderCommon,
            behavior: "domain",
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
            path: "./ruleset/direct.yaml"
        }
        // We will add more rule providers dynamically below
    };

    // Process PROXY_RULES to create proxy groups and rule provider entries
    const configLen = PROXY_RULES.length;
    for (let i = 0; i < configLen; i++) {
        const { name, gfw, urls, payload, extraProxies } = PROXY_RULES[i];
        const normalizedGroupName = name.replace(/,/g, '-').replace(/\s/g, ''); // Consistent naming

        // 创建代理组 based on gfw flag
        if (gfw) {
            gfwProxyGroups.push(createGfwProxyGroup(normalizedGroupName, extraProxies, testUrl));
        } else {
            proxyGroups.push(createProxyGroup(normalizedGroupName, extraProxies, testUrl));
        }

        // 处理规则: payload takes precedence over urls
        if (payload) {
            // Add rules generated from payload directly
            rules.push(...createPayloadRules(payload, normalizedGroupName));
        } else if (urls) {
            const urlList = Array.isArray(urls) ? urls : [urls];
            const urlLen = urlList.length;
            for (let j = 0; j < urlLen; j++) {
                const theUrl = urlList[j];
                // Create a unique name for the rule provider
                const providerName = `${normalizedGroupName}-provider${j > 0 ? `-${j+1}` : ''}`;
                // Add the rule provider configuration
                ruleProviders[providerName] = {
                    ...createRuleProviderUrl(theUrl), // Base properties from helper
                    path: `./ruleset/${providerName}.yaml` // Add local cache path
                };
                // Add the RULE-SET rule linking the provider to the group
                rules.push(`RULE-SET,${providerName},${normalizedGroupName}`);
            }
        }
    }

    // 构建基本代理组 (like Domestic, Global, GFW, Auto, LB, HighQuality)
    const baseProxyGroups = buildBaseProxyGroups(testUrl, highQualityProxies);

    // 构建最终配置对象 (JavaScript Object)
    return {
        "mixed-port": 7890, // Example: Common port for HTTP/SOCKS5 proxy
        "redir-port": 7892, // Example: Transparent proxy port (Linux/macOS)
        "tproxy-port": 7893, // Example: TPROXY port (Linux)
        "allow-lan": true, // Allow connections from local network
        mode: "rule", // Use rule-based routing
        "log-level": "info", // Logging level (silent, error, warning, info, debug)
        "external-controller": '127.0.0.1:9090', // API port for external controllers (like dashboards)
        "external-ui": "ui", // Relative path to the web UI dashboard (if you bundle one)
        "secret": "", // Optional secret for the external controller API
        "find-process-mode": "strict", // How Clash finds the process for rules (strict or always)
        "global-client-fingerprint": "chrome", // TLS fingerprint to mimic Chrome
        "unified-delay": true, // Show unified delay for groups in API
        "tcp-concurrent": true, // Allow concurrent TCP connections for testing URLs

        // GeoIP/GeoSite database URLs
        "geox-url": {
            // Use a proxy for reliability, especially in GitHub Actions / China
            geoip: "https://ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
            geosite: "https://ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
            // mmdb: "https://ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb" // Optional MMDB
        },

        dns: dns, // DNS configuration object

        proxies: proxies, // The list of proxy servers fetched from the URL

        "proxy-groups": [
            ...baseProxyGroups, // Basic groups (国内, 国外, 被墙, Auto, LB, HQ)
            ...gfwProxyGroups, // Groups for GFW-affected rules
            ...proxyGroups,    // Groups for non-GFW rules
        ],

        "rule-providers": ruleProviders, // All defined rule providers

        rules: [
            ...rules, // User rules + rules generated from PROXY_RULES (payload/RULE-SET)
            ...SAVED_RULES // Standard final rules (Reject ads, CN CIDR, Direct domains, GeoSite GFW, GeoIP CN, MATCH)
        ]
    };
}

/**
 * 构建基本代理组 (国内网站, 国外网站, 被墙网站, HighQuality, 自动选择, 负载均衡)
 * @param {string} testUrl - 测试URL for latency testing
 * @param {Array} highQualityProxies - Array of high-quality proxy names
 * @returns {Array} Array of basic proxy group configuration objects
 */
function buildBaseProxyGroups(testUrl, highQualityProxies) {
    // Provide a fallback proxy group if highQualityProxies is empty
    const highQualityOptions = highQualityProxies.length > 0
        ? highQualityProxies
        : ["自动选择(最低延迟)"]; // Fallback to auto select if no HQ nodes identified

    return [
        // Basic Policy Groups (用户可在 UI 中选择这些作为主要策略)
        {
            "name": "🚀 Proxy", // Renamed for clarity, acts as the main selection group
            "type": "select",
            "proxies": [
                "自动选择(最低延迟)",
                "负载均衡",
                "HighQuality",
                "DIRECT"
                // You might want to manually add specific regions here if needed
                // e.g., "🇭🇰 香港节点", "🇯🇵 日本节点", etc. (requires creating those groups)
            ]
            // No include-all needed for select
        },
        // Content-based Groups (由规则自动导向流量)
        {
            "name": "国内网站", // Rules match GEOIP(CN) or specific CN domains
            "type": "select",
            "proxies": ["DIRECT", "🚀 Proxy"], // Prefer DIRECT for CN sites
             "url": "http://www.baidu.com/favicon.ico", // Test CN connectivity
             "interval": 86400 // Test less frequently
        },
        {
            "name": "国外网站", // Rules match MATCH (default)
            "type": "select",
            "proxies": ["🚀 Proxy", "DIRECT"], // Prefer Proxy for non-CN sites
             "url": "http://www.google.com/favicon.ico", // Test global connectivity
             "interval": 300 // Test more frequently
        },
        {
            "name": "被墙网站", // Rules match GEOSITE(GFW)
            "type": "select",
            "proxies": ["🚀 Proxy", "DIRECT"], // Definitely prefer Proxy for GFW sites
            "url": testUrl, // Use the standard test URL
            "interval": 300
        },
        // Functional Groups (组成其他策略组的基础)
        {
            "name": "HighQuality",
            "type": "select", // Allow selecting specific HQ node or testing them
            "proxies": [
                "自动选择(最低延迟)", // Auto-select among HQ nodes + others
                "负载均衡",          // Load balance among HQ nodes + others
                ...highQualityOptions // Add specific HQ node names
            ],
            "url": testUrl,
            "interval": CONFIG.testInterval,
            // Filter only high quality proxies for underlying url-test/load-balance? More complex setup needed.
            // This simple setup includes all nodes in the underlying tests, which might not be desired.
            // A better approach might be separate url-test/lb groups *only* for HQ nodes.
            // Example for a dedicated HQ test group:
            // {
            //   "name": "HighQuality-UrlTest",
            //   "type": "url-test",
            //   "proxies": highQualityOptions, // Only test HQ nodes
            //   "url": testUrl,
            //   "interval": CONFIG.testInterval,
            //   "tolerance": CONFIG.tolerance
            // }
            // Then "HighQuality" group could use "HighQuality-UrlTest"
        },
        {
            "name": "自动选择(最低延迟)", // URL Test group including *all* proxies
            "type": "url-test",
            "tolerance": CONFIG.tolerance, // Max latency difference to switch proxy
            "include-all": true, // Include all proxies from the main list
            // "exclude-filter": "(?i)过期|剩余流量", // Optional: Exclude proxies based on name regex
            "url": testUrl,
            "interval": CONFIG.testInterval
        },
        {
            "name": "负载均衡", // Load Balance group including *all* proxies
            "type": "load-balance",
            "include-all": true,
            // "exclude-filter": "(?i)过期|剩余流量",
            "strategy": CONFIG.balanceStrategy, // round-robin, consistent-hashing, or sticky
            "url": testUrl,
            "interval": CONFIG.testInterval
        },
    ];
}


// ============================================================
// == COMPLETE JAVASCRIPT GENERATOR CODE END ==
// ============================================================


// ==================
// == Wrapper Logic ==
// ==================

// Get file paths from command line arguments
// process.argv[0] is node executable path
// process.argv[1] is script file path
// process.argv[2] is the first actual argument
const proxyFilePath = process.argv[2];
const outputFilePath = process.argv[3];

if (!proxyFilePath || !outputFilePath) {
    console.error('Usage: node generate-clash-config.js <input-proxy-yaml-path> <output-clash-config-yaml-path>');
    process.exit(1); // Exit with error code
}

console.log(`Input proxy file: ${proxyFilePath}`);
console.log(`Output config file: ${outputFilePath}`);

try {
    // Read the proxy list YAML file
    console.log(`Reading proxy file: ${proxyFilePath}...`);
    const proxyYamlContent = fs.readFileSync(proxyFilePath, 'utf8');
    console.log('Proxy file read successfully.');

    // Parse the proxy list YAML
    console.log('Parsing proxy YAML...');
    const proxyData = yaml.load(proxyYamlContent);
    console.log('Proxy YAML parsed.');

    // --- Input Validation and Proxy Extraction ---
    let proxiesArray = [];
    if (proxyData && Array.isArray(proxyData.proxies)) {
        // Handles structure like: proxies: [...]
        proxiesArray = proxyData.proxies;
        console.log(`Loaded ${proxiesArray.length} proxies from top-level 'proxies' key.`);
    } else if (Array.isArray(proxyData)) {
        // Handles structure like: - {...} - {...}
        // This is less common for a full proxy list but possible
        proxiesArray = proxyData;
        console.log(`Loaded ${proxiesArray.length} proxies directly from YAML array.`);
    } else if (proxyData && typeof proxyData === 'object' && proxyData !== null) {
         // Handles structure where proxies might be nested differently or file has other keys
         // Attempt to find a key named 'proxies' or 'proxy' that holds an array
         let found = false;
         for (const key in proxyData) {
             if ((key.toLowerCase() === 'proxies' || key.toLowerCase() === 'proxy') && Array.isArray(proxyData[key])) {
                 proxiesArray = proxyData[key];
                 console.log(`Loaded ${proxiesArray.length} proxies from key '${key}'.`);
                 found = true;
                 break;
             }
         }
         if (!found) {
            console.warn(`Warning: Input YAML (${proxyFilePath}) is an object but does not contain a recognizable 'proxies' array key. Proceeding with empty proxy list.`);
         }
    }
     else {
        console.warn(`Warning: Input YAML (${proxyFilePath}) does not seem to contain a valid proxy list (expected 'proxies:' key or a direct array). Proceeding with empty proxy list.`);
        // proxiesArray remains []
    }

    // Prepare the input for the main generator function
    const generatorInput = {
        proxies: proxiesArray
    };

    // Run the main generator function from the pasted code
    console.log('Generating Clash configuration object...');
    const finalClashConfigObject = main(generatorInput);
    console.log('Clash configuration object generated.');

    // Convert the final configuration object back to YAML
    console.log('Converting configuration object to YAML...');
    const finalClashConfigYaml = yaml.dump(finalClashConfigObject, {
        noRefs: true, // Avoids YAML anchors/aliases for cleaner output if objects are reused
        lineWidth: -1, // Do not wrap lines automatically
        quotingType: '"', // Prefer double quotes for strings where needed
        noArrayIndent: false // Keep array indentation standard
    });
    console.log('Configuration converted to YAML.');

    // Write the final YAML to the specified output file
    console.log(`Writing final configuration to ${outputFilePath}...`);
    fs.writeFileSync(outputFilePath, finalClashConfigYaml, 'utf8');
    console.log(`Clash configuration successfully generated and saved to ${outputFilePath}`);

} catch (error) {
    console.error('Error generating Clash configuration:', error);
    process.exit(1); // Exit with error code
}
