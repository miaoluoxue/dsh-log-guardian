# dsh-log-guardian · LogGuardian

<p align="center">
  <a href="https://github.com/miaoluoxue/dsh-log-guardian/actions/workflows/ci.yml"><img src="https://github.com/miaoluoxue/dsh-log-guardian/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/dsh-log-guardian"><img src="https://img.shields.io/npm/v/dsh-log-guardian" alt="npm"></a>
  <a href="https://github.com/miaoluoxue/dsh-log-guardian/blob/main/LICENSE"><img src="https://img.shields.io/github/license/miaoluoxue/dsh-log-guardian" alt="License"></a>
</p>

**A real-time log security sentinel for DeepSeek Harness (DSH).**
把「被动的人工日志查询」升级为「主动的自动化安全哨兵」：随 DSH 主进程启动即运行，增量 tail 目标日志，一旦发现 `cordis_define` / `cordis_run` / `subprocess` 等高危调用，立即**双通道**告警。

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [特性](#特性)
- [工作原理](#工作原理)
- [安装](#安装)
- [配置](#配置)
- [HTTP / WebSocket 端点](#http--websocket-端点)
- [开发与测试](#开发与测试)
- [目录结构](#目录结构)
- [安全边界](#安全边界)
- [License](#license)

---

## 它解决什么问题

DSH 的动态 Cordis 插件能力（`cordis_define` / `cordis_run` / `cordis_stop` / `cordis_undefine`）与 `subprocess` 工具，构成一条**提示注入 → 注册恶意插件 → 执行 → 沙箱逃逸 / RCE** 的完整攻击面。管理员原本只能靠事后 `grep` 日志排查，存在被动滞后、人工断点、与前端割裂三大痛点。

LogGuardian 把「事后 grep」变成「实时哨兵」：日志文件只要有新字节写入，立刻扫描、立刻告警，无需人工触发、无需等待模型调用工具，7×24 常驻。

## 特性

- ⚡ **零延时增量读取**：按**字节**推进偏移（中文等多字节日志不偏移错乱），只读末尾新增，绝不重扫历史。
- 🔀 **混合事件监听**：优先 `fs.watch(目录)`，失败自动降级 `setInterval` 轮询，另加低频兜底轮询防 NFS 漏报。
- ♻️ **截断 / 轮转自愈**：检测到「大小 < 偏移」即判定 logrotate 切割，偏移自动重置，不崩不报错。
- 📢 **双通道告警**：`ctx.logger.warn`（日志面板染色）+ WebSocket 广播（页面 toast + 系统 Notification）。
- 🎛️ **运行时可配置**：`LOG_MONITOR_KEYWORDS` / `LOG_MONITOR_FILES` / `LOG_MONITOR_POLL_MS` 环境变量覆盖，无需重启。
- 📦 **零运行时依赖**：纯 Node 原生 API；`@deepseek-ai/schemastery` 为可选 peer，缺失时优雅降级，绝不让 DSH 启动被拖崩。

## 工作原理

```
目标日志文件 ──LogTailer──▶ 增量字节(offset 之后) ──scanIncrement──▶ 命中关键词
   ▲                                                              │
   │  fs.watch(目录) ──不可用/报错──▶ setInterval 轮询             │
   │  （截断/轮转 → 自动重置偏移，不崩）                            ▼
   │                                         ① ctx.logger.warn（日志面板染色）
   │                                         ② WebSocket 广播 → toast + Notification
```

## 安装

```powershell
# 从本地目录安装
dsh plugin --profile web add E:\pythonxx\tkry\插件设计\dsh-log-guardian

# 或安装已发布的 npm 包
dsh plugin --profile web add dsh-log-guardian
```

`add` 会把包装入 profile 的 `node_modules` 并追加补丁层，**重启 DSH** 生效。确认：

```powershell
dsh --profile web --dump-config   # 找 log-guardian 行
```

卸载：`dsh plugin --profile web remove dsh-log-guardian`。

## 配置

默认配置（`cordis.patch.yml`）即可用，也可用环境变量运行时覆盖（**无需重启**）：

| 配置 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `files` | `string[]` | `[]` | 要监控的日志文件。空 = 自动探测 `$DSH_HOME/logs` 下的 `*.log` 与 `main.*`；可填文件绝对路径或目录（目录则监控其下 `*.log` 与 `main.*`） |
| `keywords` | `string[]` | 见下 | 高危关键词。普通子串（大小写不敏感）或 `/regex/flags` 字面量 |
| `pollMs` | `number` | `2000` | `fs.watch` 不可用时的降级轮询间隔（毫秒） |
| `notify` | `boolean` | `true` | 是否启用前端双通道告警 |
| `dedupeMs` | `number` | `5000` | 同一文件同一行同一关键词的告警去重窗口（毫秒） |
| `maxAlerts` | `number` | `200` | 内存保留的最近告警条数（供 `/alerts` 回放） |

默认关键词：

```
cordis_define  cordis_run  cordis_stop  cordis_undefine  cordis_runtime_inspect
subprocess  child_process  execSync  spawnSync
```

环境变量覆盖：

```powershell
$env:LOG_MONITOR_KEYWORDS = "cordis_define,cordis_run,subprocess,/require\(['`"]child_process['`"]\)/i"
$env:LOG_MONITOR_FILES    = "C:\path\to\dsh-web.log;C:\path\to\logs"
$env:LOG_MONITOR_POLL_MS  = "1000"
```

## HTTP / WebSocket 端点

宿主在 `webServer` 上注册以下端点（**仅回环或同源可访问**，不向任何地方外发数据）：

| 端点 | 方法 | 用途 |
|---|---|---|
| `/dsh-log-guardian/alerts` | GET | 最近告警回放（JSON，`alerts.slice(-50)`） |
| `/dsh-log-guardian/status` | GET | 自检：监控文件、当前偏移、关键词、是否轮询降级 |
| `/dsh-log-guardian/client.js` | GET | 注入的浏览器告警脚本 |
| `/dsh-log-guardian/events` | WS | 实时告警推送通道 |

## 开发与测试

```powershell
# 冒烟测试（18 个用例，零依赖）
npm test                # 或 node test/smoke.mjs

# 语法检查
node --check lib/index.js

# 查看 npm 发布包内容（校验 files 字段）
npm pack --dry-run
```

CI：`.github/workflows/ci.yml` 在 Node 18 / 20 / 22 上自动跑 `node test/smoke.mjs`。

## 目录结构

```
dsh-log-guardian/
├── package.json          # dsh.bundle.patch 指向 cordis.patch.yml
├── cordis.patch.yml      # insert 行（id: log-guardian）
├── lib/
│   ├── index.js          # 宿主：apply + 路由 + WS 广播 + 双通道告警
│   ├── scan.js           # 关键词编译/扫描/配置解析（纯函数）
│   ├── tailer.js         # LogTailer：偏移 + watch/轮询 + 截断自愈
│   └── client.js         # 浏览器端脚本（toast + Notification）
└── test/
    └── smoke.mjs         # 冒烟测试
```

## 安全边界

- **只读监视**：只读日志、只发告警，不修改日志、不拦截调用、不越权 kill 进程。它是「哨兵」，不是「闸门」。
- **不外发数据**：告警只经本机 `ctx.logger` 与回环/同源 WebSocket 呈现，不上报任何第三方。
- **容错优先**：watch 失败降级轮询、文件缺失/截断/轮转自动恢复、去重防刷屏 —— 作为安全插件，自身绝不应成为新的单点故障。
- **建议搭配**：配合 `dsh-undo-savepoint`（配置快照回滚）与 `plugin_guard`（崩溃自愈）构成「检测 → 取证 → 回滚」闭环。

## License

[MIT](./LICENSE) © 2026 [miaoluoxue](https://github.com/miaoluoxue)
