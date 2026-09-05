// dsh-log-guardian — 宿主半边（随 DSH 主进程启动即运行）。
//
// 把「被动的人工日志查询」升级为「主动的自动化安全哨兵」：
//   · 每个目标日志文件一个 LogTailer：增量偏移读取 + fs.watch（降级轮询）。
//   · 新增字节命中关键词 → 双通道告警：
//       通道一：ctx.logger.warn —— 被前端日志面板捕获并染色；
//       通道二：WebSocket 广播 + 注入的浏览器脚本 toast / Notification。
//   · 附 REST 端点（/alerts 轮询回放、/status 自检）供管理员与排障使用。
//
// 无第三方依赖（Node 原生 fs / path / crypto / os）。WebSocket 为 RFC 6455
// 最小实现（参考内置 dsh-terminal 的握手 + 文本帧 + ping）。

import { createHash } from "node:crypto";
import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DEFAULT_KEYWORDS, compileKeywords, resolveFiles, resolveKeywords, scanIncrement } from "./scan.js";
import { LogTailer } from "./tailer.js";
import { CLIENT_JS } from "./client.js";

export const name = "log-guardian";
export const inject = ["webServer"];

// schemastery 是 DSH 内核自带的 peer 依赖（用于 config 段校验）。用动态导入
// 兜底：即使某个安装环境解析不到它，本安全插件也不应在模块装载阶段就把整个
// DSH 启动拖崩 —— 缺它时退化为「不校验 config 原样透传」，apply 逻辑不受影响。
let z = null;
try {
	z = (await import("@deepseek-ai/schemastery")).default ?? null;
} catch {
	z = null;
}

export const Config = z
	? z.object({
			files: z.array(z.string()).default([]),
			keywords: z.array(z.string()).default(DEFAULT_KEYWORDS),
			pollMs: z.number().default(2000),
			notify: z.boolean().default(true),
			dedupeMs: z.number().default(5000),
			maxAlerts: z.number().default(200)
		})
	: undefined;

// ── 小工具 ──────────────────────────────────────────────────────────────────

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const ALERTS_ROUTE = "/dsh-log-guardian/alerts";
const STATUS_ROUTE = "/dsh-log-guardian/status";
const CLIENT_ROUTE = "/dsh-log-guardian/client.js";
const EVENTS_ROUTE = "/dsh-log-guardian/events";

function fnv1a(str) {
	let h = 0x811c9dc5;
	for (let i = 0; i < str.length; i += 1) {
		h ^= str.charCodeAt(i);
		h = (h * 0x01000193) >>> 0;
	}
	return h.toString(36);
}

function truncate(s, n) {
	const t = String(s ?? "");
	return t.length > n ? t.slice(0, n) + "…" : t;
}

function isLoopback(req) {
	const ra = req?.socket?.remoteAddress;
	return ra === "127.0.0.1" || ra === "::1" || ra === "::ffff:127.0.0.1";
}

function sameOrigin(req) {
	const origin = req?.headers?.origin;
	const host = req?.headers?.host;
	if (origin === undefined || host === undefined) return false;
	try {
		return new URL(origin).host === host;
	} catch {
		return false;
	}
}

/** 可信请求：回环或同源（本地 Web UI 恒为回环；远程管理员走同源）。 */
function isTrusted(req) {
	return isLoopback(req) || sameOrigin(req);
}

function sendJson(res, status, obj) {
	const data = Buffer.from(JSON.stringify(obj), "utf8");
	res.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store",
		"content-length": String(data.length)
	});
	res.end(data);
}

// ── WebSocket 最小实现（服务端→客户端文本帧 + ping；客户端只需接收）──────────

function wsSendRaw(socket, buffer) {
	try {
		socket.write(buffer);
	} catch {}
}

function wsSendText(socket, text) {
	const payload = Buffer.from(text, "utf8");
	const len = payload.length;
	let header;
	if (len < 126) {
		header = Buffer.alloc(2);
		header[0] = 0x81;
		header[1] = len;
	} else if (len < 65536) {
		header = Buffer.alloc(4);
		header[0] = 0x81;
		header[1] = 126;
		header.writeUInt16BE(len, 2);
	} else {
		header = Buffer.alloc(10);
		header[0] = 0x81;
		header[1] = 127;
		header.writeBigUInt64BE(BigInt(len), 2);
	}
	wsSendRaw(socket, Buffer.concat([header, payload]));
}

function wsSendPing(socket) {
	wsSendRaw(socket, Buffer.from([0x89, 0]));
}

// ── 插件入口 ────────────────────────────────────────────────────────────────

export function apply(ctx, config = {}) {
	// 配置解析（env 覆盖优先，满足「无需重启即可改关键词」）。
	const keywords = resolveKeywords(config);
	const compiled = compileKeywords(keywords);
	const pollMs = (() => {
		const env = process.env.LOG_MONITOR_POLL_MS;
		if (env && /^\d+$/.test(env.trim()) && Number(env) > 0) return Number(env);
		return Number(config.pollMs) > 0 ? Number(config.pollMs) : 2000;
	})();
	const dedupeMs = Number(config.dedupeMs) >= 0 ? Number(config.dedupeMs) : 5000;
	const maxAlerts = Number(config.maxAlerts) > 0 ? Number(config.maxAlerts) : 200;
	const notify = config.notify !== false;

	const files = resolveFiles(config, {
		fs: { existsSync, readdirSync, statSync },
		path: { join },
		os: { homedir }
	});

	// 告警内存环 + 去重表。
	const alerts = [];
	const lastAlert = new Map();
	const clients = new Set();
	let seq = 0;

	const broadcast = (alert) => {
		if (!notify) return;
		const text = JSON.stringify({ type: "alert", alert });
		for (const socket of clients) wsSendText(socket, text);
	};

	const raiseAlert = (file, hit) => {
		const key = file + "::" + hit.keywords.join(",") + "::" + fnv1a(hit.line);
		const now = Date.now();
		const last = lastAlert.get(key);
		if (last !== undefined && now - last < dedupeMs) return;
		lastAlert.set(key, now);
		if (lastAlert.size > 2000) {
			for (const [k, ts] of lastAlert) if (now - ts > dedupeMs * 4) lastAlert.delete(k);
		}

		const alert = {
			id: String(now) + "-" + String(seq++),
			at: new Date(now).toISOString(),
			file,
			keywords: hit.keywords,
			line: hit.line
		};
		alerts.push(alert);
		if (alerts.length > maxAlerts) alerts.splice(0, alerts.length - maxAlerts);

		// 通道一：控制台/日志面板高亮告警。
		ctx.logger.warn(`⚠️ [LogGuardian] 发现高危调用 [${hit.keywords.join(", ")}] @ ${file}: ${truncate(hit.line, 400)}`);

		// 通道二：WebSocket 广播（前端 toast + 系统通知）。
		broadcast(alert);
	};

	const tailers = files.map((file) => {
		const tailer = new LogTailer(file, {
			pollMs,
			onChunk: (text, f) => {
				for (const hit of scanIncrement(text, compiled)) raiseAlert(f, hit);
			},
			onError: (info) => {
				if (info.type === "reset") {
					ctx.logger.info(`[LogGuardian] 检测到日志 ${info.file} 被截断/轮转（${info.from}→${info.size} 字节），已重置偏移`);
				} else if (info.type === "polling-fallback") {
					ctx.logger.info(`[LogGuardian] ${info.file} 的 fs.watch 不可用，已降级为轮询（${pollMs}ms）`);
				} else if (info.type === "read") {
					ctx.logger.warn(`[LogGuardian] 读取 ${info.file} 失败：${info.error}`);
				}
			}
		});
		return tailer;
	});

	// 启动日志（明确告知监控面，便于管理员核对自动探测结果）。
	if (files.length === 0) {
		ctx.logger.warn("[LogGuardian] 未探测到任何日志文件：请设置 LOG_MONITOR_FILES 或 cordis.patch.yml 的 files（绝对路径或目录）");
	} else {
		ctx.logger.info(`[LogGuardian] 开始监控 ${files.length} 个日志文件，关键词 ${keywords.length} 个：[${keywords.join(", ")}]`);
		for (const f of files) ctx.logger.info(`[LogGuardian]   · ${f}`);
	}

	const disposers = [];
	const webServer = ctx.webServer ?? (typeof ctx.get === "function" ? ctx.get("webServer") : undefined);

	if (webServer !== undefined && typeof webServer.register === "function") {
		// REST：最近告警回放。
		disposers.push(webServer.register({
			kind: "exact",
			path: ALERTS_ROUTE,
			handler: (req, res) => {
				if (!isTrusted(req)) return sendJson(res, 403, { ok: false, error: "untrusted origin" });
				return sendJson(res, 200, { ok: true, count: alerts.length, alerts: alerts.slice(-50) });
			}
		}));

		// REST：自检状态。
		disposers.push(webServer.register({
			kind: "exact",
			path: STATUS_ROUTE,
			handler: (req, res) => {
				if (!isTrusted(req)) return sendJson(res, 403, { ok: false, error: "untrusted origin" });
				return sendJson(res, 200, {
					ok: true,
					keywords,
					notify,
					pollMs,
					files: tailers.map((t) => ({ file: t.filePath, offset: t.offset, started: t.started, polling: !!t._timer }))
				});
			}
		}));

		// 客户端脚本（静态，随包分发）。
		disposers.push(webServer.register({
			kind: "exact",
			path: CLIENT_ROUTE,
			handler: (req, res) => {
				res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store" });
				res.end(CLIENT_JS);
			}
		}));

		// WebSocket 推送通道。
		if (typeof webServer.registerUpgrade === "function") {
			disposers.push(webServer.registerUpgrade({
				path: EVENTS_ROUTE,
				handler: (req, socket) => {
					if (!isTrusted(req)) {
						socket.destroy();
						return;
					}
					const key = req.headers["sec-websocket-key"];
					if (!key) {
						socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
						socket.destroy();
						return;
					}
					const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
					socket.write(
						"HTTP/1.1 101 Switching Protocols\r\n" +
						"Upgrade: websocket\r\n" +
						"Connection: Upgrade\r\n" +
						"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
					);
					clients.add(socket);
					const beat = setInterval(() => wsSendPing(socket), 25000);
					beat.unref?.();
					const cleanup = () => {
						clearInterval(beat);
						clients.delete(socket);
						try {
							socket.destroy();
						} catch {}
					};
					socket.on("close", cleanup);
					socket.on("error", cleanup);
				}
			}));
		}

		// 注入客户端脚本（tapIndex）。
		if (typeof webServer.tapIndex === "function") {
			disposers.push(webServer.tapIndex((html) => {
				if (html.indexOf(CLIENT_ROUTE) !== -1) return html;
				const tag = `<script defer src="${CLIENT_ROUTE}"></script>`;
				if (html.indexOf("</body>") !== -1) return html.replace("</body>", tag + "</body>");
				return html + tag;
			}));
		}
	} else if (notify) {
		ctx.logger.info("[LogGuardian] webServer 服务不可用：前端 WebSocket 告警已禁用，仅保留日志面板告警（通道一）");
	}

	ctx.effect(() => {
		for (const t of tailers) t.start();
		return () => {
			for (const d of disposers) {
				try {
					d();
				} catch {}
			}
			for (const t of tailers) t.stop();
			for (const socket of clients) {
				try {
					socket.destroy();
				} catch {}
			}
			clients.clear();
		};
	}, "log-guardian: stop tailers and routes");
}
