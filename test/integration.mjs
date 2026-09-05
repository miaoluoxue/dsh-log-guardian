// dsh-log-guardian — 端到端集成测试（宿主半边全链路）。
//
// 验证 apply() 把「LogTailer → scanIncrement → raiseAlert」正确接起来，并触发
// 双通道告警：
//   通道一：ctx.logger.warn 收到高危告警；
//   通道二：已连接的 WebSocket 客户端收到告警帧（RFC 6455 文本帧）。
//
// 用桩 cordis ctx（logger / effect / webServer）+ 真实临时日志文件，零外部依赖：
//   node test/integration.mjs

import { EventEmitter } from "node:events";
import { mkdtempSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { apply } from "../lib/index.js";

let passed = 0;
let failed = 0;
function check(desc, cond) {
	if (cond) {
		passed += 1;
		console.log(`  ok  ${desc}`);
	} else {
		failed += 1;
		console.error(`FAIL  ${desc}`);
	}
}

// base64 of "0123456789abcdef"（任意合法的 sec-websocket-key 即可）
const WS_KEY = "MDEyMzQ1Njc4OWFiY2RlZg==";

async function main() {
	const dir = mkdtempSync(join(tmpdir(), "logguardian-int-"));
	const file = join(dir, "app.log");
	writeFileSync(file, "boot line\n", "utf8");

	const warns = [];
	let wsHandler = null;
	const fakeSocket = new EventEmitter();
	const frames = [];
	fakeSocket.write = (buf) => frames.push(buf);
	fakeSocket.destroy = () => {};

	const webServer = {
		register: () => () => {},
		registerUpgrade: (r) => {
			wsHandler = r.handler;
			return () => {};
		},
		tapIndex: () => () => {}
	};
	let dispose = () => {};
	const ctx = {
		logger: { warn: (m) => warns.push(String(m)), info: () => {} },
		webServer,
		effect: (setup) => {
			dispose = setup() || (() => {});
			return () => dispose();
		},
		get: () => undefined
	};

	// 钉住环境变量，避免宿主环境的 LOG_MONITOR_* 干扰用例语义。
	const savedKw = process.env.LOG_MONITOR_KEYWORDS;
	const savedFiles = process.env.LOG_MONITOR_FILES;
	process.env.LOG_MONITOR_KEYWORDS = "cordis_run";
	delete process.env.LOG_MONITOR_FILES;

	apply(ctx, { files: [file], pollMs: 100, dedupeMs: 0, notify: true });

	// 模拟一个浏览器 WebSocket 客户端接入。
	wsHandler({ socket: { remoteAddress: "127.0.0.1" }, headers: { "sec-websocket-key": WS_KEY } }, fakeSocket);
	check("WebSocket 升级握手成功（101）", frames.some((b) => b.toString("latin1").startsWith("HTTP/1.1 101")));

	// 恢复环境变量。
	if (savedKw === undefined) delete process.env.LOG_MONITOR_KEYWORDS;
	else process.env.LOG_MONITOR_KEYWORDS = savedKw;
	if (savedFiles === undefined) delete process.env.LOG_MONITOR_FILES;
	else process.env.LOG_MONITOR_FILES = savedFiles;

	// 等 fs.watch 挂上，再写入高危行（兜底：LogTailer 的 15s 安全轮询保证最终读到）。
	await new Promise((r) => setTimeout(r, 300));
	appendFileSync(file, "warn cordis_run triggered from prompt injection\n", "utf8");

	const deadline = Date.now() + 20000;
	let warnHit = false;
	let wsHit = false;
	while (Date.now() < deadline && !(warnHit && wsHit)) {
		warnHit = warns.some((w) => w.includes("cordis_run"));
		wsHit = frames.some((b) => b.toString("utf8").includes("cordis_run"));
		if (!(warnHit && wsHit)) await new Promise((r) => setTimeout(r, 200));
	}

	check("通道一：ctx.logger.warn 收到高危告警", warnHit);
	check("通道二：WebSocket 客户端收到告警帧", wsHit);

	dispose();
	rmSync(dir, { recursive: true, force: true });

	console.log(`\n${passed} passed, ${failed} failed`);
	process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
