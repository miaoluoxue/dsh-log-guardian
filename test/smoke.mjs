// dsh-log-guardian 冒烟测试：验证关键词编译/扫描、文件解析、LogTailer 的
// 增量偏移 / 截断重置 / 多字节偏移正确性。
// 纯函数 + 临时文件，零依赖： node test/smoke.mjs

import { mkdtempSync, writeFileSync, appendFileSync, truncateSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compileKeywords, scanIncrement, resolveFiles, resolveKeywords, splitList, DEFAULT_KEYWORDS } from "../lib/scan.js";
import { LogTailer } from "../lib/tailer.js";

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

// ── compileKeywords / scanIncrement ─────────────────────────────────────────

{
	const compiled = compileKeywords(["cordis_define", "/subprocess\\.(?:spawn|run)/i", "child_process"]);
	check("编译普通子串不抛错", compiled.length === 3);
	const hits = scanIncrement(
		"info 2026-09-05 CORDIS_DEFINE called\n" +
		"attack: subprocess.spawn('cmd')\n" +
		"normal line nothing here\n" +
		"危险：child_process exec\n",
		compiled
	);
	check("命中 3 行", hits.length === 3);
	check("第 1 行命中 cordis_define（大小写不敏感）", hits[0].keywords[0] === "cordis_define");
	check("第 2 行命中正则 subprocess.spawn", hits[1].keywords[0].startsWith("/subprocess"));
	check("第 4 行命中 child_process", hits[2].keywords[0] === "child_process");
	check("无关行不误报", !hits.some((h) => h.line.includes("normal line")));
}

{
	// 中文多字节内容也照常匹配。
	const compiled = compileKeywords(["subprocess"]);
	const hits = scanIncrement("日志：检测到 subprocess 调用（中文上下文）", compiled);
	check("中文上下文命中关键词", hits.length === 1);
}

{
	// 非法正则字面量回落到普通子串。
	const compiled = compileKeywords(["/[/"]);
	check("非法正则字面量回落为子串", compiled.length === 1 && compiled[0].re.test("a/[/b"));
}

// ── resolveKeywords / splitList ─────────────────────────────────────────────

{
	check("默认关键词含 cordis_run", DEFAULT_KEYWORDS.includes("cordis_run"));
	check("config 关键词覆盖默认", resolveKeywords({ keywords: ["evil"] })[0] === "evil");
	check("空 config 回默认", resolveKeywords({}).length === DEFAULT_KEYWORDS.length);
	check("splitList 逗号/分号/引号", JSON.stringify(splitList('a, "b c"; d')) === JSON.stringify(["a", "b c", "d"]));
}

// ── resolveFiles（mock io，测目录展开 + 过滤） ─────────────────────────────

{
	const mockFs = {
		existsSync: (p) => p === "/logs" || p === "/logs/a.log" || p === "/logs/main.00" || p === "/logs/main.01" || p === "/logs/keep.log",
		readdirSync: (p) => (p === "/logs" ? ["a.log", "b.txt", "main.00", "main.01", "keep.log"] : []),
		statSync: (p) => ({ isDirectory: () => p === "/logs" })
	};
	const mockPath = { join: (a, b) => a + "/" + b };
	const mockOs = { homedir: () => "/home/u" };
	const files = resolveFiles({ files: ["/logs"] }, { fs: mockFs, path: mockPath, os: mockOs });
	check("目录展开出 .log 与 main.*，剔除 b.txt", JSON.stringify(files.sort()) === JSON.stringify(["/logs/a.log", "/logs/keep.log", "/logs/main.00", "/logs/main.01"].sort()));
}

// ── LogTailer：增量偏移 / 截断重置 / 多字节 ────────────────────────────────

function readOnce(t) {
	return new Promise((resolve) => {
		const chunks = [];
		const orig = t.onChunk;
		t.onChunk = (text, file) => {
			orig(text, file);
			chunks.push(text);
			resolve(chunks.join(""));
		};
		t.readNew();
		setTimeout(() => resolve(chunks.join("")), 60);
	});
}

{
	const dir = mkdtempSync(join(tmpdir(), "logguardian-"));
	const file = join(dir, "app.log");
	const tail = new LogTailer(file, { onChunk: () => {}, pollMs: 1000 });

	// 初始：中文内容（多字节），skipExisting 应把 offset 设为字节数。
	const initial = "启动日志：你好世界\n";
	writeFileSync(file, initial, "utf8");
	const off = tail.skipExisting();
	check("skipExisting 对齐到字节偏移", off === Buffer.byteLength(initial, "utf8"));

	// 追加一行危险调用 → readNew 只返回新增部分。
	const added = "warn cordis_run triggered\n";
	appendFileSync(file, added, "utf8");
	const got = await readOnce(tail);
	check("readNew 只返回新增内容", got === added);
	check("offset 推进到文件末尾（字节）", tail.offset === Buffer.byteLength(initial + added, "utf8"));

	// 截断 → 自动重置偏移并从头读。
	truncateSync(file, Buffer.byteLength(initial, "utf8"));
	const got2 = await readOnce(tail);
	check("截断后重置偏移并读回现有内容", got2 === initial);

	// 再次追加含关键词内容，确认截断后仍可继续增量。
	appendFileSync(file, "subprocess.spawn hit\n", "utf8");
	const got3 = await readOnce(tail);
	check("截断后继续增量读取", got3 === "subprocess.spawn hit\n");

	tail.stop();
	rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
