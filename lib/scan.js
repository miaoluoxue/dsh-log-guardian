// dsh-log-guardian — 关键词扫描与配置解析（纯函数，零依赖，可独立单测）。
//
// 关键词两种形态：
//   · 普通字符串 —— 大小写不敏感的子串匹配（转义后套 i 标志）。
//   · "/pattern/flags" 字面量 —— 按正则处理（如 "/require\\(['\"]child_process['\"]\\)/i"）。

/** 出厂默认高危关键词（对应 DSH 提示注入攻击链 + 沙箱逃逸调用面）。 */
export const DEFAULT_KEYWORDS = [
	"cordis_define",
	"cordis_run",
	"cordis_stop",
	"cordis_undefine",
	"cordis_runtime_inspect",
	"subprocess",
	"child_process",
	"execSync",
	"spawnSync"
];

/** 转义正则元字符，把普通字符串变成字面子串。 */
export function escapeRegExp(source) {
	return String(source).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 编译关键词为可复用的正则表。
 * @param {string[]} keywords
 * @returns {Array<{ source: string, re: RegExp }>}
 */
export function compileKeywords(keywords) {
	const out = [];
	for (const raw of keywords) {
		const k = typeof raw === "string" ? raw : String(raw);
		if (k.length === 0) continue;
		// "/regex/flags" 字面量
		if (k.startsWith("/") && k.length > 2) {
			const last = k.lastIndexOf("/");
			if (last > 0) {
				try {
					out.push({ source: k, re: new RegExp(k.slice(1, last), k.slice(last + 1)) });
					continue;
				} catch {
					/* 非法正则字面量 → 回落到普通子串 */
				}
			}
		}
		out.push({ source: k, re: new RegExp(escapeRegExp(k), "i") });
	}
	return out;
}

/**
 * 扫描一段新增日志文本，返回命中行。
 * @param {string} text 新增文本。
 * @param {Array<{ source: string, re: RegExp }>} compiled compileKeywords 的结果。
 * @returns {Array<{ line: string, lineNo: number, keywords: string[] }>}
 */
export function scanIncrement(text, compiled) {
	if (typeof text !== "string" || text.length === 0) return [];
	const hits = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i += 1) {
		const line = lines[i];
		if (!line) continue;
		const matched = [];
		for (const c of compiled) {
			if (c.re.test(line)) matched.push(c.source);
		}
		if (matched.length > 0) hits.push({ line, lineNo: i + 1, keywords: matched });
	}
	return hits;
}

/** 逗号/分号分隔的列表解析（支持引号包裹与空项剔除）。 */
export function splitList(raw) {
	const s = String(raw ?? "").trim();
	if (!s) return [];
	const parts = [];
	for (const piece of s.split(/[,;]/)) {
		const v = piece.trim().replace(/^['"]|['"]$/g, "");
		if (v) parts.push(v);
	}
	return parts;
}

/**
 * 关键词解析优先级：环境变量 LOG_MONITOR_KEYWORDS > config.keywords > 默认。
 * @param {object} config 插件配置（cordis.patch.yml 的 config 段）。
 */
export function resolveKeywords(config) {
	const env = typeof process !== "undefined" ? process.env.LOG_MONITOR_KEYWORDS : "";
	if (env && env.trim()) return splitList(env);
	if (Array.isArray(config?.keywords) && config.keywords.length > 0) {
		return config.keywords.filter((k) => typeof k === "string" && k.length > 0);
	}
	return DEFAULT_KEYWORDS;
}

/**
 * 日志文件路径解析。
 * 优先级：环境变量 LOG_MONITOR_FILES > config.files > 自动探测。
 * 每个条目可以是文件绝对路径，或目录（展开为目录下的 *.log 与 main.*）。
 * @param {object} config 插件配置。
 * @param {object} io 注入的 fs 外观（便于单测；默认用 node:fs）。
 * @returns {string[]} 去重后的绝对文件路径。
 */
export function resolveFiles(config, io) {
	const fs = io?.fs;
	const path = io?.path;
	const os = io?.os;
	const explicitEnv = typeof process !== "undefined" ? process.env.LOG_MONITOR_FILES : "";
	let entries = [];
	if (explicitEnv && explicitEnv.trim()) {
		entries = splitList(explicitEnv);
	} else if (Array.isArray(config?.files) && config.files.length > 0) {
		entries = config.files.filter((f) => typeof f === "string" && f.length > 0);
	}
	const out = new Set();
	const expand = (entry) => {
		const p = String(entry).trim();
		if (!p) return;
		if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
			for (const name of fs.readdirSync(p)) {
				if (name.endsWith(".log") || /^main\.\d{2}$/.test(name)) out.add(path.join(p, name));
			}
		} else if (fs.existsSync(p)) {
			out.add(p);
		}
	};
	if (entries.length > 0) {
		for (const entry of entries) expand(entry);
		if (out.size > 0) return [...out];
		// 显式配置但都探测不到 → 空结果由调用方打告警提示，不静默回退。
		return [...out];
	}
	// 自动探测：DSH 约定日志目录。
	const home = typeof process !== "undefined" && process.env.DSH_HOME
		? process.env.DSH_HOME
		: path.join(os.homedir(), ".dsh");
	const dirs = [
		typeof process !== "undefined" ? process.env.DSH_LOG_DIR : "",
		path.join(home, "logs"),
		path.join(home, "profiles", "web", "logs"),
		path.join(os.homedir(), ".dsh", "logs")
	].filter(Boolean);
	for (const dir of dirs) expand(dir);
	return [...out];
}
