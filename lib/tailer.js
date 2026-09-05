// dsh-log-guardian — 增量日志 tail（文件偏移 + fs.watch 混合监听 + 轮询降级）。
//
// 设计要点（对齐方案文档「技术实现方案」）：
//   · 增量读取：记录字节偏移，每次只读文件末尾新增字节，绝不重扫历史。
//   · 字节级偏移：用 Buffer 读、按字节推进 offset —— 中文等多字节日志不会
//     因为「字符数 ≠ 字节数」而偏移错乱。
//   · 截断 / 轮转自愈：读到「当前大小 < 偏移」判定为被截断或 logrotate 切割，
//     自动把偏移重置为 0 继续追新文件，不抛错、不崩溃。
//   · 混合监听：优先 fs.watch(目录)；不可用或报错时降级为 setInterval 轮询；
//     另加一条低频「安全兜底轮询」，避免 NFS 等漏事件的文件系统漏报。
//
// 纯 Node 原生 API（node:fs / node:path），无第三方依赖。

import { createReadStream, existsSync, readdirSync, statSync, watch } from "node:fs";
import { basename, dirname, join } from "node:path";

export class LogTailer {
	/**
	 * @param {string} filePath 要监控的日志文件绝对路径。
	 * @param {object} opts { onChunk(text, file), onError(info), pollMs, safetyPollMs }
	 */
	constructor(filePath, opts = {}) {
		this.filePath = filePath;
		this.offset = 0;
		this.started = false;
		this.onChunk = typeof opts.onChunk === "function" ? opts.onChunk : () => {};
		this.onError = typeof opts.onError === "function" ? opts.onError : () => {};
		this.pollMs = Number(opts.pollMs) > 0 ? Number(opts.pollMs) : 2000;
		this.safetyPollMs = Number(opts.safetyPollMs) > 0 ? Number(opts.safetyPollMs) : Math.max(this.pollMs * 10, 15000);
		this._watcher = null;
		this._timer = null;
		this._safetyPoll = null;
		this._readTimer = null;
		this._reading = false;
		this._pending = false;
	}

	/** 把偏移推进到当前文件末尾，跳过既有历史（初始化语义）。 */
	skipExisting() {
		try {
			const st = statSync(this.filePath);
			if (st.isFile()) this.offset = st.size;
		} catch {
			this.offset = 0;
		}
		return this.offset;
	}

	/** 同步读取一次新增字节（幂等：只读 offset 之后的字节）。 */
	readNew() {
		if (this._reading) {
			this._pending = true;
			return;
		}
		let st;
		try {
			st = statSync(this.filePath);
		} catch (err) {
			// 文件暂时不存在（轮转切换窗口）→ 偏移归零等新文件出现。
			if (err && err.code === "ENOENT" && this.offset !== 0) this.offset = 0;
			return;
		}
		if (!st.isFile()) return;
		let start = this.offset;
		if (st.size < start) {
			this.onError({ type: "reset", file: this.filePath, from: start, size: st.size });
			start = 0;
		}
		const toRead = st.size - start;
		if (toRead <= 0) return;

		this._reading = true;
		const chunks = [];
		const stream = createReadStream(this.filePath, { start, end: st.size - 1 });
		const finish = () => {
			this._reading = false;
			const buf = Buffer.concat(chunks);
			this.offset = start + buf.length; // 字节级推进
			if (buf.length > 0) {
				try {
					this.onChunk(buf.toString("utf8"), this.filePath);
				} catch (e) {
					this.onError({ type: "callback", file: this.filePath, error: String((e && e.message) || e) });
				}
			}
			if (this._pending) {
				this._pending = false;
				setImmediate(() => this.readNew());
			}
		};
		stream.on("data", (c) => chunks.push(c));
		stream.on("error", (err) => {
			this._reading = false;
			this._pending = false;
			this.onError({ type: "read", file: this.filePath, error: String((err && err.message) || err) });
		});
		stream.on("end", finish);
	}

	/** 去抖触发一次读取（fs.watch 事件可能密集连发）。 */
	_scheduleRead() {
		if (this._readTimer) return;
		this._readTimer = setTimeout(() => {
			this._readTimer = null;
			this.readNew();
		}, 50);
	}

	/** fs.watch 失败时降级为轮询。 */
	_fallbackToPolling() {
		if (this._timer) return;
		this._timer = setInterval(() => this._scheduleRead(), this.pollMs);
		this._timer.unref?.();
		this.onError({ type: "polling-fallback", file: this.filePath });
	}

	/** 启动监听：先对齐偏移，再挂 watch / 轮询。 */
	start() {
		if (this.started) return;
		this.started = true;
		this.skipExisting();
		this.readNew(); // 收敛「stat 与挂 watch 之间」写入的字节

		const dir = dirname(this.filePath);
		const base = basename(this.filePath);
		let watched = false;
		try {
			this._watcher = watch(dir, { persistent: false }, (eventType, filename) => {
				// rename 一定重读（轮转/截断信号）；change 只认目标文件。
				if (eventType === "rename" || filename === null || filename === base) this._scheduleRead();
			});
			this._watcher.on("error", () => {
				try {
					this._watcher?.close();
				} catch {}
				this._watcher = null;
				this._fallbackToPolling();
			});
			watched = true;
		} catch {
			watched = false;
		}
		if (!watched) this._fallbackToPolling();

		// 安全兜底：低频轮询，防 watch 漏事件（NFS / 部分网络盘）。
		this._safetyPoll = setInterval(() => this._scheduleRead(), this.safetyPollMs);
		this._safetyPoll.unref?.();
	}

	stop() {
		this.started = false;
		if (this._watcher) {
			try {
				this._watcher.close();
			} catch {}
			this._watcher = null;
		}
		if (this._timer) {
			clearInterval(this._timer);
			this._timer = null;
		}
		if (this._safetyPoll) {
			clearInterval(this._safetyPoll);
			this._safetyPoll = null;
		}
		if (this._readTimer) {
			clearTimeout(this._readTimer);
			this._readTimer = null;
		}
	}
}

// 供 resolveFiles 使用的纯 node 外观（scan.js 注入点复用）。
export const NODE_FS_IO = {
	existsSync,
	readdirSync,
	statSync
};
export const NODE_PATH = { basename, dirname, join };
