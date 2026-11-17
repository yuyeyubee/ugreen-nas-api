#!/usr/bin/env node
'use strict';
/**
 * 绿联 NAS (UGOS Pro) 接口还原实现 —— 零依赖 Node.js 客户端 (Node >= 18)
 *
 * 覆盖：账号密码登录、登录态校验、根目录/目录列表、文件下载（含断点续传）。
 * 协议细节见同目录 API.md。
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const DEFAULT_CLIENT_VERSION = '1.21.0.80330';
const SESSION_FILE = path.join(__dirname, '.session.json');

// ---------------------------------------------------------------- crypto ---

/** PEM(PKCS#1 或 SPKI) -> KeyObject */
function pemToPublicKey(pem) {
  const b64 = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  try {
    return crypto.createPublicKey({ key: der, format: 'der', type: 'pkcs1' });
  } catch (e) {
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  }
}

/** 等价 JSEncrypt.setPublicKey(...).encryptLong(...)：RSA/PKCS#1 v1.5，Base64 输出 */
function rsaEncrypt(pub, text) {
  const key = typeof pub === 'string' ? pemToPublicKey(pub) : pub;
  const maxChunk = key.asymmetricKeyDetails.modulusLength / 8 - 11;
  const data = Buffer.from(String(text), 'utf8');
  if (data.length <= maxChunk) {
    return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, data).toString('base64');
  }
  const out = [];
  for (let i = 0; i < data.length; i += maxChunk) {
    out.push(crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, data.subarray(i, i + maxChunk)));
  }
  return Buffer.concat(out).toString('base64');
}

/** 前端 Aes128gcm（实为 AES-256-GCM）：key=32 字符 ASCII，输出 base64(iv|ct|tag) */
function aesGcmEncrypt(keyStr, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyStr, 'utf8'), iv);
  const enc = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, enc, cipher.getAuthTag()]).toString('base64');
}

function aesGcmDecrypt(keyStr, b64) {
  const buf = Buffer.from(String(b64), 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyStr, 'utf8'), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newAesKey = () => crypto.randomUUID().replace(/-/g, '');

/** 秒 -> HH:MM:SS（与客户端展示一致） */
function formatDuration(sec) {
  if (!Number.isFinite(sec) || sec <= 0) return '';
  const t = Math.floor(sec);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(Math.floor(t / 3600))}:${p(Math.floor((t % 3600) / 60))}:${p(t % 60)}`;
}

// ---------------------------------------------------------------- client ---

class UgreenNasClient {
  /**
   * @param {object} opts
   * @param {string} opts.base            NAS 地址: http://IP:9999 或 https://xxx.ug.link
   * @param {string} [opts.token]         已有会话 token
   * @param {string} [opts.publicKey]     enPublicKey(PEM)，HTTP 应用层加密用
   * @param {'header'|'url'} [opts.tokenWhere]
   * @param {boolean} [opts.encrypt]      应用层加密开关（默认按协议自动：http 加密, https 不加密）
   */
  constructor(opts = {}) {
    this.base = String(opts.base || '').replace(/\/+$/, '');
    if (!/^https?:\/\//.test(this.base)) throw new Error('base 必须是 http(s):// 开头的 NAS 地址');
    this.token = opts.token || '';
    this.publicKey = opts.publicKey || '';
    this.tokenWhere = opts.tokenWhere || 'header';
    this.lang = opts.lang || 'zh-CN';
    this.clientVersion = opts.clientVersion || DEFAULT_CLIENT_VERSION;
    this.clientId = opts.clientId || 'ugreen-nas-api';
    this.encryptMode = opts.encrypt === undefined ? 'auto' : (opts.encrypt ? 'always' : 'never');
    this.user = opts.user || null;
  }

  get isHttps() { return this.base.startsWith('https://'); }

  /** 与官方客户端一致：https 由传输层加密，不再叠加应用层加密 */
  get useAppEncrypt() {
    if (this.encryptMode === 'always') return true;
    if (this.encryptMode === 'never') return false;
    return !this.isHttps && Boolean(this.token) && Boolean(this.publicKey);
  }

  _baseHeaders() {
    return {
      'UG-Agent': 'PC/WEB',
      'User-Feature': 'Mac',
      'Client-Id': this.clientId,
      'Client-Version': this.clientVersion,
      'X-Specify-Language': this.lang,
    };
  }

  _qs(obj) {
    return Object.entries(obj)
      .filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join('&');
  }

  /**
   * 统一请求。返回业务 JSON（自动解密 encrypt_resp_body），raw=true 时返回原始 Response。
   */
  async request(method, apiPath, { query = {}, body = null, tokenAuth = true, raw = false } = {}) {
    const headers = this._baseHeaders();
    const token = this.token;
    const encrypted = Boolean(tokenAuth && token) && this.useAppEncrypt;
    const aesKey = encrypted ? newAesKey() : null;

    const fullPath = apiPath.startsWith('/ugreen/') ? apiPath : '/ugreen/' + apiPath.replace(/^\/+/, '');
    const queryObj = { ...query };

    if (tokenAuth && token && !encrypted) {
      if (this.tokenWhere === 'url') queryObj.token = token;
      else headers['X-Ugreen-Token'] = token;
    }

    if (encrypted) {
      const pub = pemToPublicKey(this.publicKey);
      headers['X-Ugreen-Security-Key'] = md5(token);
      if (this.tokenWhere === 'header') headers['X-Ugreen-Token'] = rsaEncrypt(pub, token);
      headers['X-Ugreen-Security-Code'] = rsaEncrypt(pub, aesKey);
    }

    let qs = this._qs(queryObj);
    if (encrypted && qs) {
      qs = 'encrypt_query=' + encodeURIComponent(aesGcmEncrypt(aesKey, qs));
    }
    const url = this.base + fullPath + (qs ? '?' + qs : '');

    let payload = null;
    if (body !== null && body !== undefined) {
      headers['Content-Type'] = 'application/json';
      if (encrypted) {
        const json = JSON.stringify(body);
        payload = JSON.stringify({
          encrypt_req_body: aesGcmEncrypt(aesKey, json),
          req_body_sha256: sha256(json),
        });
      } else {
        payload = JSON.stringify(body);
      }
    }

    const res = await fetch(url, { method, headers, body: payload });
    if (raw) return res;

    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      return { code: res.status, msg: text.slice(0, 200), data: null, _httpStatus: res.status };
    }
    if (json && json.encrypt_resp_body && aesKey) {
      json = JSON.parse(aesGcmDecrypt(aesKey, json.encrypt_resp_body));
    }
    json._headers = Object.fromEntries(res.headers.entries());
    json._httpStatus = res.status;
    return json;
  }

  _ok(json, what) {
    if (!json || json.code !== 200) {
      const err = new Error(`${what} 失败: code=${json && json.code} msg=${json && json.msg}`);
      err.response = json;
      throw err;
    }
    return json;
  }

  // ---- 登录 --------------------------------------------------------------

  /** 登录第 1 步：POST v1/verify/check {username}，从响应头 x-rsa-token 取一次性 RSA 公钥 */
  async getLoginPublicKey(username) {
    const res = await this.request('POST', '/ugreen/v1/verify/check', { body: { username }, tokenAuth: false });
    const h = res._headers || {};
    const b64 = h['x-rsa-token'] || h['X-Rsa-Token'];
    if (!b64) throw new Error('verify/check 未返回 x-rsa-token 头');
    return Buffer.from(b64, 'base64').toString('utf8');
  }

  /**
   * 登录第 2 步：RSA 加密密码 -> POST v1/verify/login
   * 成功后写入 this.token / this.publicKey
   */
  async login(username, password, { keepalive = true, otp = '', isSimple = false, loginEvent } = {}) {
    const pem = await this.getLoginPublicKey(username);
    const body = {
      username,
      password: rsaEncrypt(pem, password),
      keepalive: Boolean(keepalive),
      is_simple: Boolean(isSimple),
    };
    if (otp) body.otp = otp;
    if (loginEvent) body.login_event = loginEvent;

    const json = await this.request('POST', '/ugreen/v1/verify/login', { body, tokenAuth: false });
    this._ok(json, '登录');
    const data = json.data || {};

    this.token = data.token || '';
    this.tokenWhere = data.auth_type || this.tokenWhere || 'url';
    if (data.public_key) this.publicKey = Buffer.from(data.public_key, 'base64').toString('utf8');
    this.user = data;

    return { token: this.token, tokenWhere: this.tokenWhere, publicKey: this.publicKey, user: data, raw: json };
  }

  /** 校验 token：GET v1/verify/is_login */
  async isLogin() {
    const json = await this.request('GET', '/ugreen/v1/verify/is_login');
    return json.code === 200 ? (json.data || {}) : null;
  }

  // ---- 文件 --------------------------------------------------------------

  /** GET v2/filemgr/getRootDirs -> root_type 数组（2 个人空间 / 3 共享空间 / 4 用户空间 / 9 标签） */
  async roots() {
    const json = await this.request('GET', '/ugreen/v2/filemgr/getRootDirs', { query: { client: 'pc', mode: 'selector' } });
    this._ok(json, 'getRootDirs');
    return (json.data && json.data.root_list) || [];
  }

  /**
   * 列目录：target 为绝对路径字符串，或 root_type 数字(2/3/4/9)
   * 返回 { path, total, files[], tree[], raw }
   */
  async ls(target, opts = {}) {
    const body = {
      limit: opts.limit || 1000,
      page: opts.page || 1,
      data_type: opts.dataType === undefined ? 0 : opts.dataType,
      show_dir: opts.showDir === undefined ? true : opts.showDir,
      left_no_page_show: false,
      left_count: 5500,
      version: 1,
    };
    if (opts.sortType !== undefined) body.sort_type = opts.sortType;
    if (opts.reverse !== undefined) body.reverse = opts.reverse;
    if (typeof target === 'number') body.root_type = target;
    else body.path = target;

    const json = await this.request('POST', '/ugreen/v2/filemgr/getDirFileListV2', { body });
    this._ok(json, 'getDirFileListV2');
    const d = json.data || {};
    const w = d.right_files || {};
    return {
      path: typeof target === 'string' ? target : `root_type=${target}`,
      topPath: w.top_path || '',
      total: w.total || 0,
      files: w.files || [],
      tree: (d.left_tree && d.left_tree.files) || [],
      raw: json,
    };
  }

  /** 旧接口：GET v1/filemgr/getDirFileList（部分老固件/页面） */
  async lsV1(query) {
    const json = await this.request('GET', '/ugreen/v1/filemgr/getDirFileList', { query });
    this._ok(json, 'getDirFileList');
    return json.data;
  }

  /** 文件/目录详情：GET v1/filemgr/queryPathInfo?path=... */
  async stat(filePath) {
    const json = await this.request('GET', '/ugreen/v1/filemgr/queryPathInfo', { query: { path: filePath } });
    return json.code === 200 ? json.data : null;
  }

  /**
   * 下载 URL。
   * 方式 A（默认，实测可用）：GET v1/filemgr/downloadFile?paths=<路径>&token=<api_token>&coding=1
   * 方式 B（网页端两步式）：GET v2/filemgr/getDownloadToken -> data.dl_token，再 GET v2/filemgr/downloadFile?token=<dl_token>
   */
  async downloadUrl(remotePath, opts = {}) {
    if (opts.useV2) {
      const t = await this.request('GET', '/ugreen/v2/filemgr/getDownloadToken', {
        query: { paths: remotePath, coding: 1 },
      });
      this._ok(t, 'getDownloadToken');
      const dl = t.data && t.data.dl_token;
      if (!dl) throw new Error('getDownloadToken 未返回 dl_token');
      return `${this.base}/ugreen/v2/filemgr/downloadFile?token=${encodeURIComponent(dl)}`;
    }
    const qs = this._qs({ paths: remotePath, token: this.token, coding: 1 });
    return `${this.base}/ugreen/v1/filemgr/downloadFile?${qs}`;
  }

  /** 下载到本地文件；支持 rangeStart 断点续传 */
  async download(remotePath, destPath, opts = {}) {
    const url = await this.downloadUrl(remotePath, opts);
    const headers = this._baseHeaders();
    if (opts.rangeStart) headers.Range = `bytes=${opts.rangeStart}-`;

    const res = await fetch(url, { headers });
    if (res.status !== 200 && res.status !== 206) {
      const t = await res.text();
      throw new Error(`下载失败 HTTP ${res.status}: ${t.slice(0, 300)}`);
    }
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (ct.includes('application/json')) {
      const t = await res.text();
      throw new Error(`下载被拒绝: ${t.slice(0, 300)}`);
    }

    const dest = path.resolve(destPath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const total = Number(res.headers.get('content-length') || 0);
    let written = 0;
    const out = fs.createWriteStream(dest, opts.rangeStart ? { flags: 'a' } : {});
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      written += value.length;
      if (!out.write(Buffer.from(value))) await new Promise((r) => out.once('drain', r));
      if (opts.onProgress) opts.onProgress(written, total);
    }
    await new Promise((resolve, reject) => out.end((e) => (e ? reject(e) : resolve())));
    return { bytes: written, file: dest, total, headers: Object.fromEntries(res.headers.entries()) };
  }

  // ---- 媒体信息（时长 / 分辨率） ------------------------------------------

  /**
   * 读取视频/图片/音频的媒体信息：GET v1/filemgr/getMediaInfo?path=...
   * 返回（视频示例）：
   * { file_collation:"video", width:1920, height:1080, duration:4, frame_rate:50,
   *   bit_rate:"112 Mbps", video_format:"avc1", hdr:false, resolution_type:3,
   *   shoot_time:1770464582, channel:"", resolution:"72/72", device:"", software:"", ... }
   * - duration 单位为**秒**（整数，实测为向下取整：ffprobe 4.80s → 4）
   * - resolution 字段是 DPI（如 "72/72"），真正的分辨率用 width×height
   */
  async mediaInfo(filePath) {
    const json = await this.request('GET', '/ugreen/v1/filemgr/getMediaInfo', {
      query: { path: filePath },
    });
    this._ok(json, 'getMediaInfo');
    return json.data || {};
  }

  /** 媒体信息 + 便于展示的派生字段 */
  async mediaSummary(filePath) {
    const info = await this.mediaInfo(filePath);
    return {
      ...info,
      isVideo: info.file_collation === 'video' || /^avc|^hev|^h26|^vp/i.test(info.video_format || ''),
      resolutionText: info.width && info.height ? `${info.width}x${info.height}` : '',
      durationText: formatDuration(info.duration),
      fpsText: info.frame_rate ? `${info.frame_rate} fps` : '',
    };
  }

  // ---- 目录 / 文件操作 ----------------------------------------------------

  /** 新建文件夹：POST v2/filemgr/createFolder {path, no_recursive_creation} */
  async mkdir(dirPath, { noRecursive = true } = {}) {
    const json = await this.request('POST', '/ugreen/v2/filemgr/createFolder', {
      body: { path: dirPath, no_recursive_creation: Boolean(noRecursive) },
    });
    this._ok(json, 'createFolder');
    return json.data;
  }

  /** 重命名文件或文件夹：POST v2/filemgr/rename {path, new_name} */
  async rename(targetPath, newName) {
    if (!newName || /[\\/]/.test(newName)) throw new Error('new_name 不能为空且不能包含 / 或 \\');
    const json = await this.request('POST', '/ugreen/v2/filemgr/rename', {
      body: { path: targetPath, new_name: newName },
    });
    this._ok(json, 'rename');
    return json.data;
  }

  /**
   * 复制/移动：POST v2/filemgr/cpOrMvPath {dst, src, action_type, type, intranet_share_id}
   * @param {boolean} isMove true=移动, false=复制
   * @param {string|string[]} src 源路径（单个或数组）
   * @param {string} dst 目标目录路径
   * @param {number} actionType 冲突策略 0=跳过 1=覆盖 3=保留两者 4=每次询问
   */
  async _cpOrMv(isMove, src, dst, { actionType = 0, shareId = 0 } = {}) {
    const body = {
      dst,
      src: Array.isArray(src) ? src : [src],
      action_type: actionType,
      type: Boolean(isMove),
      intranet_share_id: shareId || 0,
    };
    const json = await this.request('POST', '/ugreen/v2/filemgr/cpOrMvPath', { body });
    this._ok(json, isMove ? 'move' : 'copy');
    return json.data; // { path:"", task_id:"..." } 异步任务
  }

  /** 移动文件/文件夹 */
  mv(src, dst, opts = {}) { return this._cpOrMv(true, src, dst, opts); }

  /** 复制文件/文件夹 */
  cp(src, dst, opts = {}) { return this._cpOrMv(false, src, dst, opts); }

  /**
   * 删除：POST v2/filemgr/delPaths {paths, forever}
   * forever=false 进回收站；true 直接彻底删除。
   */
  async rm(paths, { forever = false } = {}) {
    const json = await this.request('POST', '/ugreen/v2/filemgr/delPaths', {
      body: { paths: Array.isArray(paths) ? paths : [paths], forever: Boolean(forever) },
    });
    this._ok(json, 'delPaths');
    return json.data;
  }

  /** 清空回收站：POST v1/filemgr/emptyRecycles */
  async emptyRecycle(paths = []) {
    const json = await this.request('POST', '/ugreen/v1/filemgr/emptyRecycles', {
      body: { paths: Array.isArray(paths) ? paths : [paths] },
    });
    this._ok(json, 'emptyRecycles');
    return json.data;
  }

  /** 从回收站恢复：POST v1/filemgr/restoreFiles */
  async restore(paths) {
    const json = await this.request('POST', '/ugreen/v1/filemgr/restoreFiles', {
      body: { paths: Array.isArray(paths) ? paths : [paths] },
    });
    this._ok(json, 'restoreFiles');
    return json.data;
  }
}

// ------------------------------------------------------------ session I/O ---

function loadSession() {
  try { return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch (e) { return null; }
}
function saveSession(s) {
  fs.writeFileSync(SESSION_FILE, JSON.stringify(s, null, 2));
  try { fs.chmodSync(SESSION_FILE, 0o600); } catch (e) { /* ignore */ }
}

function ask(question, { silent = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (silent) {
      const orig = rl._writeToOutput.bind(rl);
      rl._writeToOutput = function (str) {
        if (str.includes(question)) orig(str);
        else rl.output.write('*');
      };
    }
    rl.question(question, (a) => { if (silent) rl.output.write('\n'); rl.close(); resolve(a); });
  });
}

// ------------------------------------------------------------------- CLI ----

const USAGE = `绿联 NAS 接口命令行（还原版）

用法:
  node ugreen.js login  --base <NAS地址> [--user 用户名] [--password 密码]
  node ugreen.js status
  node ugreen.js roots
  node ugreen.js ls     <路径|root_type> [--limit 100] [--page 1]
  node ugreen.js url    <远程路径> [--v2]
  node ugreen.js get    <远程路径> <本地路径> [--v2]

  node ugreen.js mkdir  <新目录路径>
  node ugreen.js rename <原路径> <新名称>
  node ugreen.js mv     <源路径[,源路径2...]> <目标目录> [--action 0|1|3]
  node ugreen.js cp     <源路径[,源路径2...]> <目标目录> [--action 0|1|3]
  node ugreen.js rm     <路径[,路径2...]> [--forever] --yes
  node ugreen.js media  <远端文件路径> [--json]          # 时长/分辨率/帧率/编码

公共参数:
  --base   例: http://192.168.1.10:9999  或 https://xxx.cn18.ug.link（不传则用 .session.json 里的）
  --token  直接指定会话 token（跳过登录）
  --pub    指定 enPublicKey 的 PEM 文件（HTTP 应用层加密需要）
  --no-enc 关闭应用层加密

文件操作参数:
  --action 冲突策略: 0=跳过(默认) 1=覆盖 3=保留两者
  --forever 删除时跳过回收站（彻底删除）
  --yes     删除必须显式确认

示例:
  node ugreen.js login --base https://your-device.cn18.ug.link --user admin
  node ugreen.js roots
  node ugreen.js ls 2
  node ugreen.js ls /volume1/docker
  node ugreen.js get /volume1/docker/a.txt ./a.txt
  node ugreen.js mkdir /home/user/临时目录
  node ugreen.js rename /home/user/临时目录 新目录名
  node ugreen.js mv /home/user/a.txt /volume1/docker
  node ugreen.js rm /home/user/新目录名 --yes
  node ugreen.js media "/home/user/Videos/sample.mp4"
  node ugreen.js media "/volume1/media/a.mkv" --json
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--no-enc') { out.noEnc = true; continue; }
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      out[key] = val;
    } else out._.push(a);
  }
  return out;
}

function makeClient(args, { needToken = true } = {}) {
  const saved = loadSession() || {};
  const base = args.base || process.env.NAS_BASE || saved.base;
  if (!base) throw new Error('缺少 --base（NAS 地址）');
  const publicKey = args.pub ? fs.readFileSync(args.pub, 'utf8') : (saved.publicKey || '');
  const client = new UgreenNasClient({
    base,
    token: args.token || process.env.NAS_TOKEN || saved.token || '',
    publicKey,
    tokenWhere: saved.tokenWhere || 'header',
    lang: args.lang || saved.lang || 'zh-CN',
    clientVersion: args['client-version'] || saved.clientVersion || DEFAULT_CLIENT_VERSION,
    clientId: args['client-id'] || saved.clientId || 'ugreen-nas-api',
    encrypt: args.noEnc ? false : undefined,
    user: saved.user || null,
  });
  if (needToken && !client.token) throw new Error('未登录：先执行 login，或用 --token 指定 token');
  return client;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || 'help';
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') { console.log(USAGE); return; }

  if (cmd === 'login') {
    const client = makeClient(args, { needToken: false });
    const user = args.user || (await ask('用户名: '));
    const password = args.password || (await ask('密码: ', { silent: true }));
    const r = await client.login(user, password, { keepalive: true });
    saveSession({
      base: client.base,
      token: r.token,
      tokenWhere: r.tokenWhere,
      publicKey: r.publicKey,
      user: { uid: r.user.uid, username: r.user.username, role: r.user.role, nas_name: r.user.nas_name, model: r.user.model },
      lang: client.lang,
      clientVersion: client.clientVersion,
      clientId: client.clientId,
      savedAt: new Date().toISOString(),
    });
    console.log('登录成功');
    console.log('  token       :', r.token);
    console.log('  token_where :', r.tokenWhere);
    console.log('  用户        :', r.user.username, `(uid=${r.user.uid}, role=${r.user.role})`);
    console.log('  NAS         :', r.user.nas_name || '', r.user.model || '');
    console.log('  会话已保存  :', SESSION_FILE);
    return;
  }

  const client = makeClient(args);

  if (cmd === 'status') {
    const data = await client.isLogin();
    console.log(data ? '登录态有效' : '登录态无效/已过期');
    if (data) console.log(JSON.stringify(data, null, 2));
    return;
  }

  if (cmd === 'roots') {
    const roots = await client.roots();
    const names = { 2: '个人空间 personal', 3: '共享空间 common', 4: '用户空间 users', 9: '标签 tags' };
    console.log('root_type:', roots.join(', '));
    for (const r of roots) console.log(`  ${r}  ${names[r] || ''}`);
    return;
  }

  if (cmd === 'ls') {
    const target = args._[1];
    if (!target) throw new Error('用法: ls <路径|root_type>');
    const t = /^\d+$/.test(target) ? Number(target) : target;
    const r = await client.ls(t, { limit: Number(args.limit || 1000), page: Number(args.page || 1) });
    console.log(`路径: ${r.path}  共 ${r.total} 项`);
    for (const f of r.files) {
      const isDir = f.file_type === 1;
      const size = isDir ? '' : String(f.size);
      console.log(`${isDir ? 'd' : '-'} ${size.padStart(12)}  ${new Date((f.mtime || 0) * 1000).toLocaleString()}  ${f.name}`);
      if (args.verbose) console.log('      ', f.path);
    }
    return;
  }

  if (cmd === 'url') {
    const remote = args._[1];
    if (!remote) throw new Error('用法: url <远程路径>');
    console.log(await client.downloadUrl(remote, { useV2: Boolean(args.v2) }));
    return;
  }

  if (cmd === 'get') {
    const remote = args._[1];
    const dest = args._[2] || path.basename(remote || '');
    if (!remote) throw new Error('用法: get <远程路径> <本地路径>');
    let last = 0;
    const r = await client.download(remote, dest, {
      useV2: Boolean(args.v2),
      onProgress: (n, total) => {
        const now = Date.now();
        if (now - last > 500) {
          last = now;
          process.stderr.write(`\r已下载 ${(n / 1048576).toFixed(2)} MiB${total ? ' / ' + (total / 1048576).toFixed(2) + ' MiB' : ''}`);
        }
      },
    });
    process.stderr.write('\n');
    console.log(`完成: ${r.file} (${r.bytes} 字节)`);
    return;
  }

  if (cmd === 'media') {
    const p = args._[1];
    if (!p) throw new Error('用法: media <远端文件路径> [--json]');
    const m = await client.mediaSummary(p);
    if (args.json) { console.log(JSON.stringify(m, null, 2)); return; }
    if (!m.width && !m.height && !m.duration) {
      console.log('未取到媒体信息（可能不是音视频/图片，或 NAS 未生成索引）');
      return;
    }
    const pad = (k, v) => console.log(`  ${k.padEnd(10, ' ')}: ${v}`);
    console.log(p);
    pad('类型', m.file_collation || '-');
    pad('分辨率', m.resolutionText ? `${m.resolutionText}${m.resolution_type ? '  (档位 ' + m.resolution_type + ')' : ''}` : '-');
    pad('时长', m.durationText ? `${m.durationText}  (${m.duration} 秒)` : '-');
    pad('帧率', m.fpsText || '-');
    pad('编码', m.video_format || '-');
    pad('码率', m.bit_rate || '-');
    pad('HDR', m.hdr ? '是' : '否');
    pad('拍摄时间', m.shoot_time ? new Date(m.shoot_time * 1000).toLocaleString() : '-');
    if (args.json) console.log(JSON.stringify(m, null, 2));
    return;
  }

  if (cmd === 'mkdir') {
    const p = args._[1];
    if (!p) throw new Error('用法: mkdir <新目录路径>');
    const d = await client.mkdir(p, { noRecursive: !args.recursive });
    console.log('已创建:', d && d.path ? d.path : p);
    return;
  }

  if (cmd === 'rename') {
    const p = args._[1], name = args._[2];
    if (!p || !name) throw new Error('用法: rename <原路径> <新名称>');
    const d = await client.rename(p, name);
    console.log('已重命名:', d && d.path ? d.path : `${p} -> ${name}`);
    return;
  }

  if (cmd === 'mv' || cmd === 'cp') {
    const src = args._[1], dst = args._[2];
    if (!src || !dst) throw new Error(`用法: ${cmd} <源路径[,源2...]> <目标目录>`);
    const list = String(src).split(',').map((s) => s.trim()).filter(Boolean);
    const d = cmd === 'mv'
      ? await client.mv(list, dst, { actionType: Number(args.action || 0) })
      : await client.cp(list, dst, { actionType: Number(args.action || 0) });
    console.log(cmd === 'mv' ? '已提交移动任务' : '已提交复制任务', d && d.task_id ? `task_id=${d.task_id}` : JSON.stringify(d));
    return;
  }

  if (cmd === 'rm') {
    const p = args._[1];
    if (!p) throw new Error('用法: rm <路径[,路径2...]> [--forever] --yes');
    if (!args.yes) throw new Error('删除操作需显式加 --yes 确认（--forever 时彻底删除，不进回收站）');
    const list = String(p).split(',').map((s) => s.trim()).filter(Boolean);
    const d = await client.rm(list, { forever: Boolean(args.forever) });
    console.log('已删除:', list.join(', '), `(${args.forever ? '彻底删除' : '移入回收站'})`, d && d.result !== undefined ? `result=${JSON.stringify(d.result)}` : '');
    return;
  }

  console.log(USAGE);
}

module.exports = { UgreenNasClient, rsaEncrypt, aesGcmEncrypt, aesGcmDecrypt, pemToPublicKey };

if (require.main === module) {
  main().catch((e) => {
    console.error('错误:', e.message);
    if (e.response && e.response.debug) console.error('debug:', e.response.debug);
    process.exit(1);
  });
}
