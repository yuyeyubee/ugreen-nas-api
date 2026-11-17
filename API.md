# 绿联 NAS（UGOS Pro）接口还原文档

> 目标客户端：`/Applications/UGREEN NAS.app`（Electron），分析版本 1.13.0.76379，实机验证版本 1.21.0.80330
> 目标设备：绿联 DXP4800（UGOS `1.21.00190`；设备名、SN、账号均已脱敏）
> 验证方式：通过客户端自身的 ugAgent P2P 隧道 `127.0.0.1:9444` 直接调用 NAS 真实接口（下文每节标注“已验证”）

---

## 1. 结论速览

| 能力 | 方法与路径 | 关键参数 |
|---|---|---|
| 取登录公钥 | `POST /ugreen/v1/verify/check` | `{"username":"..."}` → 响应头 `x-rsa-token`（Base64 的 PEM） |
| **登录拿登录态** | `POST /ugreen/v1/verify/login` | `{username, password(RSA密文), keepalive, is_simple}` → `data.token`、`data.auth_type` |
| 校验登录态 | `GET /ugreen/v1/verify/is_login` | 头 `X-Ugreen-Token: <token>` |
| 登出 | `PUT /ugreen/v1/verify/logout` | 头 `X-Ugreen-Token` |
| 根目录 | `GET /ugreen/v2/filemgr/getRootDirs?client=pc&mode=selector` | → `data.root_list=[2,3,4,9]` |
| **列文件夹文件** | `POST /ugreen/v2/filemgr/getDirFileListV2` | `{path}` 或 `{root_type}` + `page/limit` |
| 文件详情 | `GET /ugreen/v1/filemgr/queryPathInfo?path=...` | |
| **下载文件（直连）** | `GET /ugreen/v1/filemgr/downloadFile?paths=<路径>&token=<token>&coding=1` | 支持 `Range` → `206` |
| 下载（两步式） | `GET /ugreen/v2/filemgr/getDownloadToken?paths=...` → `data.dl_url` | 再 GET `dl_url`（token 在 query，无需鉴权头） |
| 新建文件夹 | `POST /ugreen/v2/filemgr/createFolder` | `{path, no_recursive_creation}` |
| **重命名（文件/文件夹）** | `POST /ugreen/v2/filemgr/rename` | `{path, new_name}` → `data.path` |
| **移动 / 复制（文件/文件夹）** | `POST /ugreen/v2/filemgr/cpOrMvPath` | `{dst, src[], type, action_type}` → `task_id` |
| **删除（文件/文件夹）** | `POST /ugreen/v2/filemgr/delPaths` | `{paths[], forever}` |
| **视频时长/分辨率** | `GET /ugreen/v1/filemgr/getMediaInfo?path=...` | → `width,height,duration,frame_rate,video_format,bit_rate,hdr` |

三种可用的 Base URL：

1. **局域网**：`http://<NAS内网IP>:9999`（HTTP 明文，需要应用层加密，见 §4）
2. **远程**：`https://<设备名>.cn<xx>.ug.link`（HTTPS，不需要应用层加密；需 NAS 在线且已连上绿联云）
3. **客户端本地隧道**（本次验证所用）：`http://127.0.0.1:<port>`，由客户端 ugAgent P2P 服务建立，端口随机（日志/`NASBaseUrlInfo` 里可见）

---

## 1.1 本次实测结果（真实设备）

| 步骤 | 请求 | 结果 |
|---|---|---|
| 取登录公钥 | `POST /ugreen/v1/verify/check {"username":"user"}` | ✅ 200 + `X-Rsa-Token`（459 字符 PEM） |
| 登录 | `POST /ugreen/v1/verify/login`（RSA 密码） | ✅ 200，32 位 token，`auth_type=header`，uid=1000 admin |
| 会话校验 | `GET /ugreen/v1/verify/is_login` | ✅ 200 |
| 根目录 | `GET /ugreen/v2/filemgr/getRootDirs` | ✅ `[2,3,4,9]` |
| 列目录 | `POST /ugreen/v2/filemgr/getDirFileListV2` | ✅ `/home/user/Videos` 共 158 项 |
| 下载 | `GET /ugreen/v1/filemgr/downloadFile?...` | ✅ 2134 字节 XML，`Content-Disposition` 正常 |
| 分片下载 | 同上 + `Range: bytes=0-1048575` | ✅ 206 + `Content-Range: bytes 0-1048575/67254625` |
| 两步式下载 | `getDownloadToken` → `downloadFile?token=` | ✅ 返回 dl_token/dl_url 并成功取到文件 |

设备：DXP4800 / UGOS `1.21.0.0190`（设备名、SN 已脱敏）；
Base URL 为客户端 ugAgent 建立的本地 P2P 隧道 `http://127.0.0.1:9444`（HTTP → 全程走 §4.4 加密）。

---

## 2. 客户端架构（逆向得到的关键事实）

| 文件 | 说明 |
|---|---|
| `Contents/Resources/app.asar` | 主进程：`background.js` → `require('bytenode'); require('./main-c.jsc')`，主逻辑是 **V8 字节码**（`main-c.jsc`），无源码 |
| `Contents/render/renderPro.ugos` | 渲染层整包被加密（高熵二进制），运行时解密后交给 webview 执行 → 只能运行时 dump |
| `Contents/Resources/transportCore/transport.darwin-arm64.node` | 原生传输模块（P2P 下载 / 隧道） |
| `Contents/Resources/public/darwin/ugAgent/UgAgent` | 绿联 P2P/中继代理，监听 `127.0.0.1:<port>`，把 HTTP 透传到 NAS |
| `node_modules/{bytenode,adm-zip,mime}` | 仅此三个依赖 |

界面层（渲染层）是完整的 Vue 应用，运行在 `http://pro.ugos.pc/`，其 bundle 通过 CDP 从内存 dump 后得到全部 API 定义（下文接口均来自这些代码 + 实机验证）。

**发现过程**：
- 应用内日志 `~/Library/UGREEN_Nas_Pro/log/<版本>/UgreenNasPro_darwin_<build>.log` 直接记录 `[nasReq]` 的 method@path，可快速枚举接口清单。
- 渲染层配置 `localStorage.proConfig` 里保存了 `accessInfo{api_token,token_where,static_token}`、`enPublicKey`（NAS RSA 公钥）、`NASBaseUrlInfo`（当前 Base URL / 本地隧道端口）。
- 启动 Electron 时环境变量必须去掉 `ELECTRON_RUN_AS_NODE`，否则 Electron 会退化成 Node 解释器，进程秒退（本次踩坑点）。

---

## 3. 通用约定

### 3.1 请求头（所有 NAS 请求）

```
UG-Agent: PC/WEB
Client-Id: <设备指纹>            # 客户端实际是 "<uuid>-PC-darwin"，如 00000000-0000-0000-0000-PC-darwin
Client-Version: 1.21.0.80330     # 客户端版本号
X-Specify-Language: zh-CN
User-Feature: Mac                # 桌面端专有；Windows 传 Windows
Content-Type: application/json   # 有 body 时
X-Ugreen-Token: <token>          # 登录后；当 auth_type=url 时改为 query 参数 token=
```

登录接口额外带：`UG-Client-Id: <客户端指纹 md5>`（例如 `a1b2c3d4e5f60718293a4b5c6d7e8f90`）。

### 3.2 响应结构

```json
{ "code": 200, "msg": "success", "data": { }, "time": 0.0033 }
```

| code | 含义 |
|---|---|
| 200 | 成功 |
| 1003 | 账号或密码错误（`debug: Authentication failure`） |
| 1010 | token 格式非法 / 缺失（未按 §4 加密时常见） |
| 1024 | 登录已过期，需要重新登录 |
| 1118 | 需要二次验证（OTP） |
| 1302 | 无权限 |
| 407 | 设备连接超时（远程 ug.link 中继可达但 NAS 未上线） |
| 9404 | 应用路由不存在（路径/方法不对） |

响应还会带若干头并被客户端合并进 `data`：`x-rsa-token`（一次性登录公钥）、`x-init-token`、`x-id-token`、`x-init-key`。

---

## 4. 登录与鉴权（★核心）

### 4.1 取一次性 RSA 公钥

```http
POST /ugreen/v1/verify/check
Content-Type: application/json

{"username":"user"}
```

响应（**已验证**）：

```
HTTP/1.1 200 OK
X-Rsa-Token: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0t...

{"code":200,"msg":"success","data":{}}
```

`X-Rsa-Token` = Base64 解码后得到 PEM：

```
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END RSA PUBLIC KEY-----
```

### 4.2 登录

密码用上一步公钥做 **RSA/PKCS#1 v1.5** 加密，Base64 后放进 `password`：

```http
POST /ugreen/v1/verify/login
Content-Type: application/json
UG-Client-Id: a1b2c3d4e5f60718293a4b5c6d7e8f90

{
  "username": "user",
  "password": "<Base64(RSA_PKCS1(password))>",
  "keepalive": true,
  "is_simple": false
}
```

可选字段：`otp`（二次验证码，配合 `POST v1/verify/code/login`）、`login_event`。

成功响应（**2026-11-14 用真实账号实测通过**，`data` 完整字段）：

```json
{
  "code": 200,
  "msg": "success",
  "data": {
    "token": "<32 位会话 token>",
    "token_id": "...",
    "auth_type": "header",          // 或 "url"
    "static_token": "...",
    "third_token": "...",
    "is_ugk": true,
    "public_key": "<Base64(PEM)>",  // enPublicKey，§4.4 应用层加密用
    "uid": 1000,
    "username": "user",
    "role": "admin",
    "model": "DXP4800",
    "model_series": "...",
    "product_series": "...",
    "nas_name": "MyNAS",
    "sn": "SN0000000000000000",
    "system_version": "1.21.0.0190",
    "version_number": 12100190,
    "need_bind": false,
    "deny_change_pwd": false,
    "enable_change_pwd": true,
    "enable_otp": false,
    "otp_status": 0,
    "password_expire": 0,
    "is_simple": false,
    "is_domain": false,
    "is_bootstrap_completed": true,
    "is_arm": true,
    "is_cloud": false,
    "is_exceed": false,
    "http_port": 9999,
    "https_port": 9443,
    "ipv4": ["..."],
    "ipv6": [],
    "network_info": { },
    "ddns": "...",
    "uglink": "...",
    "uglink_id": "MyNAS",
    "support_biometric": true,
    "match_rule": "...",
    "mobile_guide": "...",
    "urgent_email": "...",
    "color": "gray",
    "edev": false
  }
}
```

实测得到的完整字段名清单（便于按需取用）：

```
auth_type, color, ddns, deny_change_pwd, edev, enable_change_pwd, enable_otp, http_port,
https_port, ipv4, ipv6, is_arm, is_bootstrap_completed, is_cloud, is_domain, is_exceed,
is_simple, is_ugk, match_rule, mobile_guide, model, model_series, nas_name, need_bind,
network_info, otp_status, password_expire, product_series, public_key, role, sn,
static_token, support_biometric, system_version, third_token, token, token_id, uglink,
uglink_id, uid, urgent_email, username, version_number
```

**已验证**：
- 真实密码登录 → `code 200`，拿到 32 位 `token`、`auth_type=header`、`public_key`，角色为 `admin`，系统版本 `1.21.0.0190`。
- 错误密码 → `{"code":1003,"msg":"账号或密码错误，请重新登录","debug":"Authentication failure"}`（说明请求结构、RSA 加密、必需头都正确）。

### 4.3 会话 token 的使用

- 后续所有需要鉴权的请求：`X-Ugreen-Token: <token>`（`auth_type=header`，本机实测为 header）
- 若 `auth_type=url`：改为 query 参数 `?token=<token>`
- 校验：`GET /ugreen/v1/verify/is_login` → `{"code":200,"data":{"wallpaper":"...","avatar":"...","need_bind":false}}`（**已验证**）
- 登出：`PUT /ugreen/v1/verify/logout`
- 刷新：`PUT /ugreen/v1/verify/refresh`

### 4.4 HTTP 下的应用层加密（**仅在 Base URL 为 http 时启用**）

官方客户端逻辑：`baseURL.startsWith('https') ? 不加密 : 加密`。所以走 `https://xxx.ug.link` 时可以完全跳过本节；走 `http://IP:9999` 或本地 P2P 隧道 `http://127.0.0.1:port` 时必须实现，否则服务端返回 `1010 token format is invalid`。

每次请求生成一个随机会话密钥 `aesKey = uuidv4 去掉 '-'`（32 个 ASCII 字符 → AES-256 密钥）：

| 位置 | 内容 |
|---|---|
| 头 `X-Ugreen-Security-Key` | `md5(hex, token)` |
| 头 `X-Ugreen-Token` | `Base64(RSA_PKCS1(enPublicKey, token))` |
| 头 `X-Ugreen-Security-Code` | `Base64(RSA_PKCS1(enPublicKey, aesKey))` |
| query | 原 query 串 → `encrypt_query=<Base64(iv|AES-256-GCM(明文, aesKey)|tag)>` |
| body | `{"encrypt_req_body":"<同上格式>","req_body_sha256":"<sha256(原始JSON字符串)>"}` |

- `enPublicKey` 来自登录响应 `data.public_key`（Base64 的 PEM），客户端也缓存到 `localStorage.enPublicKey`；它与 §4.1 的一次性 `x-rsa-token` **不是同一把钥匙**。
- AES-GCM 细节（前端类名 `Aes128gcm`，实现其实是 AES-256-GCM）：
  - `key = Buffer.from(aesKey, 'utf8')`（32 字节）
  - `iv = 12 字节随机`，`tag = 16 字节`（GCM 默认）
  - 输出 = `Base64(iv ‖ ciphertext ‖ tag)`
- 响应若为 `{"encrypt_resp_body":"<base64>"}`，用同一个 `aesKey` 解出 JSON 再解析。
- 加密只作用于 JSON 请求；`multipart/form-data`、`application/x-www-form-urlencoded` 及下载类白名单接口不加密（下载 token 走 query 明文）。

**已验证**：按上述算法向 `http://127.0.0.1:9444` 发送 `is_login` / `getRootDirs` / `getDirFileListV2`，均返回 `code 200` 且响应体需要 GCM 解密，解密后为正常 JSON。

---

## 5. 文件浏览与下载

### 5.1 根目录列表

```http
GET /ugreen/v2/filemgr/getRootDirs?client=pc&mode=selector
X-Ugreen-Token: <token>
```

响应（**已验证**）：

```json
{"code":200,"msg":"success","data":{"root_list":[2,3,4,9]}}
```

| root_type | 含义 | 实测 top_path |
|---|---|---|
| 2 | 个人空间 personal | `/home/<用户名>` |
| 3 | 共享空间 common（存储池根） | `/volume1` |
| 4 | 用户空间 users（所有用户目录） | `/home/<用户名>` |
| 9 | 标签 tags（返回 tag 列表，不是文件） | — |

### 5.2 列目录 / 找文件夹里的文件

```http
POST /ugreen/v2/filemgr/getDirFileListV2
X-Ugreen-Token: <token>
Content-Type: application/json

{
  "path": "/home/user/Videos",   // 或 "root_type": 2
  "page": 1,
  "limit": 1000,
  "data_type": 0,        // 0=all 1=tree 2=list
  "show_dir": true,
  "left_no_page_show": false,
  "left_count": 5500,
  "version": 1
}
```

可选：`sort_type`、`reverse`、`permission`、`file_collation`、`file_exts`、`is_shield_recycle`、`filter_items`、`as_dir`、`tag_filter`。

响应（**已验证**）：

```json
{"code":200,"msg":"success","data":{
  "left_tree":{"status":0,"total":2,"top_path":"/home/user","permission_mask":7,"files":[...]},
  "right_files":{"status":0,"total":2,"top_path":"/home/user","permission_mask":7,"files":[...]}
}}
```

文件对象主要字段：

| 字段 | 说明 |
|---|---|
| `path` | 绝对路径（后续下载/操作都用它） |
| `name` | 文件名 |
| `file_type` | **0=文件，1=目录** |
| `size` | 字节数（目录为 0） |
| `takes_space` | 实际占用（含块对齐） |
| `ext` | 扩展名 |
| `ctime/mtime/atime` | 秒级 Unix 时间戳 |
| `permission_mask` | 权限位（7=读写） |
| `top_path` | 所在存储根 |
| `intranet_share_id` | 共享场景下的分享 ID（下载时可作为额外 query） |

旧接口（部分页面仍在用）：`GET /ugreen/v1/filemgr/getDirFileList?path=/xxx&...`

其他目录相关接口：
- `POST /ugreen/v2/filemgr/getAllLevelsPath` `{path,count,sort_type,reverse}` → 面包屑/多级路径
- `POST /ugreen/v1/filemgr/pathExist` `{path}`
- `POST /ugreen/v2/filemgr/createFolder` `{path,no_recursive_creation}`
- `POST /ugreen/v2/filemgr/rename`
- `POST /ugreen/v2/filemgr/delPaths` `{paths:[...],forever:false}`
- `GET /ugreen/v1/filemgr/getVolumes`、`getShareList`、`getHomeFolderSet`、`remoteMountList`
- `GET /ugreen/v1/filemgr/thumbnail?path=...`、`GET /ugreen/v1/filemgr/mediaPlayer?path=...`

### 5.3 下载文件

本项目实测**可用且最简单**的方式（= 桌面客户端任务中心实际使用的 URL 形式）：

```http
GET /ugreen/v1/filemgr/downloadFile?paths=<URL编码的绝对路径>&token=<api_token>&coding=1
UG-Agent: PC/WEB
User-Feature: Mac
```

响应（**已验证**）：

```
HTTP/1.1 200 OK
Content-Type: text/xml; charset=utf-8
Content-Length: 2132
Content-Disposition: attachment; filename="sample.xml"; filename*=UTF-8''sample.xml
Accept-Ranges: bytes
```

- 断点续传：加 `Range: bytes=<start>-` → `206 Partial Content` + `Content-Range: bytes 0-1048575/67254625`（**已验证**）
- `token` 直接放在 query 明文里即可（即使 Base URL 是 http 也一样），无需 `X-Ugreen-Token` 头
- `coding=1` 让服务端按 UTF-8 编码 `Content-Disposition`

两步式（网页端逻辑，**已验证**）：

```http
GET /ugreen/v2/filemgr/getDownloadToken?paths=<URL编码路径>&coding=1
→ {"code":200,"data":{"dl_token":"01A1D5c3...","dl_url":"/ugreen/v2/filemgr/downloadFile?token=01A1D5c3..."}}

GET /ugreen/v2/filemgr/downloadFile?token=<dl_token>
→ 文件字节流（无需任何鉴权头）
```

其他下载类接口（客户端白名单里可查）：`v1/filemgr/downloadFile`、`v2/filemgr/downloadFile`、`v1/downloadCenter/download/add`（离线下载）、`v1/photo/external/download`、`v1/netDisk/server/file/download` 等。

### 5.4 新建 / 重命名 / 移动 / 复制 / 删除

以下 5 个接口全部在实机验证通过（在个人空间用临时对象做增删改，验证后已清理）。都走 `POST` + JSON body，HTTP base 下同样受 §4.4 的应用层加密保护。

#### 新建文件夹

```http
POST /ugreen/v2/filemgr/createFolder
{"path":"/home/user/__test__","no_recursive_creation":true}
```

响应（已验证）：`{"code":200,"data":{"path":"/home/user/__test__","name":"__test__","file_type":1,...}}`

#### 重命名（文件夹和文件同一个接口）

```http
POST /ugreen/v2/filemgr/rename
{"path":"/home/user/__test__","new_name":"__test2__"}
```

响应（已验证）：`{"code":200,"data":{"path":"/home/user/__test2__","name":"__test2__",...}}`

- 只传新名字，不传完整路径；改名后的完整路径在 `data.path`
- 文件同理：`{"path":"/home/user/a.txt","new_name":"b.txt"}`

#### 移动 / 复制（同一个接口，`type` 区分）

```http
POST /ugreen/v2/filemgr/cpOrMvPath
{
  "dst": "/home/user/sub",        // 目标目录（不是目标文件路径）
  "src": ["/home/user/a.txt"],    // 源路径数组，支持批量
  "action_type": 0,                   // 冲突策略：0=跳过 1=覆盖 3=保留两者 4=每次询问
  "type": true,                       // true=移动，false=复制
  "intranet_share_id": 0              // 分享场景才用，普通目录传 0
}
```

响应（已验证）：`{"code":200,"data":{"path":"","task_id":"3d9deee1-ec67-4f97-bd2b-38666039a20e"}}`

- **异步**：返回 `task_id`，实际搬动由后台任务完成，稍后重新列目录即可看到结果（实测 1~2 秒内完成）
- 移动文件夹与移动文件是同一接口；`src` 放目录路径即可整体搬运
- 复制 = `"type": false`（实测把文件复制到新目录成功，源文件保留）

#### 删除（文件 / 文件夹，支持批量）

```http
POST /ugreen/v2/filemgr/delPaths
{"paths":["/home/user/__test2__"],"forever":true}
```

响应（已验证）：`{"code":200,"data":{"result":""}}`

- `forever: false` → 进回收站（客户端默认行为）；`true` → 彻底删除，不进回收站
- `paths` 可同时传多个文件/目录；删除非空目录会连同内容一起删（已实测）

#### 回收站相关（客户端代码中存在，未逐条实测）

| 用途 | 接口 |
|---|---|
| 恢复 | `POST /ugreen/v1/filemgr/restoreFiles {paths:[...]}`（`paths` 用回收站视图里的 item 路径，不是原路径） |
| 清空回收站 | `POST /ugreen/v1/filemgr/emptyRecycles {...}` |
| 删除「个人文件夹」 | `DELETE /ugreen/v1/filemgr/delHomeFolder?path=<urlencoded>` |
| 删除「共享文件夹」 | `DELETE /ugreen/v2/filemgr/delSharedFolder?path=<urlencoded>` |
| 删除任务查询 | `GET /ugreen/v2/filemgr/getDelTaskInfo?uuid=<task_id>` |

> 说明：回收站列表用的是虚拟路径 `/recycle/...`（直接访问返回 `1301 不允许访问`），需要文件管理页面的特殊上下文，本次未还原其查询接口。

#### 其他常用操作

| 用途 | 接口 |
|---|---|
| 文件/目录详情 | `GET /ugreen/v1/filemgr/queryPathInfo?path=...` |
| 判断路径是否存在 | `POST /ugreen/v1/filemgr/pathExist {path}` |
| 可读/可写检查 | `GET /ugreen/v1/filemgr/queryReadable?path=` / `queryWritable` |
| 操作前权限检测 | `POST /ugreen/v1/filemgr/detectionPermissions {paths,type,to_path}` |
| 目标路径判定 | `GET /ugreen/v1/filemgr/determinePath?path=` |
| 最近访问记录 | `POST /ugreen/v1/filemgr/logOpenOperation` |

### 5.5 视频 / 图片媒体信息（时长、分辨率）

文件管理「详细信息」面板调用这个接口读取媒体元数据（`GET`，`path` 为绝对路径）：

```http
GET /ugreen/v1/filemgr/getMediaInfo?path=/home/user/Videos/sample.mp4
X-Ugreen-Token: <token>
```

实测响应（**已验证**，v1.21.0）：

```json
{
  "code": 200,
  "msg": "success",
  "data": {
    "file_collation": "video",
    "width": 1920,
    "height": 1080,
    "duration": 4,
    "bit_rate": "112 Mbps",
    "channel": "Non-Real Time Metadata",
    "device": "",
    "software": "",
    "color_space": "",
    "resolution": "72/72",
    "shoot_time": 1770464582,
    "frame_rate": 50,
    "video_format": "avc1",
    "hdr": false,
    "iso": "",
    "aperture": "",
    "shutter_speed": "",
    "focal_length": "",
    "resolution_type": 3
  }
}
```

| 字段 | 含义 | 备注 |
|---|---|---|
| `width` / `height` | 视频宽高（像素） | **分辨率 = width×height** |
| `duration` | 时长，**秒（整数）** | 客户端用 `Math.floor` 格式化成 `HH:MM:SS`；实测 ffprobe 4.80s → 4 |
| `frame_rate` | 帧率 | 如 `50`（对应 50/1） |
| `video_format` | 视频编码 | 如 `avc1`、`hvc1`、`hevc` |
| `bit_rate` | 码率（带单位字符串） | 如 `"112 Mbps"` |
| `hdr` | 是否 HDR | boolean |
| `resolution_type` | 清晰度档位 | 4=2k、5=4K、6=8k（1/2/3 为 SD/HD/FHD 类本地化标签），其它为 0 |
| `resolution` | 注意：这里是 **DPI**（`"72/72"`），不是分辨率 | 别误用 |
| `shoot_time` | 拍摄时间（Unix 秒） | 来自容器元数据 |
| `file_collation` | 文件归类 | 视频为 `video`，图片为 `image`，普通文件返回文件路径 |
| `channel` / `device` / `software` / `color_space` | 音频声道 / 拍摄设备 / 软件 / 色彩空间 | 无则为空串 |
| `iso` / `aperture` / `shutter_speed` / `focal_length` | 相机参数（EXIF） | 视频一般空 |

**交叉验证**：同一文件 `sample.mp4` 用 `ffprobe` 比对 —— 1920×1080、h264(avc1)、50/1 fps、码率 112,091,041 bps（≈112 Mbps）、时长 4.80s，与接口返回完全一致（时长按秒取整）。

对非媒体文件（如 `.XML`）接口仍返回 200，但各字段为 0 / 空串，`file_collation` 直接回显路径，可据此判断「无媒体信息」。

配套的流媒体播放地址走 `GET /ugreen/v1/filemgr/mediaPlayer?path=...&mtime=...&ctime=...&file_size=...&intranet_share_id=...`（返回视频流，不是 JSON，本次未展开）。

---

## 6. 用代码复现

同目录 `ugreen.js`（零依赖，Node ≥ 18）：

```bash
# 1) 登录（会交互式输入密码，密码不会进 shell history）
node ugreen.js login --base https://your-device.cn18.ug.link --user user
#    局域网/隧道：
# node ugreen.js login --base http://192.168.1.10:9999 --user user

# 2) 看登录态 / 根目录
node ugreen.js status
node ugreen.js roots

# 3) 列文件夹内容（root_type 2=个人空间 3=共享空间 4=用户空间）
node ugreen.js ls 2
node ugreen.js ls "/home/user/Videos" --limit 20

# 4) 下载
node ugreen.js get "/home/user/Videos/sample.xml" ./sample.xml
node ugreen.js url "/volume1/docker/x.tar" --v2   # 只打印下载链接

# 5) 文件/文件夹操作
node ugreen.js mkdir  "/home/user/临时目录"
node ugreen.js rename "/home/user/临时目录" "新目录名"          # 文件夹改名
node ugreen.js rename "/home/user/临时目录/a.txt" "b.txt"      # 文件改名
node ugreen.js mv     "/home/user/a.txt" "/volume1/docker"     # 移动文件
node ugreen.js mv     "/home/user/旧目录" "/volume1/docker"     # 移动文件夹
node ugreen.js cp     "/home/user/a.txt,/home/user/b.txt" "/volume1/docker"  # 批量复制
node ugreen.js rm     "/home/user/新目录名" --yes               # 删除（进回收站）
node ugreen.js rm     "/home/user/新目录名" --forever --yes      # 彻底删除

# 6) 媒体信息（时长/分辨率/帧率/编码）
node ugreen.js media "/home/user/Videos/sample.mp4"
node ugreen.js media "/volume1/media/a.mkv" --json
```

`mv`/`cp` 的 `--action`：`0=跳过（默认） 1=覆盖 3=保留两者`；`rm` 必须显式加 `--yes`。

作为库使用：

```js
const { UgreenNasClient } = require('./ugreen.js');
const nas = new UgreenNasClient({ base: 'http://192.168.1.10:9999' });
await nas.login('user', 'password');          // 自动保存 token / publicKey
const roots = await nas.roots();                  // [2,3,4,9]
const { files } = await nas.ls('/home/user/Videos');
await nas.download(files[0].path, './download.bin');

await nas.mkdir('/home/user/tmp');                 // 新建目录
await nas.rename('/home/user/tmp', 'tmp2');        // 改名（文件/目录同一接口）
await nas.mv(files[0].path, '/home/user/tmp2');    // 移动（src 可传数组）
await nas.cp(files[0].path, '/home/user/tmp2');    // 复制
await nas.rm(['/home/user/tmp2/a.txt'], { forever: true }); // 删除

const m = await nas.mediaSummary(files[0].path);   // 视频元信息
console.log(m.resolutionText, m.durationText, m.fpsText); // 1920x1080 00:00:04 50 fps
```

会话（token、enPublicKey、Base URL）保存在 `.session.json`（权限 600）。不想用密码登录时，可从客户端 `localStorage.proConfig.accessInfo.api_token` 直接取 token 用 `--token` 传入。

`curl` 版本（HTTPS Base，无需应用层加密）：

```bash
BASE=https://your-device.cn18.ug.link
# 1. 公钥
curl -s -D- -o /dev/null -X POST $BASE/ugreen/v1/verify/check \
  -H 'Content-Type: application/json' -H 'UG-Agent: PC/WEB' \
  -d '{"username":"user"}' | grep -i x-rsa-token
# 2. 登录（password 用上面公钥 RSA 加密）
curl -s -X POST $BASE/ugreen/v1/verify/login -H 'Content-Type: application/json' \
  -H 'UG-Agent: PC/WEB' -H 'UG-Client-Id: <fingerprint>' \
  -d '{"username":"user","password":"<rsa密文>","keepalive":true,"is_simple":false}'
# 3. 列目录
curl -s -X POST $BASE/ugreen/v2/filemgr/getDirFileListV2 -H 'X-Ugreen-Token: <token>' \
  -H 'Content-Type: application/json' -d '{"path":"/home/user","page":1,"limit":100,"data_type":0,"version":1}'
# 4. 下载
curl -L -o out.bin "$BASE/ugreen/v1/filemgr/downloadFile?paths=%2Fhome%2Fuser%2Fa.txt&token=<token>&coding=1"
```

---

## 7. 分析过程与证据链

1. **静态**：解析 `app.asar`（自写 asar header 解析）→ 发现主进程 `main-c.jsc`（bytenode 字节码）、渲染层 `renderPro.ugos`（加密）。
2. **静态（字符串/日志）**：`~/Library/UGREEN_Nas_Pro/log/1.13.0.76379/UgreenNasPro_darwin_76379.log` 含大量 `[nasReq] get@ugreen/v1/...` 行，给出接口前缀与错误码语义。
3. **运行时**：Electron fuse `EnableNodeCliInspectArguments=enabled`、`EnableEmbeddedAsarIntegrityValidation=disabled`，因此可用 `--inspect` 与 `--remote-debugging-port`；从 `http://pro.ugos.pc/` 页面 CDP `Debugger.getScriptSource` dump 出 206 个脚本（14 MB），其中 `main-*.js` 就是完整前端源码（未混淆语义，仅压缩）。
4. **定位代码**：`RequestEncrypt` 类（加密协议）、`LoginApi.userLogin/enCodePassword`（登录）、`getFileList`（列目录）、任务中心 `generateDownloadOptions`（下载 URL 构造）。
   - 文件操作接口来自 NAS 自己托管的 Web 前端：`GET /desktop/`（桌面 SPA）与 `GET /filemgr/`（文件管理微应用，`entry:/filemgr`，bundle `assets/index-*.js`）。NAS 通过 nginx 以明文 JS 提供这些包，直接下载后用 `cpOrMvPath/rename/delPaths/createFolder` 定位到完整实现（比运行时 dump 更省事）：
     - `copyOrMove(e,n,o,r,a){K.post("v2/filemgr/cpOrMvPath",{dst:o,src:n,action_type:r,type:e,intranet_share_id:a})}`；`move()`→`copyOrMove(true,…)`，`copy()`→`copyOrMove(false,…)`
     - `rename(e,n){K.post("v2/filemgr/rename",{path:e.path,new_name:n})}`
     - `delPaths(e,n){K.post("v2/filemgr/delPaths",{paths:e,forever:n||false})}`
     - `action_type` 枚举：`skip=0, cover=1, save=3, askEachTime=4`
     - `getMediaInfo`：`mainPage-*.js` 中 `vt.get("v1/filemgr/getMediaInfo",{params:{path:a}})`，响应经 `Ur()` 归一化，字段即上表
5. **实机验证**：用客户端建立的 P2P 隧道 `http://127.0.0.1:9444` 重放：
   - `verify/check` → 200 + `X-Rsa-Token` ✅
   - `verify/login`（错误密码）→ `code 1003 Authentication failure` ✅
   - `verify/login`（**真实账号实测**）→ `code 200` + 32 位 token + auth_type=header ✅
   - 新 token 的 `is_login` → 200 ✅
   - `getRootDirs` → `[2,3,4,9]` ✅
   - `getDirFileListV2` → 真实目录/文件名/大小 ✅
   - `createFolder` / `rename`(目录+文件) / `cpOrMvPath`(移动+复制) / `delPaths`(文件+非空目录) → 全部 200，操作后用列表接口确认生效，最后彻底删除临时对象 ✅
   - `getMediaInfo` → 视频返回 width/height/duration/frame_rate/bit_rate/video_format/hdr，与 ffprobe 逐项一致 ✅
   - `downloadFile` → 2132 字节 XML，`Content-Disposition` 正确 ✅
   - `Range` 请求 → `206` + 正确 `Content-Range` ✅
   - `getDownloadToken` → `dl_token/dl_url`，再下载成功 ✅
6. **加密协议验证**：`X-Ugreen-Security-Key/Token/Code + encrypt_query + encrypt_req_body` 组合请求全部通过，响应 `encrypt_resp_body` 可解 ✅

### 尚存不确定

- OTP（二次验证）流程：`POST v1/verify/code/login`、`v1/otp/mail/send/code`、`v1/otp/is_new`，未实测。
- 密钥/协议细节以当前固件 `1.21.00190` 实测为准，固件升级后可能变化。
- `UG-Client-Id` 指纹可用任意稳定字符串通过校验（实测用程序自带值亦可），但可能影响 NAS 端“设备管理”列表中的显示。

---

## 8. 备注

- 远程 `*.ug.link` 只有 NAS 在线且与绿联云保持连接才可用；否则中继返回 `407 connect to device timeout`。
- 应用启动时会自动检查更新（本次分析中客户端自行从 1.13.0 升级到了 1.21.0）。
- 该接口为绿联私有协议，仅建议用于个人设备的自动化（备份、同步、批量下载）。请勿用于未授权设备。
