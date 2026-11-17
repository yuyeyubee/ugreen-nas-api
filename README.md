# 绿联 NAS 接口还原（UGOS Pro）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%E2%89%A518-brightgreen.svg)](https://nodejs.org)

从 `UGREEN NAS.app`（Electron 桌面客户端，分析版本 v1.13.0 / 实机验证版本 v1.21.0）逆向，
并在真实设备上逐条验证的私有 HTTP API 文档 + 零依赖 Node.js 客户端。

覆盖的能力：

- 账号密码登录（RSA 加密密码）→ 会话 token
- HTTP 下的应用层加密协议（RSA + AES-256-GCM）
- 根目录 / 目录列表 / 文件详情
- 文件下载（含 `Range` 断点续传、两步式 `dl_token` 下载）
- 新建文件夹、重命名、移动、复制、删除、回收站
- 音视频媒体信息（时长 / 分辨率 / 帧率 / 编码 / 码率 / HDR）

- 完整接口文档：[`API.md`](API.md)（含加密协议细节、错误码、字段表与实测记录）
- 客户端库 / 命令行：[`ugreen.js`](ugreen.js)（零依赖，Node ≥ 18，内置 `fetch`）

## 快速开始

```bash
# 1) 登录（不传 --password 时交互式输入，密码不会进 shell history）
node ugreen.js login --base https://<设备名>.cn18.ug.link --user <用户名>

# 局域网 / 客户端隧道同理
# node ugreen.js login --base http://192.168.1.10:9999 --user <用户名>

# 2) 登录态与根目录
node ugreen.js status
node ugreen.js roots                              # root_type: 2 个人 3 共享 4 用户 9 标签

# 3) 列目录
node ugreen.js ls 2                               # 个人空间
node ugreen.js ls "/home/<用户名>/Videos"          # 指定文件夹
node ugreen.js ls "/home/<用户名>/Videos" --limit 20

# 4) 下载（支持 Range 断点续传）
node ugreen.js get "/home/<用户名>/Videos/sample.mp4" ./sample.mp4
node ugreen.js url "/volume1/docker/x.tar" --v2    # 只打印下载链接

# 5) 文件 / 文件夹操作
node ugreen.js mkdir  "/home/<用户名>/临时目录"
node ugreen.js rename "/home/<用户名>/临时目录" "新名字"        # 文件夹改名
node ugreen.js rename "/home/<用户名>/a.txt" "b.txt"          # 文件改名
node ugreen.js mv     "/home/<用户名>/a.txt" "/volume1/docker"
node ugreen.js cp     "/home/<用户名>/a.txt,/home/<用户名>/b.txt" "/volume1/docker"
node ugreen.js rm     "/home/<用户名>/新名字" --yes             # 进回收站
node ugreen.js rm     "/home/<用户名>/新名字" --forever --yes    # 彻底删除

# 6) 媒体信息（时长 / 分辨率 / 帧率 / 编码）
node ugreen.js media "/home/<用户名>/Videos/sample.mp4"
node ugreen.js media "/volume1/media/a.mkv" --json
```

`mv` / `cp` 的 `--action`：`0=跳过（默认） 1=覆盖 3=保留两者 4=每次询问`；`rm` 必须显式加 `--yes`。

## 作为库使用

```js
const { UgreenNasClient } = require('./ugreen.js');

const nas = new UgreenNasClient({ base: 'http://192.168.1.10:9999' });
const { token, user } = await nas.login('<用户名>', '<密码>');   // 自动拿到 enPublicKey
console.log(token, user.model);

const roots = await nas.roots();                  // [2, 3, 4, 9]
const { files } = await nas.ls('/home/<用户名>');
await nas.download(files[0].path, './download.bin');

await nas.mkdir('/home/<用户名>/tmp');
await nas.rename('/home/<用户名>/tmp', 'tmp2');
await nas.mv(files[0].path, '/home/<用户名>/tmp2');       // src 可传数组，批量
await nas.cp(files[0].path, '/home/<用户名>/tmp2');
await nas.rm(['/home/<用户名>/tmp2/a.txt'], { forever: true });

const m = await nas.mediaSummary(files[0].path);
console.log(m.resolutionText, m.durationText, m.fpsText); // 1920x1080 00:00:04 50 fps
```

## 三种 Base URL

| 场景 | 地址 | 说明 |
|---|---|---|
| 局域网 | `http://<NAS-IP>:9999` | HTTP 明文，需要应用层加密（脚本已自动处理） |
| 远程 | `https://<设备名>.cn<xx>.ug.link` | HTTPS，无需应用层加密；NAS 必须在线 |
| 客户端隧道 | `http://127.0.0.1:<随机端口>` | 由 `UGREEN NAS.app` 的 ugAgent P2P 中继建立，客户端运行时可用 |

官方客户端的逻辑是 `baseURL.startsWith('https') ? 不加密 : 加密`：
走 `https://*.ug.link` 时整节加密协议都可以跳过；走 `http://IP:9999` 或本地隧道时，
不发 `X-Ugreen-Security-*` 系列头会被判为 `1010 token format is invalid`。

## 仓库结构

```
.
├── README.md     本文件
├── API.md        完整接口文档（加密协议、错误码、字段表、实测记录）
├── ugreen.js     零依赖 Node 客户端 + CLI
└── LICENSE       MIT
```

## 凭据与隐私

- 运行时会把 Base URL、token、`enPublicKey` 存到同目录 `.session.json`（权限 600），
  该文件已加入 `.gitignore`，**请勿提交**。
- 不想用密码登录时，可从客户端 `localStorage.proConfig.accessInfo.api_token` 取 token，
  用 `--token` 直接传入。
- 本文档与示例中的账号、设备名、SN、域名、路径均为占位符，与任何真实设备无关。

## 免责声明

- 本项目仅用于**自己拥有或已获授权**的绿联 NAS 设备的个人自动化（备份、同步、批量下载等）。
- 接口为绿联私有协议，未经官方支持；固件升级可能随时改变协议（本文档基于 UGOS `1.21.00190` 验证）。
- 使用本项目产生的一切后果由使用者自行承担。

## License

[MIT](LICENSE)
