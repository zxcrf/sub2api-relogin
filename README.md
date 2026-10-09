# sub2api-relogin

> **English summary.** A self-hosted replacement for the third-party re-login service
> (`session.ameng2027.xyz`) that the [ranxi2001/sub2api](https://github.com/ranxi2001/sub2api) fork's
> *Credential Guard* uses by default. That default service receives each account's **email, password
> and TOTP secret in plain text**. This project implements the same two HTTP endpoints on your own
> server: it logs in to ChatGPT with password + TOTP via a pinned, audited, patched copy of
> [toSub2](https://github.com/poxiao33/toSub2), and returns Codex OAuth tokens to sub2api. The login
> container has no route to the internet except through an allowlisting proxy (OpenAI hosts only).
> By default each login goes out through **the proxy that account is configured with in sub2api**, so
> the OAuth login IP matches the IP the account is later used from.
> Docs below are in Chinese; the steps are plain shell commands.

ranxi 版 sub2api 的「凭证守护」（后台 `/admin/token-guard`）和「2FA 登录导入」在没改过配置时，会把账号的**邮箱、密码、TOTP 密钥明文**发给代码里内置的第三方服务 `https://session.ameng2027.xyz/api/v1/relogin`；开启巡检后，测活接口还会收到账号的 access token。

本项目在你自己的服务器上实现同样的两个接口，替换掉它。密码和 TOTP 只在本机处理。

## 目录

- [工作原理](#工作原理)
- [安全模型](#安全模型)
- [前提条件](#前提条件)
- [部署](#部署)
- [在 sub2api 后台配置](#在-sub2api-后台配置)
- [验证](#验证)
- [失败码与排错](#失败码与排错)
- [配置项](#配置项)
- [接口](#接口)
- [升级 toSub2](#升级-tosub2)
- [开发与测试](#开发与测试)
- [已知限制](#已知限制)

## 工作原理

```
sub2api（凭证守护）
   │  POST http://172.31.250.10:18790/api/v1/relogin   Authorization: Bearer <令牌>
   ▼
relogin 容器 ── server.mjs ── 子进程 toSub2 protocol-login.mjs（密码 + TOTP 登录，Codex OAuth）
   │  内部网络 relogin-int，没有出网路由
   ▼
egress 容器（egress.mjs，主机名白名单）
   │  ① 按邮箱查 sub2api：账号 → 代理（Admin API Key，只读调用）
   │  ② 这次登录的隧道接到该账号的代理上；账号没配代理就从本机出口直连
   ▼
账号代理（http / https / socks5 / socks5h）──► chatgpt.com / auth.openai.com / sentinel.openai.com / challenges.cloudflare.com
```

- **重登**：sub2api 发来邮箱、密码、TOTP 密钥；服务用 toSub2 走一遍官方网页登录 + 2FA + Codex OAuth（PKCE），把拿到的 `access_token / refresh_token / id_token` 等返回给 sub2api，sub2api 写回账号。一次大约 1–2 分钟。
- **出口 IP 和日常使用一致**：OpenAI 可能比对 OAuth 登录时的 IP 和之后实际调用的 IP。sub2api 用某个账号时走的是该账号配置的代理，所以重登默认也走同一个代理：每次登录前，relogin 向 egress 申请一条「路由」，egress 按邮箱在 sub2api 里找到同名账号和它的代理，这次登录的所有隧道都经那个代理出去。
  - 账号没配代理 → 本机出口直连（sub2api 用这个号时也是本机出口）。
  - sub2api 里还没有这个账号（「2FA 登录导入」新号）→ 本机出口直连。导入后再给账号配代理，下次重登就会走代理。
  - 查不到（sub2api 不可达、密钥无效）或同名账号配了不同代理 → **登录直接失败**，不会悄悄退回本机出口。
  - 用的是代理的原始地址：不会像 toSub2 自带逻辑那样轮换代理会话号（`sid-…`），出口和 sub2api 用的是同一个会话。
- **测活**：被动模式，恒回 `active`，不拿账号令牌去请求上游（避免每隔几分钟多出一条官方客户端不会发的请求）。账号在业务请求里已经拿到 401 / 令牌吊销时，sub2api 会跳过测活、直接判定需要重登，所以自动重登仍然生效。

## 安全模型

**防住了：**

- 密码、TOTP 密钥、拿到的令牌不离开本机，只发往 OpenAI。
- relogin 容器没有出网路由，只能经 egress 代理出去；代理只放行 [`egress/allowlist`](egress/allowlist) 里的主机名、只放行 443 端口，其它一律 `403 Filtered`；不带有效路由的隧道一律 `407`。即使第三方代码想绕过代理直连，也连不出去（`check.sh` 会验证这一点）。经账号代理出去时，白名单照样生效（目标主机名在 egress 这一层检查）。
- sub2api 的 Admin API Key 和账号代理的地址、密码**只在 egress 容器里**。跑第三方代码的 relogin 容器只拿到「egress 地址 + 一次性路由号」，路由在登录结束后删除，最长 15 分钟过期。
- toSub2 会下载并执行 OpenAI 的 Sentinel 脚本（遇到 Cloudflare 质询时还会执行 Cloudflare 的脚本），运行它们的 vm 沙箱可以逃逸。补丁 [`patches/0001`](patches/0001-strip-secrets-from-python-worker-env.patch) 让执行这些脚本的进程拿不到密码和 TOTP 环境变量。
- toSub2 固定在审计过的提交，部署时校验压缩包哈希和打补丁后每个文件的哈希，不一致就停止。
- 服务日志只记邮箱的短哈希、走到的阶段和失败码；toSub2 的原始输出（可能含秘密）不落盘、不回传。
- 容器只读根文件系统、去掉全部 capabilities、非 root、限内存和进程数；接口要求 Bearer 令牌。

**没防住（需要你知道）：**

- **sub2api 把「重登凭据」里的密码和 TOTP 密钥以明文 JSON 存在它自己的数据库里**（`settings` 表 `account_token_guard_config_v1`）。这是 sub2api 的行为，本项目改不了；保护好 sub2api 的数据库和备份。
- 你仍然要信任 OpenAI / Cloudflare 下发的脚本不作恶（它们在沙箱里能发起白名单内的请求）。
- **Admin API Key 是 sub2api 的完整管理员权限**（sub2api 没有只读密钥）。egress 只用它读账号列表和代理详情，但密钥本身能做任何管理操作；它只挂进 egress 容器，保护好宿主机上的密钥文件。
- relogin 和 egress 用同一个令牌文件，容器内同一个 uid；逃逸出沙箱的脚本能读到令牌、自己申请路由，但只能得到「某个账号的代理 + 白名单主机」，拿不到 Admin API Key 和代理密码。
- 安全审计只覆盖 toSub2 的登录路径（`protocol-login.mjs` 及其加载的模块），npm / pip 依赖没有做漏洞扫描。

## 前提条件

| 条件 | 说明 |
| --- | --- |
| Linux 主机 | 和 sub2api 在**同一台机器**。脚本用到 `curl`、`patch`、`sha256sum`、`openssl`、`tar` |
| Docker + Compose v2 | `docker compose version` 能用 |
| ranxi 版 sub2api | 后台有「凭证守护」页面（`/admin/token-guard`）。只在 **v2.10.1** 上验证过 |
| sub2api 能访问 relogin 容器 | sub2api 用 **host 网络**或直接装在宿主机上：天然可达。sub2api 在普通 Docker 网络里：部署后执行 `docker network connect sub2api-relogin_relogin-int <sub2api 容器名>` |
| sub2api 管理员 API Key | 「系统设置 → 管理员 API Key」生成。egress 用它按邮箱查账号的代理；不想用就设 `RELOGIN_ACCOUNT_PROXY=off`（登录一律走本机出口） |
| egress 能访问 sub2api | sub2api 在本机：egress 经 `host.docker.internal` 访问，宿主机开了防火墙要放行 `172.31.249.0/24` 到 sub2api 端口（见部署第 5 步）。也可以填 sub2api 的公网地址 |
| 账号开了 TOTP 2FA | 只支持「密码 + TOTP」登录；要邮箱验证码或绑定手机的账号会失败（见[失败码](#失败码与排错)） |

## 部署

以下命令用 root 执行，目录以 `/opt/sub2api-relogin` 为例。

**1. 取代码**

```sh
git clone https://github.com/zxcrf/sub2api-relogin.git /opt/sub2api-relogin
cd /opt/sub2api-relogin
```

**2.（可选）改网段**

默认用两个网段：内部网络 `172.31.250.0/24`（relogin 固定在 `172.31.250.10`）和 egress 出网网络 `172.31.249.0/24`。先确认没被占用：

```sh
ip route | grep -E '172\.31\.(249|250)\.' || echo "未被占用"
```

被占用就 `cp .env.example .env` 改 `RELOGIN_SUBNET`、`RELOGIN_IP`、`RELOGIN_OUT_SUBNET`，后面所有地址跟着换。

**3. 下载并校验 toSub2**

```sh
./fetch-tosub2.sh
```

期望最后一行：`vendor/tosub2 已重建并校验通过`。哈希不符会直接报错退出，不要跳过。

**4. 生成访问令牌**

```sh
install -d -m 0750 -o root -g 10790 /etc/sub2api-relogin
(umask 077; openssl rand -hex 32 > /etc/sub2api-relogin/token)
chown 10790:10790 /etc/sub2api-relogin/token
chmod 0400 /etc/sub2api-relogin/token
```

`10790` 是容器里服务用户的 uid，令牌文件必须归它所有，否则服务读不到、启动即退出。

**5. 让 egress 能查 sub2api 的账号代理**

在 sub2api 后台「系统设置 → 管理员 API Key」生成密钥（已有就用现有的，**重新生成会让旧密钥立即失效**），存成文件：

```sh
(umask 077; cat > /etc/sub2api-relogin/sub2api-admin-key)   # 粘贴密钥，回车，Ctrl-D
chown 10790:10790 /etc/sub2api-relogin/sub2api-admin-key
chmod 0400 /etc/sub2api-relogin/sub2api-admin-key
```

在 `.env` 里写 sub2api 的地址（没有 `.env` 就先 `cp .env.example .env`）：

```sh
# sub2api 在本机、监听 3200 端口（按实际端口改）
SUB2API_BASE_URL=http://host.docker.internal:3200
```

sub2api 只监听 `127.0.0.1` 时，egress 从容器里连不到它，改填它的公网地址（如 `https://sub2api.example.com`）。

宿主机开了防火墙（`ufw status` 显示 `active`）时，放行 egress 的网段到 sub2api 端口，否则第 7 步会报「egress 能用管理密钥查 sub2api 账号」失败：

```sh
ufw allow from 172.31.249.0/24 to any port 3200 proto tcp comment 'sub2api-relogin egress -> sub2api'
```

不想按账号代理登录：`.env` 里写 `RELOGIN_ACCOUNT_PROXY=off`，跳过这一步（不用密钥文件）。

**6. 构建并启动**

```sh
docker compose up -d --build
docker compose ps
```

期望两个容器都是 `Up`：`sub2api-relogin-relogin-1`、`sub2api-relogin-egress-1`。

**7. 自检**

```sh
./check.sh
```

期望每行都是 `PASS`，最后一行 `全部通过`。这一步不登录任何账号。

后面带上邮箱，可以预先看这些账号重登时会走哪个出口（只查 sub2api，不登录）：

```sh
./check.sh a@example.com b@example.com
# INFO  a@example.com → http://203.0.113.7:8080（account_proxy）
# INFO  b@example.com → 本机出口直连（account_has_no_proxy）
```

## 在 sub2api 后台配置

打开 sub2api 后台 **凭证守护**（`/admin/token-guard`），按下表填写后保存：

| 页面字段 | 填写 |
| --- | --- |
| 测活接口 | `http://172.31.250.10:18790/api/v1/relogin/probe` |
| 测活接口额外请求头 | `Authorization: Bearer <令牌>`（**删掉**原有的 `X-Session-Studio-*` 行） |
| 重登接口 | `http://172.31.250.10:18790/api/v1/relogin` |
| 重登接口额外请求头 | `Authorization: Bearer <令牌>`（同样删掉原有行） |
| 重登凭据 | 每行一条：`邮箱----密码----TOTP密钥` |
| 启用凭证守护 / 自动重登 | 按需打开 |
| 测活模型 | 不用管，本服务忽略 |

`<令牌>` 是 `cat /etc/sub2api-relogin/token` 的输出。

> **重要：sub2api 按「账号名 == 重登凭据里的邮箱」把凭据对到账号上。** 账号名不是纯邮箱（比如 `team-a` 或 `team-a (x@y.com)`），自动重登就永远不会触发，巡检日志里一直是 `repaired: 0`。把要守护的账号改名为它的登录邮箱。

配好以后，后台「2FA 登录导入」也会走本服务（它用的是同一个重登接口）。

> 每次在这个页面点保存，都会整体覆盖配置。保存后确认两个接口地址和请求头还在。

## 验证

1. `./check.sh` 全部通过。
2. 在「凭证守护」页对一个账号点 **重登**（或用「2FA 登录导入」导入一个账号），同时看服务日志：

   ```sh
   docker compose logs -f relogin
   ```

   期望先出现 `relogin_start`，接着 `relogin_route`（`mode` 是 `account_proxy` 时 `via` 是所用代理），1–2 分钟后出现 `"event":"relogin_done",...,"ok":true`，后台显示重登成功、账号恢复正常。
3. 看出网记录：`route_created` 是每次登录用的出口，`connect_denied` 是被白名单拦下的目标（正常应该没有），`connect_failed` 是连不上账号代理或目标：

   ```sh
   docker compose logs egress | grep -E 'route_created|route_failed|connect_denied|connect_failed'
   ```

## 失败码与排错

失败时，sub2api 显示 `重登失败: <失败码>`，服务日志里的 `relogin_done` 带 `code`（失败码）和 `stage`（走到了哪一步）。

| 失败码 | 含义 | 怎么办 |
| --- | --- | --- |
| `password_rejected` | 密码错误 | 更新「重登凭据」里的密码 |
| `totp_rejected` | TOTP 验证码被拒 | TOTP 密钥填错或已重置；检查服务器时间是否准确（`timedatectl`） |
| `email_otp_required` | OpenAI 要求邮箱验证码 | 本服务不支持；该账号需要在浏览器里手动登录授权 |
| `phone_required` | OpenAI 要求绑定手机 | 同上 |
| `security_check` | 触发风控 | 稍后重试；频繁出现说明出口 IP 被风控 |
| `timeout` | 10 分钟没完成 | 看 `stage`；多半卡在网络或 Cloudflare 质询 |
| `email_mismatch` | 拿到的令牌不属于这个邮箱 | 不应出现；保留日志并提 issue |
| `relogin_failed` | 其它失败 | 看 `stage` 判断卡在哪一步；账号代理连不上时也是这个，查 egress 日志里的 `connect_failed` |
| `account_proxy_lookup_failed` | egress 查不到账号的代理（`stage` 为 `proxy_lookup`） | egress 日志 `route_failed` 的 `detail` 说明原因：sub2api 不可达（检查 `SUB2API_BASE_URL` 和防火墙）或管理密钥无效 |
| `account_proxy_ambiguous` | 多个账号名都是这个邮箱，且配的代理不同 | 删掉多余账号，或给它们配同一个代理 |
| `account_proxy_unsupported` | 账号的代理协议不是 http / https / socks5 / socks5h | 换代理 |
| `account_proxy_not_configured` | 没设 `SUB2API_BASE_URL` 但 `RELOGIN_ACCOUNT_PROXY` 是 `on` | 按部署第 5 步配好，或设 `RELOGIN_ACCOUNT_PROXY=off` |
| `egress_unreachable` | relogin 连不上 egress | `docker compose ps` 看 egress 是否在跑 |

`stage` 按顺序：`proxy_lookup`（查账号代理）→ `web_login` → `password_page` → `password_accepted` → `mfa_challenge` → `mfa_accepted` → `codex_authorize` → `workspace_select` → `callback` → `token_exchange`。`not_started` 表示 toSub2 没跑起来，先 `docker compose logs relogin` 看报错。

HTTP 层面的错误：

| sub2api 显示 | 原因 |
| --- | --- |
| `重登接口返回 HTTP 401` | 请求头里的令牌和 `/etc/sub2api-relogin/token` 不一致 |
| `重登接口返回 HTTP 409` | 同一邮箱正在用**不同**的密码 / TOTP 登录（凭据相同的并发请求会共用一次登录的结果） |
| `重登接口返回 HTTP 503` | 同时进行的登录已达上限（默认 2），稍后重试 |
| 连接失败 / 超时 | sub2api 访问不到 `172.31.250.10`：见[前提条件](#前提条件)里的网络一行 |
| `缺少该账号的重登凭据` | 账号名不等于重登凭据里的邮箱 |

## 配置项

`.env`（见 [`.env.example`](.env.example)）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `RELOGIN_SUBNET` | `172.31.250.0/24` | 内部网络网段 |
| `RELOGIN_IP` | `172.31.250.10` | relogin 容器地址，sub2api 用它访问 |
| `RELOGIN_TOKEN_PATH` | `/etc/sub2api-relogin/token` | 宿主机上的令牌文件 |
| `RELOGIN_OUT_SUBNET` | `172.31.249.0/24` | egress 出网网络网段（防火墙放行用） |
| `SUB2API_BASE_URL` | 空 | sub2api 地址，egress 用它查账号代理 |
| `SUB2API_ADMIN_KEY_PATH` | `/etc/sub2api-relogin/sub2api-admin-key` | 宿主机上的管理员 API Key 文件 |
| `RELOGIN_ACCOUNT_PROXY` | `on` | `on`：走账号配置的代理；`off`：一律本机出口直连，不查 sub2api |

服务本身的环境变量在 [`compose.yaml`](compose.yaml) 里：`RELOGIN_MAX_CONCURRENT`（同时登录数，默认 2）、`RELOGIN_TIMEOUT_SECONDS`（单次登录超时，默认 600）。

## 接口

两个接口都要求 `Authorization: Bearer <令牌>`。

**`POST /api/v1/relogin`**

请求：

```json
{"action": "start", "auth_mode": "password_2fa", "email": "a@example.com", "password": "…", "mfa_secret": "BASE32SECRET"}
```

响应为 `application/x-ndjson`：每 15 秒一行心跳 `{"type":"progress","stage":"running"}`，最后一行结果：

```json
{"type":"result","payload":{"status":"succeeded","credential":{"access_token":"…","refresh_token":"…","id_token":"…","email":"a@example.com","chatgpt_account_id":"…","chatgpt_user_id":"…","client_id":"…","expires_at":1760000000}}}
{"type":"result","payload":{"status":"failed","error":{"code":"password_rejected"}}}
```

**`POST /api/v1/relogin/probe`** → `{"status":"active","mode":"passive"}`

**`GET /healthz`**（不需要令牌）→ `{"ok":true,"running":0}`

egress（只在内部网络里可达，供 relogin 和 `check.sh` 使用）：

- `POST /routes`，`Authorization: Bearer <令牌>`，`{"email":"a@example.com","mode":"account"}`（`mode` 为 `direct` 时不查 sub2api）→ `{"route":"<32 位十六进制>","mode":"account_proxy"|"direct","reason":"…","via":{"protocol","host","port"}|null}`
- `DELETE /routes/<路由号>`
- `CONNECT host:443`，`Proxy-Authorization: Basic base64("route:<路由号>")`

## 升级 toSub2

1. 在 [`fetch-tosub2.sh`](fetch-tosub2.sh) 里换 `COMMIT`，下载新压缩包算出 `TARBALL_SHA256` 填进去。
2. **重新审计登录路径的出网**：`protocol-login.mjs` 及它加载的模块（`tls-transport.mjs`、`tls_transport.py`、`cloudflare-ctf/`）会连哪些主机，有没有新的第三方服务、遥测或远端代码。
3. 确认补丁还能打上（`patches/`），必要时重做。
4. 重新生成 `vendor/tosub2/` 和 `vendor/tosub2.sha256`（在 `vendor/tosub2` 里 `find . -type f ! -name UPSTREAM_COMMIT | sort | xargs sha256sum > ../tosub2.sha256`）。
5. 如果登录需要访问新主机，加进 `egress/allowlist`。
6. 部署后跑 `./check.sh`，再用一个账号实测重登。

## 开发与测试

自动测试（真实的 `server.mjs` + `egress.mjs`，配假的 sub2api、假的 HTTP / SOCKS5 账号代理和 toSub2 替身；不联网）：

```sh
node --test test/relogin.test.mjs
```

`test/fake-tosub2` 是 toSub2 的替身，也可以手动起服务测协议、超时、并发和断连，不碰真实账号：

```sh
openssl rand -hex 24 > /tmp/relogin-token
RELOGIN_TOKEN_FILE=/tmp/relogin-token TOSUB2_ROOT=$PWD/test/fake-tosub2 RELOGIN_TIMEOUT_SECONDS=3 node server.mjs
# 另开终端：密码 "wrong" → password_rejected，"hang" → timeout，"slow" → 2 秒后成功，其它 → 成功
curl -s -H "Authorization: Bearer $(cat /tmp/relogin-token)" -X POST http://127.0.0.1:18790/api/v1/relogin \
  -d '{"action":"start","auth_mode":"password_2fa","email":"a@example.com","password":"slow"}'
```

需要 Node.js 22。

## 已知限制

- 只支持「密码 + TOTP」账号；要邮箱验证码、绑定手机的账号无法自动登录。
- 测活是被动的：令牌只在业务请求失败后才会被发现失效、触发重登。
- 账号代理按「账号名 == 邮箱」查找，规则和 sub2api 凭证守护对账号的匹配一致；只查 `openai` 平台的账号。
- SOCKS5 代理一律把目标主机名交给代理解析（`socks5` 和 `socks5h` 同样处理），DNS 查询也从代理那一侧发出。
- sub2api 新版「凭证运营」页（`/admin/token-guard-v2`）的 `session_studio` 引擎要求 https 接口，本服务只提供 http，**不支持**；只对接旧版「凭证守护」。
- 只在 ranxi sub2api v2.10.1 + toSub2 `8548397e` 上验证过。

## 许可

本项目代码以 [MIT](LICENSE) 发布。`vendor/tosub2` 是 [poxiao33/toSub2](https://github.com/poxiao33/toSub2) 的副本（MIT，见 `vendor/tosub2/LICENSE`），附带本项目的补丁。
