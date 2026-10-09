# sub2api-relogin

替代 ranxi sub2api「凭证守护」默认的第三方重登服务 `session.ameng2027.xyz`。账号密码和 TOTP 密钥只在本机处理。

## 组成
- `server.mjs`：实现凭证守护的两个接口（Bearer 令牌鉴权）
  - `POST /api/v1/relogin`：`{"action":"start","auth_mode":"password_2fa","email","password","mfa_secret"}` → NDJSON，心跳 `{"type":"progress"}`，结果 `{"type":"result","payload":{"status":"succeeded","credential":{...}}}` 或 `{"status":"failed","error":{"code":...}}`。同一邮箱同时只登录一次；凭据相同的后到请求共用结果，不同则 409。
  - `POST /api/v1/relogin/probe`：被动测活，恒回 `active`，不拿账号令牌打上游。业务请求已拿到 401/吊销的账号，sub2api 会跳过测活直接重登。
- `vendor/tosub2`：第三方 [poxiao33/toSub2](https://github.com/poxiao33/toSub2) 固定提交 `8548397e`，用它的 `protocol-login.mjs` 走密码 + TOTP 登录、Codex OAuth。服务器上由 `fetch-tosub2.sh` 下载、校验压缩包哈希、打 `patches/` 补丁、按 `vendor/tosub2.sha256` 逐文件校验。
- `patches/0001`：Python 工作进程不继承密码和 TOTP 环境变量（它的下游会执行 OpenAI Sentinel / Cloudflare 下发的 JS，沙箱可逃逸）。
- `egress/`：tinyproxy，唯一出网口，只放行 `allowlist` 里的主机名（chatgpt.com、auth.openai.com、sentinel.openai.com、challenges.cloudflare.com）。

## 网络
`relogin` 只在 `internal` 网络 172.31.250.0/24（无出网路由），只能经 `egress:8888`。sub2api（host 网络）调 `http://172.31.250.10:18790`。

## 部署（netcup `/opt/sub2api-relogin`）
```
./fetch-tosub2.sh
install -d -m 0750 -g 10790 /etc/sub2api-relogin && (umask 077; openssl rand -hex 32 > /etc/sub2api-relogin/token) && chown 10790:10790 /etc/sub2api-relogin/token
docker compose up -d --build
```
sub2api 设置 `account_token_guard_config_v1`：`relogin_endpoint` / `probe_endpoint` 指向上面地址，`relogin_headers` / `probe_headers` = `{"Authorization": "Bearer <token>"}`。

## 注意
- 旧版凭证守护按**账号名 == 邮箱**匹配重登凭据，账号名要改成邮箱。
- 日志只记邮箱哈希、阶段和失败码；toSub2 的原始输出不落盘。
- 升级 toSub2：改 `fetch-tosub2.sh` 里的提交和哈希，重新审计登录路径的出网，重新生成 `vendor/tosub2.sha256`。
