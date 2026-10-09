// 自托管重登服务：实现 ranxi sub2api「凭证守护」的重登 / 测活接口，替代 session.ameng2027.xyz。
// 登录本身交给审计过、固定提交的 toSub2（protocol-login.mjs），在本机子进程里跑；
// 密码和 TOTP 密钥只经环境变量交给子进程，不落盘、不写日志、不回显。
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const LISTEN_HOST = process.env.RELOGIN_LISTEN_HOST || "127.0.0.1";
const LISTEN_PORT = Number(process.env.RELOGIN_LISTEN_PORT || 18790);
const TOSUB2_ROOT = process.env.TOSUB2_ROOT || "/opt/tosub2";
const EGRESS_PROXY = (process.env.RELOGIN_EGRESS_PROXY || "").trim();
// on（默认）：登录走该账号在 sub2api 里配置的代理，和日常使用同一个出口 IP；off：一律从本机出口直连。
const ACCOUNT_PROXY = (process.env.RELOGIN_ACCOUNT_PROXY || "on").trim().toLowerCase() !== "off";
const MAX_CONCURRENT = Number(process.env.RELOGIN_MAX_CONCURRENT || 2);
const LOGIN_TIMEOUT_MS = Number(process.env.RELOGIN_TIMEOUT_SECONDS || 600) * 1000;
const HEARTBEAT_MS = 15_000;
const MAX_BODY = 16 * 1024;
const MAX_CHILD_OUTPUT = 512 * 1024;

const TOKEN = (await readToken()).trim();
if (TOKEN.length < 32) {
  console.error("RELOGIN_TOKEN_FILE 里的令牌至少 32 个字符");
  process.exit(1);
}

let running = 0;
// 同一邮箱同时只跑一次登录；凭据完全相同的后到请求等同一次登录的结果。
const inflight = new Map();

async function readToken() {
  const file = process.env.RELOGIN_TOKEN_FILE;
  if (!file) {
    console.error("必须设置 RELOGIN_TOKEN_FILE");
    process.exit(1);
  }
  return fs.readFile(file, "utf8");
}

function log(fields) {
  console.log(JSON.stringify({ time: new Date().toISOString(), ...fields }));
}

// 日志里只留邮箱的短哈希，能对上号又不暴露邮箱。
function emailTag(email) {
  return crypto.createHash("sha256").update(email).digest("hex").slice(0, 10);
}

function authorized(req) {
  const header = String(req.headers.authorization || "");
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7).trim() : "");
  const want = Buffer.from(TOKEN);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error("body too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJSON(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function jwtClaims(token) {
  try {
    return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8"));
  } catch {
    return {};
  }
}

// toSub2 的输出可能含秘密，只按固定标记归类：走到了哪一步、为什么失败。
const STAGES = [
  ["[1/5] Start ChatGPT web login", "web_login"],
  ["[3/5] Password login page reached", "password_page"],
  ["[ok] Password accepted", "password_accepted"],
  ["[mfa] TOTP 2FA challenge reached", "mfa_challenge"],
  ["[ok] 2FA verification accepted", "mfa_accepted"],
  ["[2/5] Start Codex OAuth flow", "codex_authorize"],
  ["[5/5] Select workspace", "workspace_select"],
  ["[ok] Codex callback URL", "callback"],
  ["[6/6] Convert OAuth callback", "token_exchange"],
];
const FAILURE_REASONS = [
  ["Password was rejected", "password_rejected"],
  ["2FA key was rejected", "totp_rejected"],
  ["[3/5] Email OTP page reached", "email_otp_required"],
  ["[4/5] Phone binding is required", "phone_required"],
  ["PROXY_RISK_CONTROL", "security_check"],
  ["security-check", "security_check"],
];

function classifyFailure(output, exitCode, timedOut) {
  let stage = "not_started";
  for (const [marker, name] of STAGES) {
    if (output.includes(marker)) stage = name;
  }
  if (timedOut) return { code: "timeout", stage };
  for (const [marker, code] of FAILURE_REASONS) {
    if (output.includes(marker)) return { code, stage };
  }
  return { code: exitCode === 0 ? "incomplete_credentials" : "relogin_failed", stage };
}

// 向 egress 申请这次登录的出网路由：egress 按邮箱查 sub2api 里该账号的代理，返回一个路由号。
// 登录子进程只拿到「egress + 路由号」，看不到账号代理本身的地址和密码。
async function createRoute(email) {
  let res;
  try {
    res = await fetch(new URL("/routes", EGRESS_PROXY), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ email, mode: ACCOUNT_PROXY ? "account" : "direct" }),
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return { ok: false, code: "egress_unreachable" };
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !/^[0-9a-f]{32}$/.test(String(body.route || ""))) {
    return { ok: false, code: String(body?.error?.code || "account_proxy_lookup_failed") };
  }
  const proxy = new URL(EGRESS_PROXY);
  proxy.username = "route";
  proxy.password = body.route;
  return { ok: true, id: body.route, proxy: proxy.toString(), mode: body.mode, reason: body.reason, via: body.via };
}

function deleteRoute(id) {
  fetch(new URL(`/routes/${id}`, EGRESS_PROXY), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${TOKEN}` },
    signal: AbortSignal.timeout(10_000),
  }).catch(() => {});
}

async function runLogin(job, signal) {
  if (!EGRESS_PROXY) return spawnLogin(job, null, signal);
  const route = await createRoute(job.email);
  if (!route.ok) return { ok: false, code: route.code, stage: "proxy_lookup" };
  if (signal.aborted) {
    deleteRoute(route.id);
    return { ok: false, code: "cancelled", stage: "proxy_lookup" };
  }
  log({ event: "relogin_route", email: job.tag, mode: route.mode, reason: route.reason, via: route.via });
  try {
    return await spawnLogin(job, route.proxy, signal);
  } finally {
    deleteRoute(route.id);
  }
}

function spawnLogin({ email, password, mfaSecret }, proxy, signal) {
  return new Promise(async (resolve) => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "relogin-"));
    await fs.chmod(dir, 0o700);
    const outFile = path.join(dir, "oauth.json");
    const args = [
      path.join(TOSUB2_ROOT, "src", "protocol-login.mjs"),
      "--email", email,
      "--output-mode", "sub2api",
      "--sub2api-out", outFile,
      "--sub2api-name", "relogin",
    ];
    if (proxy) args.push("--proxy", proxy);
    // 子进程只拿到它需要的变量：不继承本服务的令牌和其它环境。
    const env = {
      PATH: process.env.PATH,
      HOME: dir,
      NODE_ENV: "production",
      CHATGPT_LOGIN_PASSWORD: password,
      CHATGPT_PROXY_MAX_ATTEMPTS: "1",
    };
    if (mfaSecret) env.CHATGPT_TOTP_SECRET = mfaSecret;
    if (process.env.TOSUB2_PYTHON) env.TOSUB2_PYTHON = process.env.TOSUB2_PYTHON;

    const child = spawn(process.execPath, args, { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const collect = (chunk) => {
      if (output.length < MAX_CHILD_OUTPUT) output += chunk.toString("utf8");
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, LOGIN_TIMEOUT_MS);
    const abort = () => child.kill("SIGKILL");
    signal.addEventListener("abort", abort, { once: true });

    child.on("close", async (exitCode) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      let result;
      try {
        if (exitCode !== 0 || timedOut || signal.aborted) throw new Error("login failed");
        const payload = JSON.parse(await fs.readFile(outFile, "utf8"));
        const account = payload?.accounts?.length === 1 ? payload.accounts[0] : null;
        const credentials = account?.credentials || {};
        const extra = account?.extra || {};
        for (const key of ["access_token", "refresh_token", "id_token"]) {
          if (!String(credentials[key] || "").trim()) throw new Error("incomplete");
        }
        const claims = jwtClaims(credentials.access_token);
        if (String(claims["https://api.openai.com/profile"]?.email || email).toLowerCase() !== email) {
          throw new Error("email mismatch");
        }
        const credential = {
          access_token: credentials.access_token,
          refresh_token: credentials.refresh_token,
          id_token: credentials.id_token,
          email,
        };
        for (const key of ["chatgpt_account_id", "chatgpt_user_id", "client_id", "account_id"]) {
          const value = credentials[key] || extra[key];
          if (value) credential[key] = String(value);
        }
        if (Number.isFinite(claims.exp)) credential.expires_at = claims.exp;
        result = { ok: true, credential };
      } catch (err) {
        const failure = classifyFailure(output, exitCode, timedOut);
        if (err.message === "email mismatch") failure.code = "email_mismatch";
        result = { ok: false, ...failure, exitCode };
      } finally {
        output = "";
        await fs.rm(dir, { recursive: true, force: true });
      }
      resolve(result);
    });
  });
}

async function handleRelogin(req, res) {
  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch (err) {
    return sendJSON(res, err.status || 400, { error: { code: "bad_request" } });
  }
  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");
  const mfaSecret = String(body?.mfa_secret || "").replace(/\s+/g, "").toUpperCase();
  if (body?.action !== "start" || body?.auth_mode !== "password_2fa"
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password
      || (mfaSecret && !/^[A-Z2-7]+=*$/.test(mfaSecret))) {
    return sendJSON(res, 400, { error: { code: "bad_request" } });
  }
  const secretHash = crypto.createHash("sha256").update(JSON.stringify([email, password, mfaSecret])).digest("hex");
  let job = inflight.get(email);
  if (job && job.secretHash !== secretHash) {
    return sendJSON(res, 409, { error: { code: "login_in_progress" } });
  }
  if (!job && running >= MAX_CONCURRENT) {
    return sendJSON(res, 503, { error: { code: "busy" } });
  }
  const tag = emailTag(email);
  if (!job) {
    job = startJob({ email, password, mfaSecret, secretHash, tag });
  } else {
    log({ event: "relogin_join", email: tag });
  }
  job.waiters += 1;

  res.writeHead(200, { "Content-Type": "application/x-ndjson", "Cache-Control": "no-store" });
  const write = (event) => res.write(JSON.stringify(event) + "\n");
  write({ type: "progress", stage: "started" });
  const heartbeat = setInterval(() => write({ type: "progress", stage: "running" }), HEARTBEAT_MS);
  let left = false;
  const leave = () => {
    if (left) return;
    left = true;
    job.waiters -= 1;
    if (job.waiters === 0) job.controller.abort();
  };
  res.on("close", () => { if (!res.writableFinished) leave(); });

  try {
    const result = await job.promise;
    if (result.ok) {
      write({ type: "result", payload: { status: "succeeded", credential: result.credential } });
    } else {
      write({ type: "result", payload: { status: "failed", error: { code: result.code } } });
    }
  } finally {
    clearInterval(heartbeat);
    left = true;
    res.end();
  }
}

function startJob({ email, password, mfaSecret, secretHash, tag }) {
  const job = { secretHash, waiters: 0, controller: new AbortController() };
  running += 1;
  inflight.set(email, job);
  const started = Date.now();
  log({ event: "relogin_start", email: tag, totp: Boolean(mfaSecret) });
  job.promise = runLogin({ email, password, mfaSecret, tag }, job.controller.signal).then((result) => {
    const elapsed = Date.now() - started;
    if (result.ok) {
      log({ event: "relogin_done", email: tag, ok: true, elapsed_ms: elapsed });
    } else {
      log({ event: "relogin_done", email: tag, ok: false, code: result.code, stage: result.stage,
        exit_code: result.exitCode, elapsed_ms: elapsed });
    }
    return result;
  }).finally(() => {
    running -= 1;
    inflight.delete(email);
  });
  return job;
}

// 测活走被动模式：不拿账号令牌去打上游（避免每几分钟多出一条官方客户端不会发的请求）。
// sub2api 在业务请求已经拿到 401/吊销时，会跳过测活直接判定需要重登，所以这里恒报 active。
async function handleProbe(req, res) {
  try {
    await readBody(req);
  } catch (err) {
    return sendJSON(res, err.status || 400, { error: { code: "bad_request" } });
  }
  sendJSON(res, 200, { status: "active", mode: "passive" });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/healthz") {
    return sendJSON(res, 200, { ok: true, running });
  }
  if (!authorized(req)) {
    return sendJSON(res, 401, { error: { code: "unauthorized" } });
  }
  if (req.method === "POST" && url.pathname === "/api/v1/relogin") return handleRelogin(req, res);
  if (req.method === "POST" && url.pathname === "/api/v1/relogin/probe") return handleProbe(req, res);
  sendJSON(res, 404, { error: { code: "not_found" } });
});

server.requestTimeout = 0;
server.headersTimeout = 10_000;
server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  log({ event: "listening", host: LISTEN_HOST, port: LISTEN_PORT, egress_proxy: Boolean(EGRESS_PROXY),
    account_proxy: Boolean(EGRESS_PROXY) && ACCOUNT_PROXY });
});
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
