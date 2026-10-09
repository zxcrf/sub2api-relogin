// 出网代理：relogin 容器唯一的出网口。只放行到白名单主机的 CONNECT，
// 并按「路由」把一次登录的流量接到该账号在 sub2api 里配置的代理上，让登录出口 IP 和日常使用一致。
// 路由由 relogin 服务（凭令牌）按邮箱申请；账号代理的地址和密码只留在这个进程里，登录子进程看不到。
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import tls from "node:tls";

const LISTEN_HOST = process.env.EGRESS_LISTEN_HOST || "0.0.0.0";
const LISTEN_PORT = Number(process.env.EGRESS_LISTEN_PORT || 8888);
const ALLOWLIST_FILE = process.env.EGRESS_ALLOWLIST_FILE || "/etc/egress/allowlist";
const CONNECT_PORTS = new Set(String(process.env.EGRESS_CONNECT_PORTS || "443").split(",").map((p) => Number(p.trim())));
const SUB2API_BASE_URL = (process.env.SUB2API_BASE_URL || "").trim().replace(/\/+$/, "");
const ROUTE_TTL_MS = Number(process.env.EGRESS_ROUTE_TTL_SECONDS || 900) * 1000;
const UPSTREAM_TIMEOUT_MS = 20_000;
const LOOKUP_TIMEOUT_MS = 15_000;
const TUNNEL_IDLE_MS = 600_000;

const ALLOWLIST = fs.readFileSync(ALLOWLIST_FILE, "utf8").split("\n")
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => new RegExp(line, "i"));
const TOKEN = readSecret("EGRESS_TOKEN_FILE", true);
const ADMIN_KEY = SUB2API_BASE_URL ? readSecret("SUB2API_ADMIN_KEY_FILE", true) : "";

// routeId -> { upstream: null | {protocol, host, port, username, password}, expires }
const routes = new Map();

function readSecret(envName, required) {
  const file = process.env[envName];
  if (!file) {
    if (!required) return "";
    console.error(`必须设置 ${envName}`);
    process.exit(1);
  }
  return fs.readFileSync(file, "utf8").trim();
}

function log(fields) {
  console.log(JSON.stringify({ time: new Date().toISOString(), ...fields }));
}

function emailTag(email) {
  return crypto.createHash("sha256").update(email).digest("hex").slice(0, 10);
}

function sendJSON(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function bearerOK(req) {
  const header = String(req.headers.authorization || "");
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7).trim() : "");
  const want = Buffer.from(TOKEN);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

class LookupError extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.code = code;
  }
}

async function adminGet(pathAndQuery) {
  let res;
  try {
    res = await fetch(SUB2API_BASE_URL + pathAndQuery, {
      headers: { "x-api-key": ADMIN_KEY, accept: "application/json" },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    });
  } catch (err) {
    throw new LookupError("account_proxy_lookup_failed", `sub2api 不可达：${err.cause?.code || err.name}`);
  }
  if (res.status === 401 || res.status === 403) {
    throw new LookupError("account_proxy_lookup_failed", `sub2api 拒绝了管理密钥（HTTP ${res.status}）`);
  }
  if (!res.ok) throw new LookupError("account_proxy_lookup_failed", `sub2api 返回 HTTP ${res.status}`);
  const body = await res.json().catch(() => null);
  if (!body || body.code !== 0) throw new LookupError("account_proxy_lookup_failed", "sub2api 返回格式不对");
  return body.data;
}

// 按 sub2api 凭证守护的匹配规则（账号名 == 邮箱，忽略大小写和首尾空白）找到账号，再取它的代理。
// 没有这个账号（例如「2FA 登录导入」新号）或账号没配代理：直连，和 sub2api 自己用这个号时的出口一致。
async function lookupAccountProxy(email) {
  const query = new URLSearchParams({ platform: "openai", search: email, page: "1", page_size: "100" });
  const data = await adminGet(`/api/v1/admin/accounts?${query}`);
  const items = Array.isArray(data?.items) ? data.items : [];
  const matches = items.filter((a) => String(a?.name || "").trim().toLowerCase() === email);
  if (matches.length === 0) return { upstream: null, reason: "account_not_found" };
  const proxyIds = [...new Set(matches.map((a) => a.proxy_id ?? null))];
  if (proxyIds.length > 1) {
    throw new LookupError("account_proxy_ambiguous", `有 ${matches.length} 个同名账号且代理不同`);
  }
  if (proxyIds[0] === null) return { upstream: null, reason: "account_has_no_proxy", accountIds: matches.map((a) => a.id) };
  const proxy = await adminGet(`/api/v1/admin/proxies/${encodeURIComponent(proxyIds[0])}`);
  const protocol = String(proxy?.protocol || "").toLowerCase();
  const port = Number(proxy?.port);
  if (!["http", "https", "socks5", "socks5h"].includes(protocol) || !proxy?.host || !Number.isInteger(port)) {
    throw new LookupError("account_proxy_unsupported", `代理 ${proxyIds[0]} 的协议或地址不支持`);
  }
  return {
    upstream: {
      protocol,
      host: String(proxy.host),
      port,
      username: String(proxy.username || ""),
      password: String(proxy.password || ""),
    },
    reason: "account_proxy",
    accountIds: matches.map((a) => a.id),
    proxyId: proxyIds[0],
    proxyStatus: proxy.status,
  };
}

function pruneRoutes() {
  const now = Date.now();
  for (const [id, route] of routes) if (route.expires <= now) routes.delete(id);
}

async function handleCreateRoute(req, res) {
  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch {
    return sendJSON(res, 400, { error: { code: "bad_request" } });
  }
  const email = String(body?.email || "").trim().toLowerCase();
  if (!email) return sendJSON(res, 400, { error: { code: "bad_request" } });
  const tag = emailTag(email);
  let found;
  if (body?.mode === "direct") {
    found = { upstream: null, reason: "disabled" };
  } else if (!SUB2API_BASE_URL) {
    log({ event: "route_failed", email: tag, code: "account_proxy_not_configured" });
    return sendJSON(res, 503, { error: { code: "account_proxy_not_configured" } });
  } else {
    try {
      found = await lookupAccountProxy(email);
    } catch (err) {
      log({ event: "route_failed", email: tag, code: err.code || "account_proxy_lookup_failed", detail: err.message });
      return sendJSON(res, 502, { error: { code: err.code || "account_proxy_lookup_failed" } });
    }
  }
  pruneRoutes();
  const id = crypto.randomBytes(16).toString("hex");
  routes.set(id, { upstream: found.upstream, expires: Date.now() + ROUTE_TTL_MS });
  const via = found.upstream
    ? { protocol: found.upstream.protocol, host: found.upstream.host, port: found.upstream.port }
    : null;
  log({ event: "route_created", email: tag, reason: found.reason, account_ids: found.accountIds,
    proxy_id: found.proxyId, proxy_status: found.proxyStatus, via });
  sendJSON(res, 200, { route: id, mode: found.upstream ? "account_proxy" : "direct", reason: found.reason, via });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 4096) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ---- CONNECT 隧道 ----

function routeFromAuth(header) {
  if (!header) return null;
  const [scheme, value] = String(header).split(" ");
  if (!/^basic$/i.test(scheme || "") || !value) return null;
  const decoded = Buffer.from(value, "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (decoded.slice(0, sep) !== "route") return null;
  const route = routes.get(decoded.slice(sep + 1));
  if (!route || route.expires <= Date.now()) return null;
  return route;
}

function connectTimeout(socket, ms) {
  socket.setTimeout(ms, () => socket.destroy(new Error("upstream timeout")));
  return () => socket.setTimeout(0);
}

// 经 HTTP(S) 代理开隧道：发 CONNECT，读到响应头为止，返回已打通的 socket 和多读到的字节。
function tunnelViaHttp(up, host, port) {
  return new Promise((resolve, reject) => {
    const socket = up.protocol === "https"
      ? tls.connect({ host: up.host, port: up.port, servername: net.isIP(up.host) ? undefined : up.host })
      : net.connect({ host: up.host, port: up.port });
    const clear = connectTimeout(socket, UPSTREAM_TIMEOUT_MS);
    socket.once("error", reject);
    socket.once(up.protocol === "https" ? "secureConnect" : "connect", () => {
      let head = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n`;
      if (up.username || up.password) {
        head += `Proxy-Authorization: Basic ${Buffer.from(`${up.username}:${up.password}`).toString("base64")}\r\n`;
      }
      socket.write(head + "\r\n");
    });
    let buffered = Buffer.alloc(0);
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf("\r\n\r\n");
      if (end === -1) {
        if (buffered.length > 16384) socket.destroy(new Error("upstream header too large"));
        return;
      }
      socket.off("data", onData);
      const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(buffered.subarray(0, end).toString("latin1"))?.[1]);
      if (status !== 200) {
        socket.destroy();
        return reject(new Error(`upstream CONNECT HTTP ${status || "?"}`));
      }
      clear();
      socket.off("error", reject);
      resolve({ socket, rest: buffered.subarray(end + 4) });
    };
    socket.on("data", onData);
  });
}

// 经 SOCKS5 代理开隧道（RFC 1928/1929）。目标一律按域名交给代理解析，DNS 也走代理那一侧。
function tunnelViaSocks5(up, host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: up.host, port: up.port });
    const clear = connectTimeout(socket, UPSTREAM_TIMEOUT_MS);
    socket.once("error", reject);
    const useAuth = Boolean(up.username || up.password);
    let buffered = Buffer.alloc(0);
    let step = "greeting";
    const fail = (message) => {
      socket.destroy();
      reject(new Error(message));
    };
    const take = (n) => {
      if (buffered.length < n) return null;
      const out = buffered.subarray(0, n);
      buffered = buffered.subarray(n);
      return out;
    };
    const sendConnect = () => {
      const name = Buffer.from(host);
      const req = Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([port >> 8, port & 255])]);
      socket.write(req);
      step = "connect";
    };
    const pump = () => {
      for (;;) {
        if (step === "greeting") {
          const reply = take(2);
          if (!reply) return;
          if (reply[0] !== 5) return fail("socks: bad version");
          if (reply[1] === 0) sendConnect();
          else if (reply[1] === 2 && useAuth) {
            const u = Buffer.from(up.username);
            const p = Buffer.from(up.password);
            socket.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
            step = "auth";
          } else return fail("socks: no acceptable auth method");
        } else if (step === "auth") {
          const reply = take(2);
          if (!reply) return;
          if (reply[1] !== 0) return fail("socks: auth rejected");
          sendConnect();
        } else if (step === "connect") {
          if (buffered.length < 5) return;
          const atyp = buffered[3];
          const addrLen = atyp === 1 ? 4 : atyp === 4 ? 16 : atyp === 3 ? 1 + buffered[4] : -1;
          if (addrLen < 0) return fail("socks: bad reply");
          const reply = take(4 + addrLen + 2);
          if (!reply) return;
          if (reply[1] !== 0) return fail(`socks: connect failed (${reply[1]})`);
          socket.off("data", onData);
          socket.off("error", reject);
          clear();
          return resolve({ socket, rest: buffered });
        }
      }
    };
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      pump();
    };
    socket.on("data", onData);
    socket.once("connect", () => {
      socket.write(Buffer.from(useAuth ? [5, 2, 0, 2] : [5, 1, 0]));
    });
  });
}

function tunnelDirect(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const clear = connectTimeout(socket, UPSTREAM_TIMEOUT_MS);
    socket.once("error", reject);
    socket.once("connect", () => {
      clear();
      socket.off("error", reject);
      resolve({ socket, rest: Buffer.alloc(0) });
    });
  });
}

function refuse(client, status, text) {
  client.end(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
}

async function handleConnect(req, client, head) {
  client.on("error", () => {});
  const match = /^([^:\s]+):(\d+)$/.exec(req.url || "");
  const host = match?.[1]?.toLowerCase();
  const port = Number(match?.[2]);
  if (!host || !CONNECT_PORTS.has(port) || !ALLOWLIST.some((re) => re.test(host))) {
    log({ event: "connect_denied", target: req.url });
    return refuse(client, 403, "Filtered");
  }
  // 每条隧道都必须带 relogin 申请到的路由，没带或已过期就拒绝，免得哪条请求悄悄绕开账号代理。
  const route = routeFromAuth(req.headers["proxy-authorization"]);
  if (!route) return refuse(client, 407, "Unknown Route");
  const up = route.upstream;
  let tunnel;
  try {
    if (!up) tunnel = await tunnelDirect(host, port);
    else if (up.protocol === "http" || up.protocol === "https") tunnel = await tunnelViaHttp(up, host, port);
    else tunnel = await tunnelViaSocks5(up, host, port);
  } catch (err) {
    log({ event: "connect_failed", target: `${host}:${port}`, via: up ? `${up.protocol}://${up.host}:${up.port}` : "direct",
      error: err.message });
    return refuse(client, 502, "Bad Gateway");
  }
  const upstream = tunnel.socket;
  upstream.on("error", () => client.destroy());
  client.on("error", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  client.on("close", () => upstream.destroy());
  for (const socket of [client, upstream]) socket.setTimeout(TUNNEL_IDLE_MS, () => socket.destroy());
  client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  if (tunnel.rest.length) client.write(tunnel.rest);
  if (head?.length) upstream.write(head);
  upstream.pipe(client);
  client.pipe(upstream);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://egress");
  if (req.method === "GET" && url.pathname === "/healthz" && !/^https?:/i.test(req.url)) {
    return sendJSON(res, 200, { ok: true, routes: routes.size, account_proxy: Boolean(SUB2API_BASE_URL) });
  }
  if (/^https?:/i.test(req.url)) return sendJSON(res, 403, { error: { code: "filtered" } });
  if (!bearerOK(req)) return sendJSON(res, 401, { error: { code: "unauthorized" } });
  if (req.method === "POST" && url.pathname === "/routes") return handleCreateRoute(req, res);
  const del = /^\/routes\/([0-9a-f]{32})$/.exec(url.pathname);
  if (req.method === "DELETE" && del) {
    routes.delete(del[1]);
    return sendJSON(res, 200, { ok: true });
  }
  sendJSON(res, 404, { error: { code: "not_found" } });
});
server.on("connect", (req, client, head) => {
  handleConnect(req, client, head).catch(() => client.destroy());
});
server.headersTimeout = 10_000;
server.maxConnections = 64;
server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  log({ event: "listening", host: LISTEN_HOST, port: LISTEN_PORT, rules: ALLOWLIST.length,
    account_proxy: Boolean(SUB2API_BASE_URL) });
});
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => process.exit(0));
}
