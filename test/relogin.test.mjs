// 端到端测试：真实的 server.mjs + egress.mjs，配假的 sub2api、假的 HTTP / SOCKS5 账号代理和 toSub2 替身。
// 不碰外网，不碰真实账号。用法：node --test test/
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const FAKE_TOSUB2 = path.join(ROOT, "test", "fake-tosub2");
const PROBE_FILE = path.join(FAKE_TOSUB2, "probe-target");
const TOKEN = "t".repeat(40);
const ADMIN_KEY = "admin-key-for-tests";

const seen = { http: [], socks: [] };
const children = [];
const servers = [];
let tmp;
let reloginURL;
let egressPort;
let sub2apiDown = false;

function listen(server) {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

function freePort() {
  return listen(net.createServer()).then(async (port) => {
    await new Promise((resolve) => servers.pop().close(resolve));
    return port;
  });
}

// 握手完成后原样回显，代表「代理后面的目标站」。
function echo(socket) {
  socket.on("data", (chunk) => socket.write(chunk));
  socket.on("error", () => {});
}

function fakeHttpProxy() {
  const server = http.createServer((req, res) => res.writeHead(405).end());
  server.on("connect", (req, socket) => {
    seen.http.push({ target: req.url, auth: req.headers["proxy-authorization"] });
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    echo(socket);
  });
  return listen(server);
}

function fakeSocksProxy() {
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    let step = "greeting";
    const record = {};
    socket.on("error", () => {});
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (step === "greeting" && buf.length >= 2 && buf.length >= 2 + buf[1]) {
        const methods = [...buf.subarray(2, 2 + buf[1])];
        buf = buf.subarray(2 + buf[1]);
        record.methods = methods;
        if (methods.includes(2)) {
          socket.write(Buffer.from([5, 2]));
          step = "auth";
        } else {
          socket.write(Buffer.from([5, 0]));
          step = "request";
        }
      }
      if (step === "auth" && buf.length >= 2) {
        const ulen = buf[1];
        if (buf.length < 3 + ulen) return;
        const plen = buf[2 + ulen];
        if (buf.length < 3 + ulen + plen) return;
        record.user = buf.subarray(2, 2 + ulen).toString();
        record.pass = buf.subarray(3 + ulen, 3 + ulen + plen).toString();
        buf = buf.subarray(3 + ulen + plen);
        socket.write(Buffer.from([1, record.pass === "p2" ? 0 : 1]));
        step = "request";
      }
      if (step === "request" && buf.length >= 5) {
        const len = buf[4];
        if (buf.length < 5 + len + 2) return;
        record.atyp = buf[3];
        record.host = buf.subarray(5, 5 + len).toString();
        record.port = buf.readUInt16BE(5 + len);
        buf = buf.subarray(7 + len);
        seen.socks.push(record);
        socket.off("data", onData);
        socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        echo(socket);
      }
    };
    socket.on("data", onData);
  });
  return listen(server);
}

function fakeSub2api(httpPort, socksPort) {
  const accounts = [
    { id: 1, name: "a@x.test", proxy_id: 11 },
    { id: 2, name: " B@X.test ", proxy_id: 12 },
    { id: 3, name: "c@x.test", proxy_id: null },
    { id: 4, name: "dup@x.test", proxy_id: 11 },
    { id: 5, name: "dup@x.test", proxy_id: 12 },
    { id: 6, name: "aa@x.test", proxy_id: 12 },
  ];
  const proxies = {
    11: { id: 11, protocol: "http", host: "127.0.0.1", port: httpPort, username: "u1", password: "p1", status: "active" },
    12: { id: 12, protocol: "socks5", host: "127.0.0.1", port: socksPort, username: "u2", password: "p2", status: "active" },
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://sub2api");
    const send = (status, body) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
    if (sub2apiDown) return send(500, { code: 500, message: "down" });
    if (req.headers["x-api-key"] !== ADMIN_KEY) return send(401, { code: 401, message: "unauthorized" });
    if (url.pathname === "/api/v1/admin/accounts") {
      assert.equal(url.searchParams.get("platform"), "openai");
      const search = url.searchParams.get("search").toLowerCase();
      const items = accounts.filter((a) => a.name.toLowerCase().includes(search));
      return send(200, { code: 0, data: { items, total: items.length, page: 1, page_size: 100, pages: 1 } });
    }
    const match = /^\/api\/v1\/admin\/proxies\/(\d+)$/.exec(url.pathname);
    if (match && proxies[match[1]]) return send(200, { code: 0, data: proxies[match[1]] });
    send(404, { code: 404 });
  });
  return listen(server);
}

function start(script, env) {
  const child = spawn(process.execPath, [script], { env: { PATH: process.env.PATH, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  child.logs = [];
  const collect = (chunk) => {
    for (const line of chunk.toString().split("\n")) {
      if (!line.trim()) continue;
      try { child.logs.push(JSON.parse(line)); } catch { child.logs.push({ raw: line }); }
    }
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      if (child.logs.some((l) => l.event === "listening")) {
        clearInterval(timer);
        resolve(child);
      }
    }, 20);
    child.on("exit", (code) => reject(new Error(`${script} exited ${code}: ${JSON.stringify(child.logs)}`)));
  });
}

let egress;

before(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), "relogin-test-"));
  const targetPort = await listen(net.createServer(echo));
  // 同一端口在 ::1 上也开一个，用来看直连时选了哪个地址族
  const v6 = net.createServer(echo);
  servers.push(v6);
  await new Promise((resolve) => v6.listen({ port: targetPort, host: "::1", ipv6Only: true }, resolve));
  await fs.writeFile(PROBE_FILE, `localhost:${targetPort}`);
  const httpPort = await fakeHttpProxy();
  const socksPort = await fakeSocksProxy();
  const sub2apiPort = await fakeSub2api(httpPort, socksPort);
  await fs.writeFile(path.join(tmp, "token"), TOKEN);
  await fs.writeFile(path.join(tmp, "admin-key"), ADMIN_KEY + "\n");
  await fs.writeFile(path.join(tmp, "allowlist"), "# test\n^localhost$\n");
  egressPort = await freePort();
  const reloginPort = await freePort();
  egress = await start(path.join(ROOT, "egress", "egress.mjs"), {
    EGRESS_LISTEN_HOST: "127.0.0.1",
    EGRESS_LISTEN_PORT: String(egressPort),
    EGRESS_ALLOWLIST_FILE: path.join(tmp, "allowlist"),
    EGRESS_CONNECT_PORTS: String(targetPort),
    EGRESS_TOKEN_FILE: path.join(tmp, "token"),
    SUB2API_BASE_URL: `http://127.0.0.1:${sub2apiPort}/`,
    SUB2API_ADMIN_KEY_FILE: path.join(tmp, "admin-key"),
  });
  await start(path.join(ROOT, "server.mjs"), {
    RELOGIN_LISTEN_PORT: String(reloginPort),
    RELOGIN_TOKEN_FILE: path.join(tmp, "token"),
    RELOGIN_EGRESS_PROXY: `http://127.0.0.1:${egressPort}`,
    TOSUB2_ROOT: FAKE_TOSUB2,
    RELOGIN_TIMEOUT_SECONDS: "10",
  });
  reloginURL = `http://127.0.0.1:${reloginPort}/api/v1/relogin`;
});

after(async () => {
  for (const child of children) child.kill("SIGKILL");
  for (const server of servers) server.close();
  await fs.rm(PROBE_FILE, { force: true });
  await fs.rm(tmp, { recursive: true, force: true });
});

async function relogin(email, password = "ok") {
  const res = await fetch(reloginURL, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ action: "start", auth_mode: "password_2fa", email, password, mfa_secret: "" }),
  });
  assert.equal(res.status, 200);
  const events = (await res.text()).trim().split("\n").map((line) => JSON.parse(line));
  return events.find((e) => e.type === "result").payload;
}

function lastRouteLog(tag) {
  return egress.logs.filter((l) => l.event === "route_created" || l.event === "route_failed").at(-1);
}

test("账号配了 HTTP 代理：经该代理登录，带上代理的账号密码", async () => {
  const before = seen.http.length;
  const result = await relogin("a@x.test");
  assert.equal(result.status, "succeeded");
  assert.equal(seen.http.length, before + 1);
  assert.match(seen.http.at(-1).target, /^localhost:\d+$/);
  assert.equal(seen.http.at(-1).auth, `Basic ${Buffer.from("u1:p1").toString("base64")}`);
  assert.equal(lastRouteLog().reason, "account_proxy");
});

test("账号配了 SOCKS5 代理：按域名交给代理，账号名大小写和空白不影响匹配", async () => {
  const before = seen.socks.length;
  const result = await relogin("b@x.test");
  assert.equal(result.status, "succeeded");
  assert.equal(seen.socks.length, before + 1);
  assert.deepEqual({ ...seen.socks.at(-1), port: undefined },
    { methods: [0, 2], user: "u2", pass: "p2", atyp: 3, host: "localhost", port: undefined });
});

test("搜索会模糊匹配，只认账号名完全相同的那个", async () => {
  const before = { http: seen.http.length, socks: seen.socks.length };
  assert.equal((await relogin("a@x.test")).status, "succeeded");
  assert.equal(seen.http.length, before.http + 1);
  assert.equal(seen.socks.length, before.socks, "aa@x.test 的 SOCKS 代理不该被用上");
});

test("账号没配代理、或 sub2api 里没有这个账号：直连", async () => {
  const before = seen.http.length + seen.socks.length;
  assert.equal((await relogin("c@x.test")).status, "succeeded");
  assert.equal(lastRouteLog().reason, "account_has_no_proxy");
  assert.equal((await relogin("new@x.test")).status, "succeeded");
  assert.equal(lastRouteLog().reason, "account_not_found");
  assert.equal(seen.http.length + seen.socks.length, before);
});

test("直连按 Go 的规则选地址族：有 IPv6 路由就先走 IPv6", async () => {
  const before = egress.logs.length;
  assert.equal((await relogin("c@x.test")).status, "succeeded");
  const opened = egress.logs.slice(before).filter((l) => l.event === "tunnel_open" && l.via === "direct");
  assert.ok(opened.length > 0);
  assert.deepEqual([...new Set(opened.map((l) => l.family))], ["IPv6"]);
});

test("同名账号代理不同：拒绝登录，不猜", async () => {
  const result = await relogin("dup@x.test");
  assert.equal(result.status, "failed");
  assert.equal(result.error.code, "account_proxy_ambiguous");
});

test("查不到 sub2api：登录失败，不退回本机出口", async () => {
  sub2apiDown = true;
  try {
    const result = await relogin("a@x.test");
    assert.equal(result.status, "failed");
    assert.equal(result.error.code, "account_proxy_lookup_failed");
  } finally {
    sub2apiDown = false;
  }
});

test("路由用完即删", async () => {
  await relogin("a@x.test");
  await new Promise((resolve) => setTimeout(resolve, 100));
  const health = await (await fetch(`http://127.0.0.1:${egressPort}/healthz`)).json();
  assert.equal(health.routes, 0);
});

function rawConnect(target, headers = "") {
  return new Promise((resolve, reject) => {
    const socket = net.connect(egressPort, "127.0.0.1", () => {
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${headers}\r\n`);
    });
    socket.once("data", (chunk) => {
      socket.destroy();
      resolve(Number(chunk.toString().split(" ")[1]));
    });
    socket.on("error", reject);
  });
}

test("egress：没带路由 407，白名单外 403，申请路由要令牌", async () => {
  const target = (await fs.readFile(PROBE_FILE, "utf8")).trim();
  assert.equal(await rawConnect(target), 407);
  assert.equal(await rawConnect(target, `Proxy-Authorization: Basic ${Buffer.from("route:" + "0".repeat(32)).toString("base64")}\r\n`), 407);
  assert.equal(await rawConnect("example.com:443"), 403);
  assert.equal(await rawConnect(target.replace(/\d+$/, "22")), 403);
  const res = await fetch(`http://127.0.0.1:${egressPort}/routes`, { method: "POST", body: "{}" });
  assert.equal(res.status, 401);
});
