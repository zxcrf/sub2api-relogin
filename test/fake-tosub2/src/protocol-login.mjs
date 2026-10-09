// 测试替身：按密码决定成功、密码错误或挂起，用来验证服务的协议和错误处理。
// 测试写了 ../probe-target 时，还会经 --proxy 开一条隧道到那个地址并收发一次，验证出网路由真的通。
import fs from "node:fs/promises";
import net from "node:net";
const arg = (name) => process.argv[process.argv.indexOf(name) + 1];
const email = arg("--email");
const pw = process.env.CHATGPT_LOGIN_PASSWORD;
if (process.env.RELOGIN_TOKEN_FILE || process.env.SECRET_PARENT) { console.error("env leaked"); process.exit(9); }
const proxyArg = process.argv.includes("--proxy") ? arg("--proxy") : "";
const target = await fs.readFile(new URL("../probe-target", import.meta.url), "utf8").catch(() => "");
if (proxyArg && target.trim()) await probe(new URL(proxyArg), target.trim());
if (pw === "slow") await new Promise((r) => setTimeout(r, 2000));
if (pw === "wrong") { console.error("Password was rejected " + pw); process.exit(2); }
if (pw === "hang") { setInterval(() => {}, 1000); await new Promise(() => {}); }
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const at = `${b64({alg:"none"})}.${b64({exp: 2000000000, "https://api.openai.com/profile": {email}})}.sig`;
await fs.writeFile(arg("--sub2api-out"), JSON.stringify({accounts: [{credentials: {access_token: at, refresh_token: "rt", id_token: "it", chatgpt_account_id: "acc-1", email}, extra: {client_id: "app_x", chatgpt_user_id: "u1"}}]}));

function probe(proxy, target) {
  return new Promise((resolve) => {
    const failed = (why) => { console.error("probe failed: " + why); process.exit(7); };
    const socket = net.connect({ host: proxy.hostname, port: Number(proxy.port) });
    socket.on("error", (err) => failed(err.message));
    socket.once("connect", () => {
      const auth = Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64");
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: Basic ${auth}\r\n\r\n`);
    });
    let buf = "";
    let opened = false;
    socket.on("data", (chunk) => {
      buf += chunk.toString("latin1");
      if (!opened) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        if (!/^HTTP\/1\.1 200/.test(buf)) failed(buf.split("\r\n")[0]);
        opened = true;
        buf = buf.slice(end + 4);
        socket.write("ping\n");
      }
      if (buf.includes("ping\n")) {
        socket.destroy();
        resolve();
      }
    });
  });
}
