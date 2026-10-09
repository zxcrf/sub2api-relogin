// 测试替身：按密码决定成功、密码错误或挂起，用来验证服务的协议和错误处理。
import fs from "node:fs/promises";
const arg = (name) => process.argv[process.argv.indexOf(name) + 1];
const email = arg("--email");
const pw = process.env.CHATGPT_LOGIN_PASSWORD;
if (process.env.RELOGIN_TOKEN_FILE || process.env.SECRET_PARENT) { console.error("env leaked"); process.exit(9); }
if (pw === "slow") await new Promise((r) => setTimeout(r, 2000));
if (pw === "wrong") { console.error("Password was rejected " + pw); process.exit(2); }
if (pw === "hang") { setInterval(() => {}, 1000); await new Promise(() => {}); }
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const at = `${b64({alg:"none"})}.${b64({exp: 2000000000, "https://api.openai.com/profile": {email}})}.sig`;
await fs.writeFile(arg("--sub2api-out"), JSON.stringify({accounts: [{credentials: {access_token: at, refresh_token: "rt", id_token: "it", chatgpt_account_id: "acc-1", email}, extra: {client_id: "app_x", chatgpt_user_id: "u1"}}]}));
