#!/bin/sh
# 部署后自检：服务可达、鉴权生效、出网只能走白名单、能查到 sub2api 里的账号代理。
# 每项打印 PASS/FAIL，有失败则退出码非 0。不会发起任何账号登录。
# 用法：sudo ./check.sh                 全部检查
#       sudo ./check.sh 邮箱 [邮箱…]    另外列出这些账号重登时会走哪个出口（只查 sub2api，不登录）
set -u
cd "$(dirname "$0")"
[ -f .env ] && . ./.env
IP=${RELOGIN_IP:-172.31.250.10}
GW=${RELOGIN_GATEWAY:-172.31.250.1}
TOKEN_PATH=${RELOGIN_TOKEN_PATH:-/etc/sub2api-relogin/token}
BASE="http://$IP:18790"
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1（期望 $3，实际 $2）"; fail=1; fi; }

check "宿主机访问 $BASE/healthz" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/healthz")" 200
check "不带令牌被拒绝" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "$BASE/api/v1/relogin" -d '{}')" 401
TOKEN=$(cat "$TOKEN_PATH" 2>/dev/null)
check "读取令牌文件 $TOKEN_PATH" "$([ -n "$TOKEN" ] && echo ok)" ok
check "带令牌访问测活接口" "$(curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" -X POST "$BASE/api/v1/relogin/probe" -d '{}')" '{"status":"active","mode":"passive"}'

ACCOUNT_PROXY=${RELOGIN_ACCOUNT_PROXY:-on}
# 宿主机自己访问 OpenAI 的出口 IP（sub2api 没配代理的账号就是从这里出去的）
HOST_EXIT=$(curl -s --max-time 10 https://chatgpt.com/cdn-cgi/trace | sed -n 's/^ip=//p')
docker compose exec -T -e ACCOUNT_PROXY="$ACCOUNT_PROXY" -e EGRESS="http://$GW:8888" -e HOST_EXIT="$HOST_EXIT" relogin python3 - "$@" <<'PY' || fail=1
import json, os, socket, sys, urllib.error, urllib.request
TOKEN = open("/run/secrets/relogin-token").read().strip()
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def route(email, mode):
    req = urllib.request.Request(os.environ["EGRESS"] + "/routes", method="POST",
        data=json.dumps({"email": email, "mode": mode}).encode(),
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        return json.load(direct.open(req, timeout=30))
    except urllib.error.HTTPError as e:
        return json.load(e)
    except Exception as e:
        return {"error": {"code": "egress_unreachable: " + str(e)[:80]}}
r = route("relogin-selfcheck@example.invalid", "direct")
EGRESS_HOSTPORT = os.environ["EGRESS"].split("//", 1)[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": "http://route:%s@%s" % (r.get("route", "none"), EGRESS_HOSTPORT)}))
noroute = urllib.request.build_opener(urllib.request.ProxyHandler({"https": os.environ["EGRESS"]}))
def via_proxy(url, opener=opener):
    try:
        opener.open(url, timeout=15)
        return "connected"
    except urllib.error.HTTPError:
        return "connected"          # 拿到了目标站的 HTTP 响应（Cloudflare 对脚本回 403 也算连通）
    except Exception as e:
        text = str(e)
        if "403" in text: return "filtered"
        if "407" in text: return "no_route"
        return "error: " + text[:80]
failed = False
def check(name, got, want):
    global failed
    ok = got == want
    failed |= not ok
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"（期望 {want}，实际 {got}）"))
check("egress 发放直连路由", "ok" if r.get("route") else str(r.get("error")), "ok")
for host in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
    check(f"经代理可连 {host}", via_proxy(f"https://{host}/"), "connected")
for host in ("example.com", "session.ameng2027.xyz"):
    check(f"经代理拒绝 {host}", via_proxy(f"https://{host}/"), "filtered")
check("不带路由的隧道被拒绝", via_proxy("https://chatgpt.com/", noroute), "no_route")
# 直连出口必须和宿主机（sub2api）一致，包括 IPv4 / IPv6
try:
    trace = opener.open("https://chatgpt.com/cdn-cgi/trace", timeout=15).read().decode()
    exit_ip = next((l[3:] for l in trace.splitlines() if l.startswith("ip=")), "?")
except Exception as e:
    exit_ip = "error: " + str(e)[:60]
check("直连出口与宿主机一致（%s）" % (os.environ.get("HOST_EXIT") or "宿主机未取到"), exit_ip, os.environ.get("HOST_EXIT") or "宿主机未取到")
if os.environ.get("ACCOUNT_PROXY", "on").lower() != "off":
    # 查一个不存在的账号：能得到 account_not_found，说明 egress 连得上 sub2api、管理密钥有效
    got = route("relogin-selfcheck@example.invalid", "account")
    check("egress 能用管理密钥查 sub2api 账号", got.get("reason") or str(got.get("error")), "account_not_found")
for email in sys.argv[1:]:
    got = route(email.strip().lower(), "account" if os.environ.get("ACCOUNT_PROXY", "on").lower() != "off" else "direct")
    if got.get("route"):
        via = got.get("via")
        where = "%s://%s:%s" % (via["protocol"], via["host"], via["port"]) if via else "本机出口直连"
        print(f"INFO  {email} → {where}（{got.get('reason')}）")
    else:
        print(f"FAIL  {email} → 查不到出口：{got.get('error', {}).get('code')}")
        failed = True
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    check("不经代理直连外网被阻断", "connected", "blocked")
except OSError:
    check("不经代理直连外网被阻断", "blocked", "blocked")
sys.exit(1 if failed else 0)
PY

[ "$fail" = 0 ] && echo "全部通过" || echo "有检查未通过"
exit "$fail"
