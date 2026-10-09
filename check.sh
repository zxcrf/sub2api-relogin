#!/bin/sh
# 部署后自检：服务可达、鉴权生效、出网只能走白名单。每项打印 PASS/FAIL，有失败则退出码非 0。
# 不会发起任何账号登录。用法：sudo ./check.sh
set -u
cd "$(dirname "$0")"
[ -f .env ] && . ./.env
IP=${RELOGIN_IP:-172.31.250.10}
TOKEN_PATH=${RELOGIN_TOKEN_PATH:-/etc/sub2api-relogin/token}
BASE="http://$IP:18790"
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1（期望 $3，实际 $2）"; fail=1; fi; }

check "宿主机访问 $BASE/healthz" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/healthz")" 200
check "不带令牌被拒绝" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "$BASE/api/v1/relogin" -d '{}')" 401
TOKEN=$(cat "$TOKEN_PATH" 2>/dev/null)
check "读取令牌文件 $TOKEN_PATH" "$([ -n "$TOKEN" ] && echo ok)" ok
check "带令牌访问测活接口" "$(curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" -X POST "$BASE/api/v1/relogin/probe" -d '{}')" '{"status":"active","mode":"passive"}'

docker compose exec -T relogin python3 - <<'PY' || fail=1
import socket, sys, urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": "http://egress:8888"}))
def via_proxy(url):
    try:
        opener.open(url, timeout=15)
        return "connected"
    except urllib.error.HTTPError:
        return "connected"          # 拿到了目标站的 HTTP 响应（Cloudflare 对脚本回 403 也算连通）
    except Exception as e:
        return "filtered" if "403 Filtered" in str(e) else "error: " + str(e)[:80]
failed = False
def check(name, got, want):
    global failed
    ok = got == want
    failed |= not ok
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"（期望 {want}，实际 {got}）"))
for host in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
    check(f"经代理可连 {host}", via_proxy(f"https://{host}/"), "connected")
for host in ("example.com", "session.ameng2027.xyz"):
    check(f"经代理拒绝 {host}", via_proxy(f"https://{host}/"), "filtered")
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    check("不经代理直连外网被阻断", "connected", "blocked")
except OSError:
    check("不经代理直连外网被阻断", "blocked", "blocked")
sys.exit(1 if failed else 0)
PY

[ "$fail" = 0 ] && echo "全部通过" || echo "有检查未通过"
exit "$fail"
