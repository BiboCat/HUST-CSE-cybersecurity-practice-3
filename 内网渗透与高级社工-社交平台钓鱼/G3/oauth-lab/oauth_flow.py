#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oauth_flow.py —— OAuth 2.0 授权码流程测试台

把「五棒」流程脚本化，重点是：**自己去产生授权码，而不是去页面里爬一个。**

    第 1 棒  GET  /oauth/authorize      应用向平台请求开启 OAuth
             ↑ 关键：allow_redirects=False，只看 302 的 Location 头
    第 2 棒  （用户点同意 —— 本脚本不参与，由平台侧完成）
    第 3 棒  平台 302 回回调地址，授权码就在 Location 里
    第 4 棒  POST /oauth/token          code + client_secret 兑换 access_token
    第 5 棒  GET  <api_path>            Authorization: Bearer <token>

设计要点
--------
1. 零依赖：只用标准库 urllib，不需要 pip install。
2. 不跟随重定向：授权码是通过 302 的 Location 头送出来的，读头比爬页面稳得多。
3. state 当关联 ID：每次运行随机生成，回来时校验，顺便解决「哪个 code 是我的」。
4. redirect_uri 全程只有一个变量：第 1 棒和第 4 棒用的是同一个值，不做任何加工
   （这是 invalid_grant 的头号成因）。
5. 批量模式：一次跑一串 scope 候选，出一张对照表。

用法见 README.md
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
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------- 输出小工具

try:  # Windows 控制台默认可能是 GBK，中文会炸
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def disp_width(s: str) -> int:
    """按终端显示宽度算长度（中日韩字符占 2 列）"""
    w = 0
    for ch in s:
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def pad(s: str, width: int) -> str:
    return s + " " * max(0, width - disp_width(s))


def hr(char: str = "-", n: int = 78) -> str:
    return char * n


# ---------------------------------------------------------------- HTTP 层

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止 urllib 自动跟随 302 —— 我们要的就是那个 Location 头。

    返回 None 会让 urllib 认为「这个重定向我不处理」，
    于是落到默认错误处理器，抛出一个 HTTPError，
    我们再从 HTTPError 里把状态码和头读出来。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_request(method, url, headers=None, data=None,
                 follow_redirects=False, timeout=15, insecure=False):
    """发一个请求，返回 (status, headers_lower_dict, body_bytes, final_url)。

    故意不抛异常：3xx / 4xx / 5xx 都当普通结果返回，交给调用方判断。
    """
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    handlers = []
    if not follow_redirects:
        handlers.append(_NoRedirect)
    if insecure:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)

    try:
        resp = opener.open(req, timeout=timeout)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, hdrs, resp.read(), resp.geturl()
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, hdrs, body, url
    except urllib.error.URLError as e:
        raise RuntimeError(f"连不上 {url}：{e.reason}") from e


def body_text(body: bytes, limit: int = 4000) -> str:
    t = body.decode("utf-8", "replace")
    return t if len(t) <= limit else t[:limit] + f"\n...（已截断，共 {len(t)} 字符）"


# ---------------------------------------------------------------- 解析工具

def parse_callback(location: str) -> dict:
    """从 Location（或回显 URL）里取出 code / error / state。

    query 和 fragment 都看 —— fragment 是给隐式流程（response_type=token）准备的。
    """
    out = {"raw": location, "code": None, "error": None,
           "error_description": None, "state": None, "access_token": None}
    if not location:
        return out
    p = urllib.parse.urlparse(location)
    for blob in (p.query, p.fragment):
        if not blob:
            continue
        qs = urllib.parse.parse_qs(blob, keep_blank_values=True)
        for k in ("code", "error", "error_description", "state",
                  "access_token", "token_type", "expires_in", "scope"):
            if k in qs and out.get(k) is None:
                out[k] = qs[k][0]
    return out


def decode_jwt_payload(token: str):
    """只解码 JWT 的 payload，不验签。用于看 scope / exp / sub 等声明。"""
    if not token or token.count(".") != 2:
        return None
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(part)
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception as e:
        return {"_decode_error": str(e)}


def diagnose_no_redirect(status: int, hdrs: dict, body: bytes) -> list:
    """没拿到 302 时，给点人话诊断。"""
    text = body_text(body, 20000)
    low = text.lower()
    msgs = []

    if status in (301, 302, 303, 307, 308):
        msgs.append("是重定向，但没有 Location 头 —— 平台行为异常，把原始响应留着")
        return msgs
    if status == 200:
        if "<form" in low or "password" in low or "登录" in text or "login" in low:
            msgs.append("拿到 200 HTML（疑似登录页）→ Cookie 很可能失效或没带上")
            msgs.append("重新登录平台，F12 → Application → Cookies，抄最新的会话 Cookie")
        else:
            msgs.append("拿到 200 —— 可能是同意页 / 回显页，需要人工点一下才能产生 code")
            msgs.append("把这个 HTML 存下来看，找里面的 <form> 和隐藏字段")
    elif status == 400:
        msgs.append("400：参数层面被拒。重点查 scope 名是否存在、redirect_uri 与登记值是否一致")
    elif status == 401:
        msgs.append("401：客户端认证失败。查 client_id / client_secret")
    elif status == 403:
        msgs.append("403：权限不足。可能是应用未上线 / 不在测试用户名单 / scope 未获批")
    elif status == 404:
        msgs.append("404：路径不对。确认 authorize_path 是否正确")
    else:
        msgs.append(f"未预期的状态码 {status}")
    return msgs


# ---------------------------------------------------------------- 流程本体

EXTRA_PARAMS = (
    # 可选附加参数：配置里填了就带上
    "prompt", "login_hint", "nonce", "response_mode", "access_type", "display",
)


def build_authorize_url(cfg: dict, scope: str, state: str) -> str:
    params = {
        "response_type": cfg.get("response_type") or "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],   # ← 和 token 步用的是同一个变量
        "scope": scope,
        "state": state,
    }
    if cfg.get("code_challenge"):
        params["code_challenge"] = cfg["code_challenge"]
        params["code_challenge_method"] = cfg.get("code_challenge_method") or "S256"
    for k in EXTRA_PARAMS:
        if cfg.get(k):
            params[k] = cfg[k]

    # 用 urlencode 编码 —— 绝不手工拼 %3A%2F%2F（双重编码就是这么来的）
    return cfg["base_url"].rstrip("/") + cfg["authorize_path"] + "?" + urllib.parse.urlencode(params)


def step1_get_code(cfg: dict, scope: str, verbose: bool):
    """第 1、2、3 棒：发 authorize 请求 → 从 302 的 Location 里取 code。"""
    state = secrets.token_urlsafe(12)
    url = build_authorize_url(cfg, scope, state)

    headers = {
        "User-Agent": cfg["user_agent"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]

    if verbose:
        print("\n  [→] GET " + url)
        for k, v in headers.items():
            shown = v if k.lower() != "cookie" else v[:60] + ("..." if len(v) > 60 else "")
            print(f"      {k}: {shown}")

    status, hdrs, body, _ = http_request(
        "GET", url, headers, None,
        follow_redirects=False, timeout=cfg["timeout"], insecure=cfg.get("insecure_tls", False),
    )
    location = hdrs.get("location")

    if verbose:
        print(f"  [←] {status}")
        if location:
            print(f"      Location: {location}")

    info = {"state_sent": state, "status": status, "location": location,
            "cb": parse_callback(location or ""), "notes": []}

    if status not in (301, 302, 303, 307, 308):
        info["notes"] = diagnose_no_redirect(status, hdrs, body)
        info["raw_body"] = body_text(body, 1500)
        return None, info

    cb = info["cb"]
    if cb["error"]:
        info["notes"].append(f"平台通过回调返回了错误：error={cb['error']}"
                             + (f"，{cb['error_description']}" if cb["error_description"] else ""))
        return None, info
    if not cb["code"]:
        loc_low = (location or "").lower()
        if any(w in loc_low for w in ("login", "signin", "sign-in", "auth/login", "passport")):
            info["notes"].append(f"被弹到登录页（Location: {location}）→ 未登录 / Cookie 失效")
            info["notes"].append("重新在浏览器登录平台，F12 → Application → Cookies，"
                                 "把会话 Cookie 原文抄进 --cookie（注意别漏了分号后的项）")
        elif "consent" in loc_low or "authorize" in loc_low:
            info["notes"].append(f"Location 指向同意/授权页（{location}）→ 第二棒需要人工点一次同意")
            info["notes"].append("把那个页面存下来，找 <form> 的 action 和隐藏字段，"
                                 "或者试 --prompt none 看能不能跳过")
        else:
            info["notes"].append(f"是 302 但 Location 里既没有 code 也没有 error：{location}")
        return None, info

    # state 校验：协议要求应用做，同时也是「这个 code 是不是我这次请求产生的」的答案
    if cb["state"] and cb["state"] != state:
        info["notes"].append(f"⚠️ state 不匹配：发出去 {state!r}，回来 {cb['state']!r}")
    return cb["code"], info


def step4_exchange(cfg: dict, code: str, verbose: bool):
    """第 4 棒：拿 code 兑换 access_token。"""
    url = cfg["base_url"].rstrip("/") + cfg["token_path"]

    form = {
        "grant_type": "authorization_code",
        "code": code,
        # ★ 原样使用同一个变量，不做任何「规范化」
        "redirect_uri": cfg["redirect_uri"],
        "client_id": cfg["client_id"],
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": cfg["user_agent"],
    }

    auth_style = (cfg.get("auth_style") or "body").lower()
    if auth_style == "basic":
        # 有的平台只认 HTTP Basic，不认 body 里的 client_secret
        raw = f"{cfg['client_id']}:{cfg.get('client_secret') or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    elif cfg.get("client_secret"):
        form["client_secret"] = cfg["client_secret"]

    if cfg.get("code_verifier"):
        form["code_verifier"] = cfg["code_verifier"]

    # urlencode 负责所有编码，我们只提供「解码后的原值」
    data = urllib.parse.urlencode(form).encode()

    if verbose:
        print("\n  [→] POST " + url)
        for k, v in form.items():
            if k in ("client_secret", "code_verifier"):
                v = v[:6] + "..." if v else v
            print(f"      {k}={v}")

    status, hdrs, body, _ = http_request(
        "POST", url, headers, data,
        follow_redirects=True, timeout=cfg["timeout"], insecure=cfg.get("insecure_tls", False),
    )
    text = body.decode("utf-8", "replace")

    if verbose:
        print(f"  [←] {status}")
        print("      " + text[:800].replace("\n", "\n      "))

    try:
        tok = json.loads(text)
    except Exception:
        return None, {"status": status, "raw": body_text(body, 1500),
                      "notes": [f"返回不是 JSON（{status}）。看原文。"]}

    if isinstance(tok, dict) and tok.get("access_token"):
        return tok, {"status": status}

    notes = []
    if isinstance(tok, dict):
        err = tok.get("error")
        if err:
            notes.append(f"平台返回 error={err}" + (f"：{tok.get('error_description')}" if tok.get("error_description") else ""))
            if err == "invalid_grant":
                notes.append("→ invalid_grant 排查顺序：① code 用过/过期 ② redirect_uri 两次不一致 ③ 跨客户端 ④ 缺 code_verifier")
            elif err == "invalid_client":
                notes.append("→ 公章 / 客户端身份问题：试 --auth-style basic，检查 secret 首尾空格")
            elif err == "invalid_scope":
                notes.append("→ 这个 scope 名不被接受（不存在，或该客户端没资格申请）")
            elif err == "invalid_request":
                notes.append("→ 请求格式问题：确认 Content-Type、参数在 body 里、grant_type 拼写")
    return None, {"status": status, "raw": body_text(body, 1500), "notes": notes}


def step5_call_api(cfg: dict, token: str, paths, verbose: bool):
    """第 5 棒：带着 Bearer token 敲受保护资源。"""
    out = []
    for p in paths:
        url = cfg["base_url"].rstrip("/") + p
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, */*",
            "User-Agent": cfg["user_agent"],
        }
        if verbose:
            print(f"\n  [→] GET {url}\n      Authorization: Bearer {token[:12]}...")
        status, hdrs, body, _ = http_request(
            "GET", url, headers, None,
            follow_redirects=True, timeout=cfg["timeout"], insecure=cfg.get("insecure_tls", False),
        )
        entry = {
            "path": p,
            "status": status,
            "www_authenticate": hdrs.get("www-authenticate"),
            "content_type": hdrs.get("content-type"),
            "body": body_text(body, 4000),
        }
        if verbose:
            print(f"  [←] {status}")
            if entry["www_authenticate"]:
                print(f"      WWW-Authenticate: {entry['www_authenticate']}")
            print("      " + entry["body"][:800].replace("\n", "\n      "))
        out.append(entry)
    return out


def run_flow(cfg: dict, scope: str, verbose: bool = False,
             dry_run: bool = False, do_introspect: bool = False) -> dict:
    """跑完整的一轮，返回结构化的结果（不管成败都返回）。"""
    res = {
        "scope_requested": scope, "ok": False, "stage": "init",
        "state": None, "code": None, "access_token": None, "token_type": None,
        "expires_in": None, "scope_granted": None, "refresh_token": None,
        "id_token": None, "jwt_claims": None, "api": [], "notes": [],
        "elapsed_ms": None,
    }
    t0 = time.time()

    try:
        # ---- 第 1~3 棒 ----
        code, info = step1_get_code(cfg, scope, verbose)
        res["state"] = info["state_sent"]
        res["notes"] += info["notes"]
        if not code:
            res["stage"] = "authorize"
            return res
        res["code"] = code
        res["stage"] = "authorized"

        if dry_run:
            res["ok"] = True
            res["stage"] = "dry-run(stopped after authorize)"
            return res

        # ---- 第 4 棒 ----
        tok, tinfo = step4_exchange(cfg, code, verbose)
        res["notes"] += tinfo.get("notes", [])
        if not tok:
            res["stage"] = "token"
            return res

        res["access_token"] = tok.get("access_token")
        res["token_type"] = tok.get("token_type")
        res["expires_in"] = tok.get("expires_in")
        res["scope_granted"] = tok.get("scope")
        res["refresh_token"] = tok.get("refresh_token")
        res["id_token"] = tok.get("id_token")
        res["stage"] = "token-ok"

        # 顺手解码 JWT，看真实签发了什么
        claims = decode_jwt_payload(res["access_token"])
        if claims:
            res["jwt_claims"] = claims
            if not res["scope_granted"]:
                res["scope_granted"] = claims.get("scope") or claims.get("scp")

        # ---- 第 5 棒 ----
        paths = cfg.get("api_paths") or ["/api/me"]
        res["api"] = step5_call_api(cfg, res["access_token"], paths, verbose)
        res["stage"] = "done"
        res["ok"] = True
        return res

    except RuntimeError as e:
        res["notes"].append(f"网络错误：{e}")
        res["stage"] = "network"
        return res
    finally:
        res["elapsed_ms"] = int((time.time() - t0) * 1000)


# ---------------------------------------------------------------- 结果呈现

def print_single(res: dict, cfg: dict, verbose: bool):
    print(hr("="))
    print(f" scope 请求：{res['scope_requested']}")
    print(hr("="))
    print(f"  阶段        : {res['stage']}")
    print(f"  耗时        : {res['elapsed_ms']} ms")
    if res["state"]:
        print(f"  state       : {res['state']}")
    if res["code"]:
        print(f"  授权码      : {res['code']}")
    if res["access_token"]:
        print(f"  access_token: {res['access_token']}")
        print(f"  token_type  : {res['token_type']}    expires_in: {res['expires_in']}")
    print(f"  请求的 scope: {res['scope_requested']}")
    print(f"  签发的 scope: {res['scope_granted']}")

    if res["scope_granted"] and res["scope_granted"] != res["scope_requested"]:
        print("  ⚠️ 请求的和签发的不一致 —— 平台做了过滤 / 降级，以「签发」为准")

    if res["jwt_claims"]:
        c = res["jwt_claims"]
        print("\n  JWT 声明（仅解码，未验签）：")
        for k in ("iss", "sub", "aud", "client_id", "scope", "scp", "exp", "iat"):
            if k in c:
                v = c[k]
                if k in ("exp", "iat") and isinstance(v, int):
                    v = f"{v}  ({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(v))})"
                print(f"    {k:<10}= {v}")

    for a in res["api"]:
        print(hr())
        print(f"  GET {a['path']}  →  {a['status']}")
        if a["www_authenticate"]:
            print(f"    WWW-Authenticate: {a['www_authenticate']}")
        print("    " + a["body"][:1200].replace("\n", "\n    "))

    if res["notes"]:
        print(hr())
        print("  备注 / 诊断：")
        for n in res["notes"]:
            print(f"    - {n}")
    print(hr("="))


def print_table(results: list):
    """批量模式的结果对照表 —— 一眼看出哪个 scope 有效。"""
    cols = [("scope", "scope 请求"), ("stage", "阶段"), ("granted", "签发 scope"),
            ("ms", "耗时"), ("note", "备注")]
    rows = []
    for r in results:
        note = ""
        if r["notes"]:
            note = r["notes"][0]
        if not note and r["api"]:
            note = f"api={r['api'][0]['status']}"
        rows.append([
            r["scope_requested"],
            r["stage"],
            str(r["scope_granted"] or ""),
            str(r["elapsed_ms"]),
            note,
        ])

    widths = []
    for i, (_, title) in enumerate(cols):
        w = disp_width(title)
        for row in rows:
            w = max(w, disp_width(row[i]))
        widths.append(min(w, 46))

    print()
    print(hr("=", sum(widths) + 3 * len(widths)))
    print("  " + "   ".join(pad(t, widths[i]) for i, (_, t) in enumerate(cols)))
    print(hr("-", sum(widths) + 3 * len(widths)))
    for row in rows:
        cells = []
        for i, c in enumerate(row):
            if disp_width(c) > widths[i]:
                c = c[: widths[i] - 2] + ".."
            cells.append(pad(c, widths[i]))
        print("  " + "   ".join(cells))
    print(hr("=", sum(widths) + 3 * len(widths)))
    print(f"  共 {len(rows)} 条")


# ---------------------------------------------------------------- 配置

DEFAULTS = {
    # ★ 平台地址是可选的：默认就是本题平台，用 --base-url 或 config.json 可以覆盖
    "base_url": "http://172.17.0.13:15633",
    "client_id": "",
    "client_secret": "",
    "redirect_uri": "",
    "scope": "profile",
    "cookie": "",
    "authorize_path": "/oauth/authorize",
    "token_path": "/oauth/token",
    "api_paths": ["/api/me"],
    "response_type": "code",
    "auth_style": "body",       # body | basic
    "timeout": 15,
    "insecure_tls": False,
    "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
}


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULTS)
    if path is None:
        for cand in ("config.json", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")):
            if os.path.isfile(cand):
                path = cand
                break
    if path:
        if not os.path.isfile(path):
            raise SystemExit(f"配置文件不存在：{path}")
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
        print(f"[i] 已加载配置：{path}")
    return cfg


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oauth_flow.py",
        description="OAuth 2.0 授权码流程测试台（五棒流程脚本化）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例
----
  # 最省事的验证：只跑第 1~3 棒，看能不能从 Location 里读到 code
  python oauth_flow.py --base-url http://172.17.0.13:15633 \\
      --client-id app_xxx --redirect-uri /oauth/cb/app_xxx \\
      --cookie "session=..." --dry-run -v

  # 跑完整流程
  python oauth_flow.py --config config.json --scope profile

  # 批量扫 scope 候选，出一张对照表
  python oauth_flow.py --config config.json --scope-file scopes.txt --json-out result.json
""")
    p.add_argument("--config", help="配置文件路径（默认自动找 ./config.json）")
    p.add_argument("--base-url", help="平台根地址，如 http://172.17.0.13:15633")
    p.add_argument("--client-id")
    p.add_argument("--client-secret")
    p.add_argument("--redirect-uri", help="★ 第1棒和第4棒共用这一个值，原样传递")
    p.add_argument("--scope", help="单个 scope（空格分隔的多个也可以）")
    p.add_argument("--scopes", help="逗号分隔的多个 scope，逐个跑完整流程")
    p.add_argument("--scope-file", help="每行一个 scope 的文件，逐个跑完整流程")
    p.add_argument("--cookie", help="会话 Cookie 原文（登录后从 F12 抄）")
    p.add_argument("--authorize-path", default=None)
    p.add_argument("--token-path", default=None)
    p.add_argument("--api-path", action="append", help="可重复：要敲的 API 路径，默认 /api/me")
    p.add_argument("--response-type", default=None, help="code（默认）/ token / code id_token")
    p.add_argument("--auth-style", choices=["body", "basic"], help="client_secret 放 body 还是用 HTTP Basic")
    p.add_argument("--code-verifier", help="上了 PKCE 时，兑换要带的 code_verifier")
    p.add_argument("--code-challenge", help="上了 PKCE 时，authorize 要带的 code_challenge")
    p.add_argument("--prompt", help="如 none / consent —— 影响「同意那一屏」")
    p.add_argument("--login-hint")
    p.add_argument("--timeout", type=int)
    p.add_argument("--delay", type=float, default=0.0, help="批量模式下每条之间的间隔秒数")
    p.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验")
    p.add_argument("--dry-run", action="store_true", help="只跑第 1~3 棒就停，用来验证 Cookie / 回调是否通")
    p.add_argument("--json-out", help="把结果写成 JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="打印每一条请求和响应")
    return p


def apply_overrides(cfg: dict, args) -> dict:
    mapping = {
        "base_url": args.base_url, "client_id": args.client_id,
        "client_secret": args.client_secret, "redirect_uri": args.redirect_uri,
        "scope": args.scope, "cookie": args.cookie,
        "authorize_path": args.authorize_path, "token_path": args.token_path,
        "response_type": args.response_type, "auth_style": args.auth_style,
        "code_verifier": args.code_verifier, "code_challenge": args.code_challenge,
        "prompt": args.prompt, "login_hint": args.login_hint,
        "timeout": args.timeout,
    }
    for k, v in mapping.items():
        if v is not None:
            cfg[k] = v
    if args.api_path:
        cfg["api_paths"] = args.api_path
    if args.insecure:
        cfg["insecure_tls"] = True
    return cfg


def collect_scopes(args, cfg) -> list:
    if args.scope_file:
        with open(args.scope_file, "r", encoding="utf-8") as f:
            items = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        return items
    if args.scopes:
        return [s.strip() for s in args.scopes.split(",") if s.strip()]
    return [cfg.get("scope") or "profile"]


def sanity_check(cfg: dict):
    """返回 (致命问题, 警告)。

    cookie 只算警告：有些平台不需要登录态（本地模拟平台就是），
    所以不能因为它就拒绝运行。
    """
    fatal, warn = [], []
    # base_url 有默认值，所以这里只在被显式清空时才报错
    if not cfg.get("base_url"):
        fatal.append("base_url 为空（去掉 --base-url 即可用默认的本题平台）")
    if not cfg.get("client_id"):
        fatal.append("缺少 client_id")
    if not cfg.get("redirect_uri"):
        fatal.append("缺少 redirect_uri（★ 必须和注册时填的一字不差，原样传）")
    if not cfg.get("cookie"):
        warn.append("没有 cookie —— 若平台要求登录态，第 1 棒会拿到登录页而不是 302")
    return fatal, warn


def main(argv=None) -> int:
    args = build_argparser().parse_args(argv)
    cfg = apply_overrides(load_config(args.config), args)

    problems, warnings = sanity_check(cfg)
    if problems:
        eprint("\n配置有问题：")
        for p in problems:
            eprint("  - " + p)
        eprint("\n用 --help 看示例，或复制 config.example.json 成 config.json 填好再跑。")
        return 2
    for w in warnings:
        eprint("[!] " + w)

    scopes = collect_scopes(args, cfg)
    batch = len(scopes) > 1

    if args.verbose:
        print("\n[i] 生效配置：")
        for k in ("base_url", "client_id", "redirect_uri", "authorize_path",
                  "token_path", "api_paths", "response_type", "auth_style"):
            print(f"    {k} = {cfg.get(k)}")
        print(f"    client_secret = {'(已设置)' if cfg.get('client_secret') else '(空)'}")
        print(f"    cookie        = {'(已设置)' if cfg.get('cookie') else '(空)'}")

    if batch:
        print(f"\n[i] 批量模式：{len(scopes)} 个 scope，逐个跑完整流程")

    results = []
    for i, sc in enumerate(scopes, 1):
        if batch:
            print(f"\n[{i}/{len(scopes)}] scope = {sc}")
        r = run_flow(cfg, sc, verbose=args.verbose, dry_run=args.dry_run)
        results.append(r)
        if not batch:
            print_single(r, cfg, args.verbose)
        else:
            mark = "OK " if r["ok"] else "-- "
            print(f"       {mark} stage={r['stage']} granted={r['scope_granted']!r} {r['elapsed_ms']}ms")
            for n in r["notes"]:
                print(f"       · {n}")
        if args.delay and i < len(scopes):
            time.sleep(args.delay)

    if batch:
        print_table(results)

    if args.json_out:
        payload = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": cfg.get("base_url"),
            "client_id": cfg.get("client_id"),
            "redirect_uri": cfg.get("redirect_uri"),
            "results": results,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n[i] 结果已写入 {args.json_out}")

    return 0 if any(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
