#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把一串 16 进制字节逐个与 0xAA 做按位异或（XOR）。

所有内容均硬编码，不读取任何输入 / 参数 / 文件。
注意：原始串中有两处漏写了逗号（"9Bh 87h"、"93h 9Ah"），
      这里按“两个独立字节”处理（用逗号或空白切分都一样）。
"""

import re

# ===== 硬编码 1：原始 16 进制字节串（与给定内容逐字一致）=====
RAW = (
    "0CCh, 0C6h, 0CBh, 0CDh, 0D1h, 9Dh, 0CFh, 99h, 0CBh, 93h, "
    "0CCh, 98h, 0C9h, 87h, 0C8h, 92h, 9Eh, 9Bh 87h, 9Eh, 0CEh, "
    "9Ch, 9Dh, 87h, 0CBh, 9Ah, 0CFh, 9Fh, 87h, 9Bh, 0CCh, 9Ch, "
    "0C9h, 92h, 0C8h, 99h, 93h 9Ah, 0CEh, 98h, 9Eh, 0D7h, 16h"
)

# ===== 硬编码 2：异或密钥 =====
KEY = 0xAA


def parse_bytes(raw: str):
    """把 '0CCh, 9Dh 87h' 这类文本切成 int 列表。

    兼容三种写法：0CCh / 9Dh（汇编风格，尾部 h）
                  0xCC / 0x9D（Python 风格）
                  204 / 157（纯十进制会被当十进制，不推荐混用）
    分隔符可以是逗号、空格或换行。
    """
    out = []
    for tok in re.split(r"[,\s]+", raw.strip()):
        if not tok:
            continue
        t = tok.lower()
        if t.startswith("0x"):
            out.append(int(t, 16))
        elif t.endswith("h"):
            out.append(int(t[:-1], 16))
        else:
            out.append(int(t, 16))
    return out


def main() -> None:
    data = parse_bytes(RAW)

    xored = [b ^ KEY for b in data]

    print("密钥 KEY = 0x%02X" % KEY)
    print("输入字节数 = %d" % len(data))
    print()

    print("原始字节 :")
    print("  " + " ".join("%02X" % b for b in data))
    print()

    print("异或结果 :")
    print("  " + " ".join("%02X" % b for b in xored))
    print()

    # 可打印字符还原成文本，不可打印的显示为 '.'
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in xored)
    print("可打印还原 :")
    print("  " + text)
    print()

    # 只取可打印部分拼成最终字符串（额外给出，便于直接使用）
    printable = "".join(chr(b) for b in xored if 32 <= b < 127)
    print("可打印拼接 :")
    print("  " + printable)

    # 非可打印字节单独报出来，避免被悄悄丢掉
    weird = [(i, b, b ^ KEY) for i, b in enumerate(data) if not (32 <= (b ^ KEY) < 127)]
    if weird:
        print()
        print("非可打印字节 :")
        for i, b, x in weird:
            print("  第 %d 个字节: 0x%02X ^ 0x%02X = 0x%02X" % (i + 1, b, KEY, x))


if __name__ == "__main__":
    main()
