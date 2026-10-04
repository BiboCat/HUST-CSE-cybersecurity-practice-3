# -*- coding: utf-8 -*-
"""
get_flag.py  —— 由 check_flag 的 key 表反推 flag
    校验逻辑:  (input[i] ^ 0x7C) == key[i]        i = 0..41
    反推:      flag[i] = key[i] ^ 0x7C

用法: python get_flag.py
"""

# ============================== 硬编码区 ==============================
KEY = [
    0x1A, 0x10, 0x1D, 0x1B, 0x07, 0x1A, 0x4D, 0x1F, 0x4F, 0x19, 0x49,
    0x1E, 0x4B, 0x51, 0x4E, 0x18, 0x48, 0x1D, 0x51, 0x48, 0x45, 0x4A,
    0x44, 0x51, 0x44, 0x1D, 0x4C, 0x1F, 0x51, 0x4A, 0x19, 0x45, 0x1E,
    0x4F, 0x1A, 0x4B, 0x4D, 0x49, 0x18, 0x4E, 0x4C, 0x01,
]

XOR_KEY = 0x7C
# =====================================================================


def get_flag(key, xk):
    return bytes(b ^ xk for b in key)


if __name__ == "__main__":
    flag = get_flag(KEY, XOR_KEY)

    print(f"key length : {len(KEY)}")
    print(f"flag       : {flag.decode()}")
    print(f"flag hex   : {flag.hex(' ').upper()}")

    # 自检: 用校验函数的逻辑验证一遍
    ok = all((c ^ XOR_KEY) == k for c, k in zip(flag, KEY)) and len(flag) == len(KEY)
    print(f"[{'OK' if ok else 'FAIL'}] check: (flag[i] ^ 0x7C) == key[i] for all i")
