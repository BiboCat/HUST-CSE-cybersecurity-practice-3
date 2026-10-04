# -*- coding: utf-8 -*-
"""
final_oprate 的解密脚本
  加密:  c = S( ROL1(x) )       即 先整体循环左移1位, 再半字节查S盒
  解密:  x = ROL7( Sinv(c) )    即 先查逆S盒, 再整体循环左移7位

用法: python flag_decrypt.py
"""

# ============================ 硬编码区 ============================
# 逆 S 盒 (16 项, 题目给出, 内部下标 0..15 -> 值)
INV_SBOX = [0xB, 0x5, 0x8, 0xE, 0x3, 0xF, 0xA, 0x0,
            0xD, 0x7, 0x2, 0x6, 0xC, 0x1, 0x9, 0x4]

# 目标密文 flag
CIPHER = [
    0xCC, 0x82, 0xCA, 0xC3, 0x5B, 0x97, 0xBF, 0xCF, 0xB6, 0xC6, 0xB7,
    0xB2, 0xCC, 0x16, 0xCA, 0xBB, 0x9A, 0xBA, 0x16, 0xB2, 0xCB, 0xB3,
    0xBC, 0x16, 0xC2, 0xB7, 0xC6, 0x97, 0x16, 0xB3, 0xCC, 0xBB, 0xCF,
    0xBF, 0xCB, 0x9A, 0xCA, 0xBA, 0xB6, 0xB7, 0xBC, 0x56,
]
# =================================================================


# --- 8 位循环移位 ---
def rol1(b):
    """循环左移 1 位"""
    return ((b << 1) | (b >> 7)) & 0xFF


def ror1(b):
    """循环右移 1 位 (等价于循环左移 7 位)"""
    return ((b >> 1) | ((b & 1) << 7)) & 0xFF


def rol7(b):
    """循环左移 7 位"""
    return ((b << 7) | (b >> 1)) & 0xFF


# --- 逆 S 盒: 两个半字节分别查表, 再拼回一个字节 ---
def inv_sub(b):
    hi = (b >> 4) & 0xF          # 高半字节
    lo = b & 0xF                 # 低半字节
    return INV_SBOX[lo] | (INV_SBOX[hi] << 4)


def decrypt(data, rot):
    return bytes(rot(inv_sub(b)) for b in data)


def show(title, data):
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in data)
    print(f"{title:<28} {txt}")
    print(f"{'':<28} {data.hex(' ').upper()}")


if __name__ == "__main__":
    print(f"cipher length: {len(CIPHER)} bytes\n")

    show("inv_sbox + rol7:", decrypt(CIPHER, rol7))
    show("inv_sbox + rol1:", decrypt(CIPHER, rol1))
    show("inv_sbox only:", decrypt(CIPHER, lambda b: b))
    show("rol7 only:", bytes(rol7(b) for b in CIPHER))
    show("rol1 only:", bytes(rol1(b) for b in CIPHER))
