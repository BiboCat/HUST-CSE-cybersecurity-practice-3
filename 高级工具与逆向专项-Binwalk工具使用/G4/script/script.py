#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
device.img 载荷提取 + AES-256-ECB 解密
====================================
用法: 把 device.img 和本脚本放同一目录, 运行  ->  python extract_decrypt.py

  1. 提取偏移 0x40000 起 0x10000 字节  -> payload.enc.bin
  2. 读偏移 0x50000 处 JSON 的 decrypt_key
  3. AES-256-ECB 解密                 -> payload.dec.bin
  4. 把明文打印出来

依赖: 无 (AES-256 纯 Python, 加载时用 FIPS-197 标准向量自校验)
"""

import json
import sys
from pathlib import Path

CT_OFFSET = 0x40000
CT_LENGTH = 0x10000
CFG_OFFSET = 0x50000

HERE = Path(__file__).resolve().parent
IMG = HERE / "device.img"

# ------------------------------------------------------------------ AES-256


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    box = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        box[p] = (q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)) ^ 0x63
        if p == 1:
            break
    box[0] = 0x63
    return box


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


MUL = {b: [_gmul(a, b) for a in range(256)] for b in (2, 3, 9, 11, 13, 14)}


class AES256:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError(f"AES-256 需要 32 字节密钥, 收到 {len(key)}")
        nk, nr = 8, 14
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= RCON[i // nk - 1]
            elif i % nk == 4:
                t = [SBOX[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        self.w = w

    def _ark(self, st, rnd):
        for c in range(4):
            kw = self.w[4 * rnd + c]
            b = 4 * c
            st[b] ^= kw[0]
            st[b + 1] ^= kw[1]
            st[b + 2] ^= kw[2]
            st[b + 3] ^= kw[3]

    def decrypt_block(self, blk):
        st = list(blk)
        self._ark(st, 14)
        m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
        for rnd in range(13, 0, -1):
            st[1], st[5], st[9], st[13] = st[13], st[1], st[5], st[9]
            st[2], st[6], st[10], st[14] = st[10], st[14], st[2], st[6]
            st[3], st[7], st[11], st[15] = st[7], st[11], st[15], st[3]
            for i in range(16):
                st[i] = INV_SBOX[st[i]]
            self._ark(st, rnd)
            for c in range(4):
                i = 4 * c
                a0, a1, a2, a3 = st[i], st[i + 1], st[i + 2], st[i + 3]
                st[i] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
                st[i + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
                st[i + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
                st[i + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
        st[1], st[5], st[9], st[13] = st[13], st[1], st[5], st[9]
        st[2], st[6], st[10], st[14] = st[10], st[14], st[2], st[6]
        st[3], st[7], st[11], st[15] = st[7], st[11], st[15], st[3]
        for i in range(16):
            st[i] = INV_SBOX[st[i]]
        self._ark(st, 0)
        return bytes(st)

    def encrypt_block(self, blk):
        """只给启动自校验用。"""
        st = list(blk)
        self._ark(st, 0)
        m2, m3 = MUL[2], MUL[3]
        for rnd in range(1, 14):
            for i in range(16):
                st[i] = SBOX[st[i]]
            st[1], st[5], st[9], st[13] = st[5], st[9], st[13], st[1]
            st[2], st[6], st[10], st[14] = st[10], st[14], st[2], st[6]
            st[3], st[7], st[11], st[15] = st[15], st[3], st[7], st[11]
            for c in range(4):
                i = 4 * c
                a0, a1, a2, a3 = st[i], st[i + 1], st[i + 2], st[i + 3]
                st[i] = m2[a0] ^ m3[a1] ^ a2 ^ a3
                st[i + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
                st[i + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
                st[i + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
            self._ark(st, rnd)
        for i in range(16):
            st[i] = SBOX[st[i]]
        st[1], st[5], st[9], st[13] = st[5], st[9], st[13], st[1]
        st[2], st[6], st[10], st[14] = st[10], st[14], st[2], st[6]
        st[3], st[7], st[11], st[15] = st[15], st[3], st[7], st[11]
        self._ark(st, 14)
        return bytes(st)


def _selftest():
    """FIPS-197 附录 C.3 AES-256 向量, 跑不过直接崩。"""
    c = AES256(bytes(range(32)))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    if c.encrypt_block(pt) != want or c.decrypt_block(want) != pt:
        raise RuntimeError("AES 自校验失败")


_selftest()

# ------------------------------------------------------------------ 主流程


def main():
    if not IMG.is_file():
        sys.exit(f"[x] 找不到 {IMG}\n    请把 device.img 和本脚本放在同一目录。")

    data = IMG.read_bytes()

    # 1. 提取密文
    ct = data[CT_OFFSET:CT_OFFSET + CT_LENGTH]
    if len(ct) != CT_LENGTH:
        sys.exit(f"[x] 0x{CT_OFFSET:x} 处数据不足, 只有 {len(ct)} 字节")
    (HERE / "payload.enc.bin").write_bytes(ct)
    print(f"[1] 提取 0x{CT_OFFSET:x}-0x{CT_OFFSET + CT_LENGTH:x} "
          f"{len(ct)} 字节 -> payload.enc.bin")

    # 2. 读密钥
    end = data.index(b"}", CFG_OFFSET)
    cfg = json.loads(data[CFG_OFFSET:end + 1].decode())
    key = bytes.fromhex(cfg["decrypt_key"])
    print(f"[2] decrypt_key = {cfg['decrypt_key']}  ({len(key)} 字节)")

    # 3. AES-256-ECB 解密
    c = AES256(key)
    pt = b"".join(c.decrypt_block(ct[i:i + 16]) for i in range(0, len(ct), 16))
    (HERE / "payload.dec.bin").write_bytes(pt)
    print(f"[3] AES-256-ECB 解密完成 {len(pt)} 字节 -> payload.dec.bin")
    tail = pt[-1]
    if 1 <= tail <= 16 and pt[-tail:] == bytes([tail]) * tail:
        print(f"    (末尾 {tail} 字节是合法 PKCS#7 填充; 下面按原样输出)")

    # 4. 贴明文
    print("\n================ 明文 ================")
    print(pt.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
