#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify() 求解器 —— 完全自包含，数据全部硬编码，不读取任何外部文件。

原始反编译逻辑:
    int verify(EVP_PKEY_CTX *flag, ...)                 // 第 1 参实为 char*
    {
      if (strlen(flag) != 0x2a) return 0;               // 必须 42 字符
      if (flag[0x29] != '}')    return 0;               // 尾字符必须是 '}'
      memcpy(buf, "flag{", 5);
      for (i = 0; i != 0x24; i++)                       // 36 轮
        buf[5+i] = decrypt_char(CONCAT11(HI[i], LO[i]) >> 2, LO[i] & 3);
      buf[41] = '}'; buf[42] = 0;
      return memcmp(flag, buf, 0x2b) == 0;              // 比较 43 字节
    }

    byte decrypt_char(int p, int sel)
    {
      int t = p * 7 + 3;
      return ((char)t + (char)(t / 0xfb) * 5
              ^ *(byte *)(*(long *)(strs.0 + p * 8) + sel)) & 0x7f;
    }

硬编码数据:
    ASSEMBLE_LO                36 字节 (dump @ 0x103060)
    ASSEMBLE_HI                36 字节 (dump @ 0x1030a0)
    strs.0 指向的 120 条字符串 (dump @ 0x1030c4 - 0x10328e)
"""

# ---------------------------------------------------------------------------
# strs.0 指向的 120 条字符串（顺序 = 地址升序 = g_str_119 ... g_str_000）
# 每条 "AAAA <hex>"：AAAA = 地址低 16 位，hex = 该字符串完整字节。
# ---------------------------------------------------------------------------
_RAW = [
    "30C4 77272200", "30C8 706e0000",
    "30CB 337f0600", "30CF 6657034600",
    "30D4 0a791d0a00", "30D9 40100000",
    "30DC 1618020b00", "30E1 6456481700",
    "30E6 4c785f00", "30EA 4d510000",
    "30ED 6a4d0000", "30F0 5e670000",
    "30F3 c4b1c9c300", "30F8 a7c6bb8f00",
    "30FD a2b68d00", "3101 9fd3d300",
    "3105 9384f99200", "310A bf8c0000",
    "310D b1920000", "3110 93e00000",
    "3113 f5b20000", "3116 d9d18300",
    "311A ed990000", "311D f3fc8be000",
    "3122 e5ef0000", "3125 b1a6e7bd00",
    "312A ecefbe00", "312E cdae0000",
    "3131 a9fa0000", "3134 cbbf0000",
    "3137 44160000", "313A 1b0c0000",
    "313D 495a1f00", "3141 3f040000",
    "3144 2414020000", "3149 3c370000",
    "314C 613b0d00", "3150 0a3f7200",
    "3154 26097a00", "3158 455a4500",
    "315C 166b0000", "315F 034a0000",
    "3162 19180000", "3165 7d6e660600",
    "316A 387c3300", "316E 622c7c00",
    "3172 31384300", "3176 516e553700",
    "317B 87d89dd300", "3180 d1d397b800",
    "3185 bf98b400", "3189 9cb1d7a600",
    "318E 97beea00", "3192 a0e00000",
    "3195 abe80000", "3198 fa950000",
    "319B a4ae9200", "319F e7820000",
    "31A2 c29e0000", "31A5 fc950000",
    "31A8 ddc4f400", "31AC f1b4b8c800",
    "31B1 a2f7d900", "31B5 ccb5f000",
    "31B9 fcf3da00", "31BD e0f30000",
    "31C0 1c3e3b0300", "31C5 0f252c4300",
    "31CA 40330000", "31CD 4f393500",
    "31D1 1276323f00", "31D6 6b150400",
    "31DA 196c0000", "31DD 0d062b6800",
    "31E2 08672600", "31E6 0a0e0000",
    "31E9 7b080000", "31EC 6d196c7f00",
    "31F1 66174100", "31F5 14640000",
    "31F8 41346000", "31FC 6b764400",
    "3200 682e453a00", "3205 4e3b4b00",
    "3209 97b2d400", "320D cfdfc5bf00",
    "3212 93d20000", "3215 cb98a6d700",
    "321A edecac9900", "321F f8ed0000",
    "3222 f5b885ea00", "3227 a4f60000",
    "322A b58f0000", "322D 8a8ff800",
    "3231 c4d5c800", "3235 9f9b9300",
    "3239 90f79b00", "323D b4acd100",
    "3241 f8bbd000", "3245 e2ec0000",
    "3248 d1a30000", "324B e0d60000",
    "324E 0e405800", "3252 424a5b00",
    "3256 0d204400", "325A 29105900",
    "325E 6b640000", "3261 24211b2000",
    "3266 7a623800", "326A 2f6e0000",
    "326D 78062f1000", "3272 494b0000",
    "3275 61030000", "3278 4f5b7300",
    "327C 7a7b0200", "3280 6f2b0000",
    "3283 7d613a00", "3287 5e5e5e00",
    "328B 33460000", "328E 3333333300",
]

STRINGS = [bytes.fromhex(_s.split(" ", 1)[1]) for _s in _RAW]
STRINGS.reverse()                       # 下标 0 -> g_str_000, 119 -> g_str_119

# ---------------------------------------------------------------------------
# 两个常量表
# ---------------------------------------------------------------------------
ASSEMBLE_LO = [0x04, 0x0c, 0x11, 0x18, 0x1d, 0x28, 0x2d, 0x3c, 0x55, 0x59, 0x70, 0x85, 0x99, 0x9d, 0xa0, 0xa5, 0xb0, 0xc0, 0xcc, 0xd8, 0xe4, 0xed, 0xf1, 0xf5, 0xf9, 0xfc, 0x00, 0x04, 0x09, 0x2d, 0x34, 0x59, 0x5d, 0x88, 0x8c, 0x94]

ASSEMBLE_HI = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]


# ---------------------------------------------------------------------------
# 解密原语
# ---------------------------------------------------------------------------
def decrypt_char(p, sel):
    """p = CONCAT11(HI,LO)>>2（原 10 bit 的高 8 位）；sel = LO & 3（低 2 位）。"""
    t = p * 7 + 3
    # 原式 (char)t + (char)(t/251)*5 在 8 位下 == (t + (t//251)*5) & 0xFF
    a = ((t & 0xFF) + ((t // 251) & 0xFF) * 5) & 0xFF
    return (a ^ STRINGS[p][sel]) & 0x7F


def build_expected():
    """复刻 verify() 在栈上拼出的 43 字节期望串（含结尾 NUL）。"""
    buf = bytearray(b"flag{")
    for i in range(36):
        code = ((ASSEMBLE_HI[i] & 3) << 8) | ASSEMBLE_LO[i]   # 10 bit 密文单元
        buf.append(decrypt_char(code >> 2, code & 3))
    buf += b"}\x00"
    return bytes(buf)


def verify(flag):
    """与原始 verify() 等价：strlen / 尾字符 / memcmp 43 字节。"""
    data = flag.encode()
    if len(data) != 0x2A:
        return False
    if data[0x29] != ord("}"):
        return False
    return data + b"\x00" == build_expected()


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    expected = build_expected()
    payload = expected[5:41].decode()
    flag = "flag{" + payload + "}"

    print("栈上期望串 (43 字节) :", expected[:42].decode())
    print("载荷       (36 字节) :", payload)
    print()
    print("逐字节解密:")
    for i in range(36):
        code = ((ASSEMBLE_HI[i] & 3) << 8) | ASSEMBLE_LO[i]
        p, sel = code >> 2, code & 3
        print("  i=%2d  HI=%02x LO=%02x  code=%3d  p=%3d sel=%d  ->  %r"
              % (i, ASSEMBLE_HI[i], ASSEMBLE_LO[i], code, p, sel,
                 chr(expected[5 + i])))
    print()
    print("长度检查  :", len(flag) == 42)
    print("尾字符检查:", flag[-1] == "}")
    print("memcmp 43 :", expected == (flag.encode() + b"\x00"))
    print("verify()  :", verify(flag))
    print()
    print("FLAG =", flag)


if __name__ == "__main__":
    main()
