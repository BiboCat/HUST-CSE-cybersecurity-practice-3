hexdump = """
9b b6 12 68 c1 f0 06 bc 9e a6 04 4d a6 91 11 4d
57 64 09 c4 e8 89 0a 80 5c 6c 10 d8 ad cb 05 82
b0 d3 0c 94 db be 19 b7 78 1a 07 99 4e 7c 1e e8
d5 f8 0d df 5f 3a 23 bc 59 74 17 e4 3d 05 14 56
c7 a1 1f 8c 7e 4f 16 e3 34 57 1d a8 ad 99 18 63
98 ae 0b 56 65 55 ff aa 61 55 ff aa b9 db 13 ac
69 5c 02 c7 f3 c6 20 de 64 55 ff aa 20 12 00 32
6c 0d 1b 94 53 37 01 8b 4e 2a 15 8d 2c 15 22 63
12 3f 08 59 16 22 0e 46 e4 81 03 6d 7e 47 0f d4
d4 e3 1a d6 89 eb 21 9a 02 32 1c 50
"""
raw = bytes(int(t, 16) for t in hexdump.split())
out = {}
for i in range(39):
    b0, b1, key, chk = raw[4*i:4*i+4]
    if chk == (b0 + b1 + key) & 0xFF and key < 0x24:
        out[key] = b0 ^ b1
print("flag{%s}" % "".join(chr(out[i]) for i in range(36)))

