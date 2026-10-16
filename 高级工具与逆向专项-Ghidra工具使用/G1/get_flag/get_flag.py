import sys
M = 0xffffffff
K = (-0x61c88647) & M
C0 = (-0x21524111) & M
def F(x): return (x * K + C0) & M

tgt = bytes(int(b,16) for b in "6F 6B 47 8F 17 BC D8 A0 BB 4A 2B C6 26 13 43 34 39 3F 4E BC 11 05 69 D6 15 90 E1 1D 25 AA 7B 9D".split())
print("target len:", len(tgt))

def dec_block(blk):
    C = int.from_bytes(blk[0:4],'little'); D = int.from_bytes(blk[4:8],'little')
    B = D ^ F(C); A = C ^ F(B)
    return A.to_bytes(4,'little') + B.to_bytes(4,'little')
def enc_block(blk):
    A = int.from_bytes(blk[0:4],'little'); B = int.from_bytes(blk[4:8],'little')
    C = A ^ F(B); D = B ^ F(C)
    return C.to_bytes(4,'little') + D.to_bytes(4,'little')

plain = b"".join(dec_block(tgt[i:i+8]) for i in range(0,32,8))
re = b"".join(enc_block(plain[i:i+8]) for i in range(0,32,8))
print("re-encrypt == target ?", re == tgt)
print("plain hex   :", plain.hex(' '))
print("plain ascii :", plain.decode('ascii'))

inner = plain.decode('ascii')
idxs = [i for i in range(5,41) if i not in (13,18,23,28)]
flag = ['?']*42
flag[0:5] = list("flag{"); flag[41] = '}'
for pos in (13,18,23,28): flag[pos] = '-'
for pos, ch in zip(idxs, inner): flag[pos] = ch
flag = ''.join(flag)
print("\nFLAG:", flag)
print("len :", len(flag), "| inner len:", len(inner))
