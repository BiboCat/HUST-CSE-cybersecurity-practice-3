# -*- coding: utf-8 -*-
"""
get_flag.py —— 不运行原程序,纯静态还原 vm_run 生成的 flag(全硬编码)

【逆向依据】verify() 里唯一的关键调用:
    vm_run(0x140004060, (longlong)local_48);
  param_1 = 0x140004060  字节码基址(g_bytecode, XREF: verify:14000158f)
  param_2 = &local_48    输出缓冲区(栈上,与 VM 内部的 abStack_48 是同一块内存)

验签逻辑:真值 = "flag{" + out[0..35] + "}",共 42 字节
        (out[36] 会被 verify 自己写的 '}' 覆盖,见文件末尾"关于最后一条 STORE"一节)

【vm_run 指令集】(opcode 1 字节,操作数紧跟其后)
    0x00 HALT              : 退出                                       PC += 1
    0x01 PUSH  imm8        : stack.append(imm)                          PC += 2
    0x02 XOR               : stack[-2] ^= stack[-1]; pop()                PC += 1
    0x03 ROL1              : stack[-1] = rol8(stack[-1], 1)              PC += 1
    0x04 ADD   imm8(有符号) : stack[-1] = (stack[-1] + (int8)imm) & 0xFF  PC += 2
    0x05 STORE idx         : out[idx] = pop()                            PC += 2
    opcode > 5             : 视为结束(0xFF 填充自然终止)
"""

# ============================================================================
# 0x140004060 .. 0x140004187,共 296 字节,第 i 字节对应 0x140004060 + i
# 数据来源:dump.txt(Ghidra Listing 导出)
# ============================================================================
CODE_HEX = (
    "01770111020500017e01120205010172"
    "011302050201730114020503016e0115"
    "02050401600155020500012e03040505"
    "010119012102050201bd030118020503"
    "01670155020504013003040505050162"
    "01550205060129030134020507017801"
    "550205080197030405050901eb018902"
    "050a01b003015002050b013101550205"
    "0c0114030405050d018901bd02050e01"
    "aa03016c02050f016401550205100199"
    "030405051101dc01f102051201d80301"
    "88020513016601550205140130030405"
    "05150113012502051601c40301a40205"
    "17016c015502051801b0030405051901"
    "6b015902051a01510301c002051b0160"
    "015502051c01af030405051d01b5018d"
    "02051e01de0301dc02051f0164015502"
    "0520012f030405052101f501c1020522"
    "01ce0301f8020523"
)

CODE_BASE = 0x140004060
FLAG_PREFIX = "flag{"
FLAG_SUFFIX = "}"
OUT_SIZE = 37                  # 缓冲区 0x25 = 37 字节

OP_HALT, OP_PUSH, OP_XOR, OP_ROL1, OP_ADD, OP_STORE = range(6)


def rol8(v, n=1):
    """8 位循环左移;x86 的 ROL 是双射,不能用 >> 代替。"""
    return ((v << n) | (v >> (8 - n))) & 0xFF


def run_vm(code_hex=CODE_HEX, out_size=OUT_SIZE, signed_add=True, trace=False):
    """执行 vm_run,返回 (out, stack)。signed_add 对应 *(char *)(param_1+iVar3)。"""
    code = bytes.fromhex(code_hex)
    out = [0] * out_size
    stack = []
    pc = 0

    while pc < len(code):
        op = code[pc]
        if op > 5 or op == OP_HALT:          # 0xFF 填充 / HALT => 结束
            break
        addr = CODE_BASE + pc

        if op == OP_PUSH:                    # 0x01
            imm = code[pc + 1]
            stack.append(imm)
            pc += 2
            if trace:
                print("%08x  PUSH   0x%02x          %s" % (addr, imm, stack))
        elif op == OP_XOR:                   # 0x02
            b = stack.pop()
            stack[-1] = (stack[-1] ^ b) & 0xFF
            pc += 1
            if trace:
                print("%08x  XOR                 %s" % (addr, stack))
        elif op == OP_ROL1:                  # 0x03
            stack[-1] = rol8(stack[-1])
            pc += 1
            if trace:
                print("%08x  ROL1                %s" % (addr, stack))
        elif op == OP_ADD:                   # 0x04
            imm = code[pc + 1]
            if signed_add and imm >= 0x80:
                imm -= 0x100
            stack[-1] = (stack[-1] + imm) & 0xFF
            pc += 2
            if trace:
                print("%08x  ADD    %+4d          %s" % (addr, imm, stack))
        elif op == OP_STORE:                 # 0x05
            idx = code[pc + 1]
            if not 0 <= idx < out_size:
                raise ValueError("STORE 下标 %d 越界" % idx)
            out[idx] = stack.pop()
            pc += 2
            if trace:
                print("%08x  STORE  out[0x%02x]    %s" % (addr, idx, stack))

    return out, stack


def get_flag():
    """返回还原出来的 flag。"""
    out, stack = run_vm()
    assert not stack, "结束时操作数栈应为空,实际 %r" % (stack,)

    body = bytes(out[:36])
    flag = FLAG_PREFIX + body.decode("ascii") + FLAG_SUFFIX
    assert len(flag) == 42, "flag 长度应为 42,实际 %d" % len(flag)
    return flag


if __name__ == "__main__":
    # ---- 1) ADD 语义判定:立即数按有符号还是无符号解释 ----
    # 字节码里 ADD 的立即数全是 0x05(<0x80),两种解释下正文理应完全相同;
    # 唯独 out[36] 会分叉 —— 正好是 verify 要放 '}' 的那一格,反过来印证了正文只到 out[35]。
    out_u, _ = run_vm(signed_add=False)
    out_s, _ = run_vm(signed_add=True)
    body_same = out_u[:36] == out_s[:36]
    print("ADD 立即数均为 0x05(<0x80):正文 out[0..35] %s;"
          "out[36] 有符号=0x%02x / 无符号=0x%02x(该格由 verify 的 '}' 占据)\n"
          % ("一致" if body_same else "不一致!", out_s[36], out_u[36]))

    # ---- 2) dump 出 VM 的 37 个输出槽 ----
    out, _ = run_vm()
    print("VM 输出 out[0x00..0x24]:")
    for i in range(0, OUT_SIZE, 8):
        chunk = out[i:i + 8]
        print("  [%02x] %s   |%s|" % (
            i,
            " ".join("%02x" % v for v in chunk),
            "".join(chr(v) if 32 <= v < 127 else "." for v in chunk),
        ))
    print("  >> out[0x23] = 0x%02x (%r),out[0x24] = 0x%02x —— 最后一条 STORE 落在 0x23\n"
          % (out[0x23], chr(out[0x23]), out[0x24]))

    # ---- 3) 出 flag ----
    flag = get_flag()
    print("get_flag() = %s" % flag)
    print("长度      = %d" % len(flag))
    print("正文       = %s   (36 字符)" % flag[5:-1])
