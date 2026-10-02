#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rc4tool.py —— RC4 加解密工具（纯标准库，无需安装任何依赖）

设计目标：CTF / 逆向分析时能直接把一段密钥和一段数据丢进来，
          立刻拿到结果，并且能在各种"脏"输入格式之间来回转换。

用法速查：
    python rc4tool.py enc -k "Key" --in-text "Plaintext"          # 加密
    python rc4tool.py dec -k "Key" --in-hex bbf316e8d940af0ad3    # 解密
    python rc4tool.py selftest                                    # 自检
    python rc4tool.py genkey -n 16                                # 生成随机密钥

RC4 是对称算法：enc 与 dec 是同一个运算，两个子命令完全等价，
分开只是为了命令行语义清楚。

作者备注：本文件不包含任何会话相关的硬编码数据，纯通用工具。
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sys

__version__ = "1.0.0"
PROG = "rc4tool.py"


def _init_console_encoding() -> None:
    """统一用 UTF-8 输出，避免 Windows 默认 cp936 控制台把中文弄成乱码。

    重定向/管道输出时也保持 UTF-8，方便和其它工具衔接。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes
            if sys.stdout.isatty():
                ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass


_init_console_encoding()

# ---------------------------------------------------------------------------
# 一、RC4 核心算法
# ---------------------------------------------------------------------------


class RC4:
    """标准 RC4 流密码。

    key  : 密钥字节串（不能为空）
    drop : 丢弃前 drop 字节密钥流（RC4-drop-N，用于对付某些变种/加固）
    """

    __slots__ = ("_S", "_i", "_j")

    def __init__(self, key: bytes, drop: int = 0) -> None:
        if not key:
            raise ValueError("密钥不能为空")
        if drop < 0:
            raise ValueError("--drop 不能为负数")

        # ---- KSA：密钥调度 ----
        S = list(range(256))
        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % key_len]) & 0xFF
            S[i], S[j] = S[j], S[i]

        self._S = S
        self._i = 0
        self._j = 0

        # ---- RC4-drop-N：先把前 drop 字节密钥流扔掉 ----
        if drop:
            self.keystream(drop)

    def keystream(self, n: int) -> bytes:
        """取 n 字节密钥流，并推进内部状态（可反复调用，输出是连续的）。"""
        S, i, j = self._S, self._i, self._j
        out = bytearray(n)
        for k in range(n):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[k] = S[(S[i] + S[j]) & 0xFF]
        self._i, self._j = i, j
        return bytes(out)

    def crypt(self, data: bytes) -> bytes:
        """与密钥流逐字节异或。加密和解密都是这一个函数。"""
        ks = self.keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))


def rc4(key: bytes, data: bytes, drop: int = 0) -> bytes:
    """一次性调用：rc4(key, data) 加密；rc4(key, cipher) 解密。"""
    return RC4(key, drop=drop).crypt(data)


# ---------------------------------------------------------------------------
# 二、输入解析：容忍各种"脏"十六进制写法
# ---------------------------------------------------------------------------

_SEP = re.compile(r"[\s,;:\-]+|\\x", re.ASCII)
_PURE_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")


def parse_hex(text: str) -> bytes:
    """把各种写法的十六进制文本解析成字节串。

    支持的写法（可混用）：
        0CCh 0C6h 9Dh 16h      —— 汇编风格（尾缀 h、前导 0）
        0xCC, 0xC6, 0x9D       —— C 风格
        \\xCC\\xC6\\x9D           —— C 字符串转义
        bbf316e8d940af0ad3     —— 连续 hex（自动按两位切分）
        CC C6 9D / CC-C6-9D    —— 空格 / 短横线分隔
    分隔符可以是空格、换行、逗号、分号、冒号、短横线。
    """
    out = bytearray()
    for raw_tok in _SEP.split(text.strip()):
        if not raw_tok:
            continue
        tok = raw_tok
        if tok[:2].lower() == "0x":
            tok = tok[2:]
        elif tok[:1] == "$":
            tok = tok[1:]
        suffix_h = tok[-1:] in ("h", "H")
        if suffix_h:
            tok = tok[:-1]
        if not tok or not _PURE_HEX.match(tok):
            raise ValueError("无法识别的十六进制片段: %r" % raw_tok)
        if suffix_h or len(tok) <= 2:
            value = int(tok, 16)
            if value > 0xFF:
                raise ValueError("字节值超出 0xFF: %r" % raw_tok)
            out.append(value)
        else:
            if len(tok) % 2:
                raise ValueError("连续十六进制串长度必须为偶数: %r" % raw_tok)
            out += bytes.fromhex(tok)
    return bytes(out)


def to_c_array(data: bytes, name: str = "data", per_line: int = 12,
               upper: bool = False) -> str:
    """生成 C 数组字面量，方便直接贴进源码或调试器。"""
    if not per_line or per_line < 1:
        per_line = 12
    fmt = "0x%02X" if upper else "0x%02x"
    lines = []
    for start in range(0, len(data), per_line):
        chunk = data[start:start + per_line]
        lines.append("    " + ", ".join(fmt % b for b in chunk) + ",")
    body = "\n".join(lines)
    return "unsigned char %s[%d] = {\n%s\n};" % (name, len(data), body)


def hex_dump(data: bytes, per_line: int = 0, upper: bool = False) -> str:
    """十六进制输出；per_line > 0 时按每行固定字节数折行。"""
    text = data.hex()
    if upper:
        text = text.upper()
    if not per_line or per_line < 1:
        return text
    step = per_line * 2
    return "\n".join(text[k:k + step] for k in range(0, len(text), step))


# ---------------------------------------------------------------------------
# 三、命令行
# ---------------------------------------------------------------------------

EPILOG = """\
示例:
  # 1) 加密：文本密钥 + 文本明文，输出 hex
  python rc4tool.py enc -k "Secret" --in-text "Attack at dawn"

  # 2) 解密：同一命令即可（RC4 对称），密文来自命令行十六进制
  python rc4tool.py dec --key-hex 4b6579 --in-hex bbf316e8d940af0ad3 -f text

  # 3) 文件加解密（密文落盘为原始字节）
  python rc4tool.py enc -k mykey -i plain.bin -o cipher.bin -f raw
  python rc4tool.py dec -k mykey -i cipher.bin -o plain.bin -f raw

  # 4) 管道：从 stdin 读原始字节，结果写 stdout 原始字节
  type cipher.bin | python rc4tool.py dec -k mykey -f raw > plain.bin

  # 5) 脏十六进制直接粘（汇编风格 / 0x 风格 / 连续 hex 都能吃）
  python rc4tool.py enc -k "Key" --in-hex "0CCh, 0C6h, 9Dh 87h" -f text

  # 6) 生成 C 数组，贴回源码或调试器
  python rc4tool.py enc -k mykey --in-text "hello" -f carray --name blob

  # 7) 带 RC4-drop-N 的变种（丢弃前 256 字节密钥流）
  python rc4tool.py dec -k mykey --drop 256 -i cipher.bin -f text
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="RC4 加解密工具（纯标准库）。enc 与 dec 完全等价 —— RC4 是对称算法。",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version",
                        version="%s %s" % (PROG, __version__))
    sub = parser.add_subparsers(dest="command", metavar="{enc,dec,selftest,genkey}")

    # ---- enc / dec：同一个处理函数 ----
    for name, help_text in (("enc", "加密（= dec，RC4 对称）"),
                            ("dec", "解密（= enc，RC4 对称）")):
        p = sub.add_parser(name, help=help_text, description=help_text,
                           epilog=EPILOG,
                           formatter_class=argparse.RawDescriptionHelpFormatter)
        _add_crypto_args(p)

    # ---- selftest ----
    p = sub.add_parser("selftest", help="跑标准 RC4 测试向量自检")
    p.set_defaults(func=cmd_selftest)

    # ---- genkey ----
    p = sub.add_parser("genkey", help="生成随机密钥")
    p.add_argument("-n", "--bytes", type=int, default=16, metavar="N",
                   help="密钥字节数（默认 16）")
    p.add_argument("--raw", action="store_true",
                   help="直接输出原始字节而不是十六进制")
    p.set_defaults(func=cmd_genkey)

    return parser


def _add_crypto_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("密钥（三选一，必填）")
    g.add_argument("-k", "--key", metavar="TEXT",
                   help="文本密钥，按 --encoding 编码（默认 UTF-8）")
    g.add_argument("--key-hex", metavar="HEX",
                   help="十六进制密钥，容忍 0x / h 后缀 / 逗号 / 空格 / \\x")
    g.add_argument("--key-file", metavar="PATH",
                   help="从文件读取原始字节作为密钥")

    g = p.add_argument_group("输入数据（可选；都不给则从 stdin 读原始字节）")
    g.add_argument("-i", "--in", dest="in_file", metavar="PATH",
                   help="输入文件（原始字节）")
    g.add_argument("--in-hex", metavar="HEX",
                   help="十六进制输入（容忍 0x / h 后缀 / 逗号 / 空格 / \\x）")
    g.add_argument("--in-hex-file", metavar="PATH",
                   help="输入文件，内容为十六进制文本（宽容解析）")
    g.add_argument("--in-text", metavar="TEXT", help="文本输入")
    g.add_argument("--in-b64", metavar="B64", help="Base64 输入")

    g = p.add_argument_group("输出")
    g.add_argument("-o", "--out", metavar="PATH",
                   help="输出文件（默认写 stdout）")
    g.add_argument("-f", "--format", "--fmt", dest="fmt", default="hex",
                   choices=("hex", "hexc", "raw", "text", "b64", "carray"),
                   help="输出格式（默认 hex）："
                        "hex=纯十六进制，hexc=0xNN,逗号分隔，raw=原始字节，"
                        "text=解码为文本，b64=Base64，carray=C 数组")
    g.add_argument("--upper", action="store_true", help="十六进制大写")
    g.add_argument("--per-line", type=int, default=0, metavar="N",
                   help="hex 格式每行多少字节（0=不折行）")
    g.add_argument("--name", default="data", metavar="ID",
                   help="carray 格式的数组名（默认 data）")
    g.add_argument("--no-newline", action="store_true",
                   help="文本类输出末尾不加换行")

    g = p.add_argument_group("算法选项")
    g.add_argument("--drop", type=int, default=0, metavar="N",
                   help="RC4-drop-N：丢弃前 N 字节密钥流（默认 0）")
    g.add_argument("--encoding", default="utf-8", metavar="ENC",
                   help="文本密钥/文本输入/文本输出使用的编码（默认 utf-8）")

    p.set_defaults(func=cmd_crypt)


def _fail(message: str) -> int:
    print("%s: 错误: %s" % (PROG, message), file=sys.stderr)
    return 1


def load_key(args: argparse.Namespace) -> bytes:
    given = [x for x in (args.key, args.key_hex, args.key_file) if x is not None]
    if not given:
        raise ValueError("必须提供密钥：-k / --key-hex / --key-file 三选一")
    if len(given) > 1:
        raise ValueError("密钥只能指定一种来源")

    if args.key is not None:
        key = args.key.encode(args.encoding)
    elif args.key_hex is not None:
        key = parse_hex(args.key_hex)
    else:
        with open(args.key_file, "rb") as fh:
            key = fh.read()

    if not key:
        raise ValueError("密钥长度为 0")
    return key


def load_data(args: argparse.Namespace) -> bytes:
    sources = [x for x in (args.in_file, args.in_hex, args.in_hex_file,
                           args.in_text, args.in_b64) if x is not None]
    if len(sources) > 1:
        raise ValueError("输入只能指定一种来源（-i / --in-hex / --in-hex-file / "
                         "--in-text / --in-b64）")

    if args.in_file is not None:
        with open(args.in_file, "rb") as fh:
            return fh.read()
    if args.in_hex is not None:
        return parse_hex(args.in_hex)
    if args.in_hex_file is not None:
        with open(args.in_hex_file, "r", encoding=args.encoding, errors="replace") as fh:
            return parse_hex(fh.read())
    if args.in_text is not None:
        return args.in_text.encode(args.encoding)
    if args.in_b64 is not None:
        return base64.b64decode(args.in_b64, validate=False)

    # 默认：从 stdin 读原始字节
    return sys.stdin.buffer.read()


def render(data: bytes, args: argparse.Namespace) -> bytes:
    """把结果渲染成最终要写出的字节（文本格式带换行，raw 格式原样）。"""
    if args.fmt == "raw":
        return data

    if args.fmt == "hex":
        text = hex_dump(data, args.per_line, args.upper)
    elif args.fmt == "hexc":
        fmt = "0x%02X" if args.upper else "0x%02x"
        text = ", ".join(fmt % b for b in data)
    elif args.fmt == "b64":
        text = base64.b64encode(data).decode("ascii")
    elif args.fmt == "carray":
        text = to_c_array(data, args.name, args.per_line or 12, args.upper)
    elif args.fmt == "text":
        text = data.decode(args.encoding, errors="backslashreplace")
    else:  # pragma: no cover - argparse 已限制取值
        raise ValueError("未知输出格式: %s" % args.fmt)

    if not args.no_newline:
        text += "\n"
    return text.encode(args.encoding, errors="backslashreplace")


def write_out(payload: bytes, out_path: str | None) -> None:
    if out_path in (None, "-"):
        stream = sys.stdout.buffer
        stream.write(payload)
        stream.flush()
    else:
        with open(out_path, "wb") as fh:
            fh.write(payload)


def cmd_crypt(args: argparse.Namespace) -> int:
    key = load_key(args)
    data = load_data(args)
    result = rc4(key, data, drop=args.drop)

    if args.fmt == "raw" and args.out in (None, "-") and sys.stdout.isatty():
        print("%s: 警告: raw 格式正在往终端写二进制数据，建议配合 -o 或重定向"
              % PROG, file=sys.stderr)

    write_out(render(result, args), args.out)

    if args.out not in (None, "-") and not getattr(args, "quiet", False):
        print("%s: 密钥 %d 字节, 输入 %d 字节, 输出 %d 字节 -> %s (%s)"
              % (PROG, len(key), len(data), len(result),
                 os.path.abspath(args.out), args.fmt), file=sys.stderr)
    return 0


def cmd_genkey(args: argparse.Namespace) -> int:
    if args.bytes < 1:
        return _fail("密钥字节数必须 >= 1")
    key = secrets.token_bytes(args.bytes)
    if args.raw:
        sys.stdout.buffer.write(key)
        sys.stdout.buffer.flush()
    else:
        print(key.hex())
    return 0


# ---------------------------------------------------------------------------
# 四、自检：标准 RC4 测试向量 + 解析器 / drop 一致性
# ---------------------------------------------------------------------------

_VECTORS = (
    (b"Key",    b"Plaintext",      "bbf316e8d940af0ad3"),
    (b"Wiki",   b"pedia",          "1021bf0420"),
    (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
)


def cmd_selftest(args: argparse.Namespace) -> int:
    ok = True
    print("== RC4 标准测试向量 ==")
    for key, plain, want in _VECTORS:
        got = rc4(key, plain).hex()
        good = got == want
        ok &= good
        print("  key=%-7s data=%-16s -> %-34s %s"
              % (key.decode(), plain.decode(), got, "OK" if good else "FAIL(期望 %s)" % want))

    print("== 往返一致性 ==")
    key = bytes(range(8))
    data = bytes(range(256)) * 2          # 512 字节，覆盖 i 回绕
    back = rc4(key, rc4(key, data))
    same = back == data
    ok &= same
    print("  512 字节随机数据加解密往返: %s" % ("OK" if same else "FAIL"))

    print("== RC4-drop-N 一致性 ==")
    n = 256
    a = rc4(b"key", data, drop=n)
    b = rc4(b"key", b"\x00" * n + data)[n:]
    same = a == b
    ok &= same
    print("  drop 256 与手工跳过前 256 字节密钥流: %s" % ("OK" if same else "FAIL"))

    print("== 宽容十六进制解析 ==")
    cases = (
        ("0CCh, 0C6h, 9Dh 87h", bytes([0xCC, 0xC6, 0x9D, 0x87])),
        ("0xCC,0xC6,0x9D",      bytes([0xCC, 0xC6, 0x9D])),
        (r"\xCC\xC6\x9D",       bytes([0xCC, 0xC6, 0x9D])),
        ("bbf316e8d940af0ad3",  bytes.fromhex("bbf316e8d940af0ad3")),
        ("CC-C6-9D",            bytes([0xCC, 0xC6, 0x9D])),
    )
    for text, want in cases:
        try:
            got = parse_hex(text)
        except ValueError as exc:
            got, want = b"<%s>" % str(exc).encode(), b"<no error>"
        good = got == want
        ok &= good
        print("  %-22s -> %-24s %s" % (text, got.hex(), "OK" if good else "FAIL"))

    print()
    print("自检结果: %s" % ("全部通过" if ok else "存在失败项"))
    return 0 if ok else 2


# ---------------------------------------------------------------------------
# 五、入口
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except ValueError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail("文件操作失败: %s" % exc)
    except KeyboardInterrupt:                       # pragma: no cover
        print("\n%s: 已中断" % PROG, file=sys.stderr)
        return 130
    except BrokenPipeError:                         # pragma: no cover
        try:
            sys.stdout.close()
        finally:
            return 0


if __name__ == "__main__":
    sys.exit(main())
