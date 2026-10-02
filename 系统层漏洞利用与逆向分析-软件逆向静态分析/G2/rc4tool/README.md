# rc4tool — RC4 加解密工具

一个**零依赖**的 RC4 命令行工具，面向 CTF / 逆向分析场景：把密钥和一段数据丢进来就能立刻拿到结果，并且能在各种"脏"输入格式（汇编风格 hex、`0x` 风格、连续 hex、C 转义、Base64、二进制文件、管道）之间自由转换。

```
rc4tool/
├── rc4tool.py     # 工具本体（单文件，约 400 行，纯标准库）
└── README.md      # 本文件
```

---

## 目录

- [环境要求](#环境要求)
- [30 秒上手](#30-秒上手)
- [为什么 enc 和 dec 是同一个命令](#为什么-enc-和-dec-是同一个命令)
- [命令与参数](#命令与参数)
- [输入来源](#输入来源)
- [输出格式](#输出格式)
- [宽容十六进制解析](#宽容十六进制解析)
- [典型场景](#典型场景)
- [算法说明](#算法说明)
- [自检与测试向量](#自检与测试向量)
- [退出码](#退出码)
- [局限与安全警告](#局限与安全警告)

---

## 环境要求

| 项目 | 要求 |
|---|---|
| Python | 3.8 及以上（用到 `list[str]` 注解与 `|` 联合类型，3.8 起可用） |
| 第三方库 | **无**，只用 `argparse / base64 / os / re / secrets / sys` |
| 操作系统 | Windows / Linux / macOS 均可 |

直接运行即可，无需安装：

```bash
python rc4tool.py --help
```

> Windows 控制台提示：脚本启动时会自动把 stdout/stderr 切到 UTF-8（并在终端里把控制台代码页设为 65001），所以中文提示不会乱码；重定向到文件时输出同样是 UTF-8。

---

## 30 秒上手

```bash
# 加密：文本密钥 + 文本明文，输出十六进制
$ python rc4tool.py enc -k "Secret" --in-text "Attack at dawn"
45a01f645fc35b383552544b9bf5

# 解密：换成 dec（其实就是同一个运算），密文给十六进制，输出文本
$ python rc4tool.py dec --key-hex 4b6579 --in-hex bbf316e8d940af0ad3 -f text
Plaintext
```

`45a01f645fc35b383552544b9bf5` 与 `bbf316e8d940af0ad3` 都是 RC4 的公开标准测试向量，可放心当"标尺"用。

---

## 为什么 enc 和 dec 是同一个命令

RC4 是流密码，加解密都是「明文/密文 XOR 密钥流」，而 XOR 自逆，所以**加密和解密在数学上是同一个函数**：

```
C = P ⊕ KS          P = C ⊕ KS
```

工具里 `enc` 与 `dec` 绑定的是同一个处理函数，两条命令完全等价，**分开只是为了命令行语义清楚**（看命令名就知道自己在干什么），不是两套实现。

---

## 命令与参数

```
python rc4tool.py {enc,dec,selftest,genkey} [选项]
```

### 子命令

| 子命令 | 作用 |
|---|---|
| `enc` | 加密（= `dec`） |
| `dec` | 解密（= `enc`） |
| `selftest` | 跑标准测试向量 + 解析器 + drop-N 一致性自检，失败返回码 2 |
| `genkey` | 生成随机密钥（`-n N` 指定字节数，默认 16；`--raw` 输出原始字节） |

### 密钥参数（三选一，必填）

| 参数 | 说明 |
|---|---|
| `-k, --key TEXT` | 文本密钥，按 `--encoding`（默认 UTF-8）编码成字节 |
| `--key-hex HEX` | 十六进制密钥，容忍 `0x` / `h` 后缀 / 逗号 / 空格 / `\x` |
| `--key-file PATH` | 从文件读取**原始字节**作为密钥 |

### 输出与算法参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-o, --out PATH` | stdout | 输出文件；`-` 也表示 stdout |
| `-f, --format` | `hex` | `hex` / `hexc` / `raw` / `text` / `b64` / `carray` |
| `--upper` | 关 | 十六进制输出用大写 |
| `--per-line N` | `0` | `hex` 每行多少字节（0 = 不折行）；`carray` 默认 12 |
| `--name ID` | `data` | `carray` 的数组名 |
| `--no-newline` | 关 | 文本类输出末尾不加换行 |
| `--drop N` | `0` | RC4-drop-N：丢弃前 N 字节密钥流 |
| `--encoding ENC` | `utf-8` | 文本密钥 / 文本输入 / 文本输出所用编码 |

> 用 `-o` 写文件时，工具会往 **stderr** 打印一行统计（密钥字节数、输入/输出字节数、绝对路径），不会污染 stdout。

---

## 输入来源

不指定任何输入参数时，**从 stdin 读原始字节**；指定多个会报错。

| 参数 | 说明 |
|---|---|
| `-i, --in PATH` | 输入文件（原始字节） |
| `--in-hex HEX` | 十六进制字符串（宽容解析，见下节） |
| `--in-hex-file PATH` | 输入文件，内容是**十六进制文本**（宽容解析） |
| `--in-text TEXT` | 文本输入，按 `--encoding` 编码 |
| `--in-b64 B64` | Base64 输入 |
| （不给） | 读 stdin 原始字节 |

---

## 输出格式

| 格式 | 样例（对 `hello` 用密钥 `mykey` 加密） |
|---|---|
| `hex` | `3e03e9021b` |
| `hexc` | `0x3e, 0x03, 0xe9, 0x02, 0x1b` |
| `raw` | 原始字节（5 字节，无换行，适合直接落盘/重定向） |
| `text` | 按 `--encoding` 解码为文本，不可打印字节显示为 `\xNN` 转义 |
| `b64` | `PgPpAhs=` |
| `carray` | 见下 |

```bash
$ python rc4tool.py enc -k 'mykey' --in-text 'hello' -f carray --name blob
unsigned char blob[5] = {
    0x3e, 0x03, 0xe9, 0x02, 0x1b,
};
```

`carray` 很适合把 dump 出来的密文贴进 IDA 脚本、C 复现程序或调试器。

---

## 宽容十六进制解析

逆向现场拿到的十六进制往往很脏——反汇编窗口里是 `0CCh`，hex dump 里是 `CC C6`，C 源码里是 `0xCC`，调试器里是连续一串。以下写法**全部支持，且可混用**：

| 输入 | 解析结果 | 说明 |
|---|---|---|
| `0CCh, 0C6h, 9Dh 87h` | `ccc69d87` | 汇编风格：尾缀 `h`、前导 `0`；**漏写逗号也能吃**（按空白切分） |
| `0xCC,0xC6,0x9D` | `ccc69d` | C 风格 |
| `\xCC\xC6\x9D` | `ccc69d` | C 字符串转义 |
| `bbf316e8d940af0ad3` | `bbf316e8d940af0ad3` | 连续 hex，自动按两位切分（长度必须为偶数） |
| `CC-C6-9D` | `ccc69d` | 短横线分隔 |

分隔符可以是**空格、换行、逗号、分号、冒号、短横线**；单字节 token 超过 `0xFF` 或连续 hex 长度为奇数会明确报错，不会静默出错。

```bash
$ python rc4tool.py enc -k 'Key' --in-hex '0CCh, 0C6h, 9Dh 87h' -f hexc
0x27, 0x59, 0xea, 0x06
```

---

## 典型场景

### 1. 文件加解密（原始字节进出）

```bash
python rc4tool.py enc -k mykey -i plain.bin -o cipher.bin -f raw
python rc4tool.py dec -k mykey -i cipher.bin -o back.bin  -f raw
```

实测（明文含中文）：

```
plain.hex  = 68656c6c6f207263342066696c6520726f756e647472697020e4bda0e5a5bd
cipher.hex = 3e03e9021b64cf05bef081f13069f0b7aeca75b78ace435607b5788ff93929
back.hex   = 68656c6c6f207263342066696c6520726f756e647472697020e4bda0e5a5bd
往返一致   = OK
```

### 2. 管道 / 重定向

```bash
type cipher.bin | python rc4tool.py dec -k mykey -f text
# hello rc4 file roundtrip 你好

type cipher.bin | python rc4tool.py dec -k mykey -f raw > plain.bin
```

> `-f raw` 往终端写二进制没有意义，工具检测到 stdout 是终端时会往 stderr 提示一句，请配合 `-o` 或重定向使用。

### 3. 应对 RC4-drop-N 变种

有些样本会丢弃前 N 字节密钥流（N 常见 256 / 768 / 3072）来规避检测。`--drop` 直接支持：

```bash
python rc4tool.py enc -k 'mykey' --drop 256 --in-text 'drop-n demo' -o d.bin -f raw
python rc4tool.py dec -k 'mykey' --drop 256 -i d.bin -f text
# drop-n demo
```

不知道 N 是多少时，可以扫一遍：对每个候选 N 解密后看结果是否可打印。

### 4. 输出成 C 数组，贴进复现程序

```bash
python rc4tool.py enc -k 'mykey' --in-text 'abcdefghijklmnopqrstuvwxyz' --upper --per-line 8
3704E60A1122DA0E
E3BA8CF43162BFB5
B0CD68A78BCA5D5E
5E2B
```

### 5. 生成密钥

```bash
$ python rc4tool.py genkey -n 16
2367c9774ff93d74c9c7a9d63eb92a80
```

---

## 算法说明

标准 RC4，两个阶段：

```c
/* KSA：密钥调度 */
for (i = 0; i < 256; ++i) S[i] = (unsigned char)i;
j = 0;
for (i = 0; i < 256; ++i) {
    j = (j + S[i] + key[i % key_len]) & 0xFF;
    swap(S[i], S[j]);
}

/* PRGA：生成密钥流并与数据异或 */
i = 0; j = 0;
for (k = 0; k < data_len; ++k) {
    i = (i + 1) & 0xFF;
    j = (j + S[i]) & 0xFF;
    swap(S[i], S[j]);
    data[k] ^= S[(S[i] + S[j]) & 0xFF];
}
```

工具里的 `RC4` 类把 PRGA 拆成可流式调用的 `keystream(n)`，因此可以：

- 分段处理大文件（状态连续，结果与一次性处理一致）；
- 实现 `--drop N`（构造时先丢掉 N 字节密钥流）。

也可以当库用：

```python
import sys; sys.path.insert(0, r"路径/rc4tool")
from rc4tool import RC4, rc4

rc4(b"key", b"data")                       # 一次性
c = RC4(b"key", drop=256)                  # drop-N
c.crypt(b"part1") + c.crypt(b"part2")      # 流式，等价于一次 crypt(b"part1part2")
```

---

## 自检与测试向量

```bash
$ python rc4tool.py selftest
```

实测输出：

```
== RC4 标准测试向量 ==
  key=Key     data=Plaintext        -> bbf316e8d940af0ad3                 OK
  key=Wiki    data=pedia            -> 1021bf0420                         OK
  key=Secret  data=Attack at dawn   -> 45a01f645fc35b383552544b9bf5       OK
== 往返一致性 ==
  512 字节随机数据加解密往返: OK
== RC4-drop-N 一致性 ==
  drop 256 与手工跳过前 256 字节密钥流: OK
== 宽容十六进制解析 ==
  0CCh, 0C6h, 9Dh 87h    -> ccc69d87                 OK
  0xCC,0xC6,0x9D         -> ccc69d                   OK
  \xCC\xC6\x9D           -> ccc69d                   OK
  bbf316e8d940af0ad3     -> bbf316e8d940af0ad3       OK
  CC-C6-9D               -> ccc69d                   OK

自检结果: 全部通过
```

三条向量取自 RC4 的公开测试集，是判断"实现有没有写错"的硬标准；后两组自检覆盖了长度超过 256 字节（`i` 回绕）和 drop-N 两条容易写错的路径。

---

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功（无子命令时打印帮助也算成功） |
| 1 | 参数/文件/解析错误（信息打到 stderr） |
| 2 | `selftest` 有失败项 |
| 130 | 被 Ctrl+C 中断 |

---

## 局限与安全警告

- **RC4 已不再安全**，本文具用于 CTF、逆向分析、样本解密、协议复现等**研究与取证**用途。
- 不要用它保护真实数据：RC4 存在大量已知偏差（密钥流前若干字节统计不均匀、`RC4-NOMORE` 之类的区分攻击），TLS 早已禁用（RFC 7465）。生产环境请用 AES-GCM / ChaCha20-Poly1305。
- **不要重复使用同一密钥加密不同明文**：流密码复用密钥流等价于"两次一密"，XOR 两段密文即可消掉密钥流。需要多消息加密时请给每条消息配随机 nonce 并派生密钥。
- `--drop N`（RC4-drop-N）只是让密钥流开头偏差被绕开，**属于缓解手段，不是修复手段**，不能把 RC4 变安全。
- 密钥太短会被暴力枚举；`genkey` 默认 16 字节，但 RC4 的密钥调度对长密钥利用并不充分，它不是靠"加长密钥"就能救的算法。
- 工具不做完整性校验（RC4 是纯流密码，无认证），解密结果"看起来是乱码"不代表密钥错，请结合已知明文/格式头判断。
