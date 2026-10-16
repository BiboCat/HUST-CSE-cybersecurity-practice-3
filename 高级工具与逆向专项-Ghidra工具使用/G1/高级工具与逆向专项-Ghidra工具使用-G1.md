### 高级工具与逆向专项-Ghidra工具使用-G1

——安装过程略。

这玩意第一次用，不过还是找到了`main`函数了！核心代码如下：

```c
printf("Enter flag: ");
pcVar2 = fgets((char *)&local_48,0x40,stdin);
uVar3 = 1;
if (pcVar2 != (char *)0x0) {
  sig = "\n";
  sVar4 = strcspn((char *)&local_48,"\n");
  *(undefined1 *)((long)&local_48 + sVar4) = 0;
  quick_check(&local_48);
  iVar1 = verify((EVP_PKEY_CTX *)&local_48,sig,siglen,in_RCX,in_R8);
  if (iVar1 == 0) {
    puts("Wrong.");
    uVar3 = 1;
  }
  else {
    puts("Correct!");
    uVar3 = 0;
  }
}
```

`local_48`是`flag`、`sVar4`是`flag_len`——核心函数在`verify`函数！

进入该函数，分析代码，重写后的代码如下：

```c
int check_serial(const char *input)   // 后 3 个参数未使用，可删除
{
    char   inner[32];      // 剥壳后的 32 字符载荷
    uchar  enc_out[32];    // Feistel 输出
    size_t len = strlen(input);
    int    n = 0;

    if (len != 42)                      return 0;
    if (strncmp(input, "flag{", 5))     return 0;
    if (input[41] != '}')               return 0;

    size_t i = 5;
    do {
        // 跳过 '-'，同时强制其只出现在固定位置
        while (i < 29 && ((0x10842000UL >> i) & 1)) {
            if (input[i] != '-') return 0;
            i++;
        }
        unsigned ch_idx = (unsigned char)input[i] - 0x30;
        if (ch_idx > 0x36)                        return 0;
        if (!((0x7e0000007e03ffUL >> ch_idx) & 1)) return 0;  // 必须是 0-9A-Fa-f
        inner[n++] = input[i++];
    } while (i != 41);
    //剥壳，提取中间32个字母
    
    if (n != 32) return 0;

    for (int blk = 0; blk != 32; blk += 8)
        feistel_enc_block(inner + blk, enc_out + blk);
        //feistel加密后才比对，每8个字节一组，共4组

    return memcmp(enc_out, g_cipher, 32) == 0;
}
```

其中`((0x10842000UL >> i) & 1)`是在筛选`-`出来：
`0x10842000UL`实际上是一个“位图”，二进制视角只有**bit 13、18、23、28 是 1**，右移`i`位就是把第i位放到最低位；此时再与`0x...0001`按位与`&`，即清空高位只留下最低位，最终作为一个bool值来决定是否执行与`-`的比对。
——**这要求13、18、23、28 个符号是`-`！**

现在确定了flag格式，那就只剩32个字母的计算了。——关键在于feistel的加密。

来看`feistel_enc_block`：

```c
void feistel_enc_block(uint *src,uint *dest)

{
  uint T1;
  uint T2;
  uint L;
  uint R;
  
  L = *src;
  R = src[1];
  T1 = F(R);
  T2 = F(L ^ T1);
  *dest = L ^ T1; //记为L1
  dest[1] = T2 ^ R; //记为R1
  return;
}
```

- 它用32位`uint`类型变量取了8字节块（64bit）的前后两半部分，记为`L`和`R`。

- 将函数写成表达式为：
  
  - `L1 = L ⊕ F(R)`
  
  - `R1 = R ⊕ F(L ⊕ F(R))`

- `L = L1 ⊕ F(R)`，所以`R1 = R ⊕ F(L1 ⊕ F(R) ⊕ F(R)) = R ⊕ F(L1)`，
  即`R = R1 ⊕ F(L1)`。

- 最后可以用`L = L1 ⊕ F(R)`求出`L`。

跟进`F`函数，就是一个简单仿射函数，它可以很容易被复刻。

最后看向`g_cipher`，内容是硬编码的：
`6F 6B 47 8F 17 BC D8 A0 BB 4A 2B C6 26 13 43 34 39 3F 4E BC 11 05 69 D6 15 90 E1 1D 25 AA 7B 9D` 

最终脚本放在了`get_flag/get_flag.py`中，直接`python get_flag.py`即可。


