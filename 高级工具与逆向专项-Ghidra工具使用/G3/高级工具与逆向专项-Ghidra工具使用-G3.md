### 高级工具与逆向专项-Ghidra工具使用-G3

通过`main`函数中的`enter you flag`、`wrong flag`等字样，可以判断出这是一个flag判断程序。

其中核心函数是`verify`函数，先让我们读一下：

```c
int verify(EVP_PKEY_CTX *flag,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen)
//只有我标注的flag参数是有用的，其他的都是反编译垃圾
{
  undefined1 uVar1;
  uint uVar2;
  int iVar3;
  size_t sVar4;
  long lVar5;
  long in_FS_OFFSET;
  undefined1 local_68;//这是函数栈缓冲区开头bp-0x68，用于存真正的flag，即比对目标
  undefined1 local_67;
  undefined1 local_66;
  undefined1 local_65;
  undefined1 local_64;
  undefined1 local_63 [36];
  undefined1 local_3f;
  undefined1 local_3e;
  long local_30;

  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  sVar4 = strlen((char *)flag);
  uVar2 = 0;
  if ((sVar4 == 0x2a) && (flag[0x29] == (EVP_PKEY_CTX)0x7d)) {
    local_68 = 0x66;//f
    local_67 = 0x6c;//l
    local_66 = 0x61;//a
    local_65 = 0x67;//g
    local_64 = 0x7b;//{
    lVar5 = 0;
    do {
      uVar1 = decrypt_char(CONCAT11((&ASSEMBLE_HI)[lVar5],(&ASSEMBLE_LO)[lVar5]) >> 2,
                           (&ASSEMBLE_LO)[lVar5] & 3);
      local_63[lVar5] = uVar1;//local63，和上面内容为{的 local64相接
      lVar5 = lVar5 + 1;
    } while (lVar5 != 0x24);
    //Var5是索引，用与指{}内36个字符
    local_3f = 0x7d;
    local_3e = 0;
    iVar3 = memcmp(flag,&local_68,0x2b);
    //比对flag
    uVar2 = (uint)(iVar3 == 0);
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

所以关键是中间的循环体，其中最核心的是计算每个字符的函数：

```c
uVar1 = decrypt_char(CONCAT11((&ASSEMBLE_HI)[lVar5],(&ASSEMBLE_LO)[lVar5]) >> 2,
                           (&ASSEMBLE_LO)[lVar5] & 3);
```

- `ASSEMBLE_HI`和`ASSEMBLE_LO`是元素大小为1字节的数组，`CONCAT11(a,b)`是把两个字节拼成一个16位整数的函数，`a`做高字节。

- 接着`>> 2`把拼成的16位整数的低2位丢掉，`& 3`则只保留了低2位——值得注意的是，第一个参数丢掉的低两位，就是第二个参数的内容。

让我们看看`decrypt_char`这个函数：

```c
byte decrypt_char(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_1 * 7 + 3;
  return ((char)iVar1 + (char)(iVar1 / 0xfb) * '\x05' ^
         *(byte *)(*(long *)(strs.0 + (long)param_1 * 8) + (long)param_2)) & 0x7f;
}

```

- `iVar1 = param_1 * 7 + 3;`就是在算一个数，`(char)iVar1 + (char)(iVar1 / 0xfb) * '\x05'`则是用这个数再算一个数。这一步全程可以复现的。

- `*(byte *)(*(long *)(strs.0 + (long)param_1 * 8) + (long)param_2)`是表达式的另外一大半。`*(byte *)(*(long *)(strs.0 + (long)param_1 * 8)`中，`strs.0 + (long)param_1 * 8`作为指针，先解引用一次得到一个`long`类型8字节的指针。这个指针再`+(long)param_1 * 8`，还解引用一次得到一个字节。

- `& 0x7f`只取低7位。

`strs.0`是硬编码的；回到`decrypt_char`的调用，`ASSEMBLE_HI`和`ASSEMBLE_LO`也是硬编码的。

现在难点在于，即使拥有了上述硬编码内容，想要复现，还需要知道第二次解引用的字符集合的内容。

分析发现`*(long *)(strs.0 + (long)param_1 * 8)`作为指针指向的地址范围是**`0x1030c4` 到 `0x10328e`**。咱们也得把这些硬编码的字节拿出来。

最后落成一个脚本`get_flag/get_flag.py`，里面一切内容都是硬编码的，直接`python get_flag.py`即可。


