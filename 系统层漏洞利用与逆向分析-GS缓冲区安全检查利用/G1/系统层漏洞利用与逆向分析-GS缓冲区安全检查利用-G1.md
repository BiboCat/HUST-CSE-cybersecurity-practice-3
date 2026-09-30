### 系统层漏洞利用与逆向分析-GS缓冲区安全检查利用-G1

#### 直连靶机试试

直接连接，给了`Buffer`和`Cookie`的提示，并且让你`Enter your name`，输入后会`hello`输入的内容。

这几个字符串都是线索呀！`Shift+F12`进入字符串视图寻找线索。

进入视图搜索`enter`，找到目标字符串，点到所处地址，再按`X`交叉引用，嗯这是基本操作！然后就找到了这个函数，地址`0x00401020`。

```c
int hello()
{
  int v0; // eax
  int v1; // eax
  int v2; // eax
  int v4; // [esp-4h] [ebp-108h]
  char v5[256]; // [esp+0h] [ebp-104h] BYREF

  v0 = sub_4041F8(0);
  sub_404527(v0, 0, 4, 0);
  v1 = sub_4041F8(1);
  sub_404527(v1, 0, 4, 0);
  v2 = sub_4041F8(2);
  sub_404527(v2, 0, 4, 0);
  sub_401130("Buffer @ %p\n", v5); //打印v5的地址（在栈上）
  sub_401130("Cookie : %08X\n", v4);
  sub_401130(aEnterYourName);
  sub_4063F5(v5);//这应该就是对v5写入了
  sub_401130("Hello, %s!\n", v5);
  return 0;
}
```

看到这里，这题也是没什么新意，因为点进`sub_4063F5`这个函数可以发现，它的限制最大输入长度仍然是`-1`，也就是还是存在溢出风险！

`v5`的位置是`[esp+0h] [ebp-104h]`，大小256字节，也就是写到`ebp`要写260字节，然后再写到`ret addr`要264字节，最后我们再写入4字节的`ret addr`，目标`get_flag`的地址`0x00401000`。

#### 套用脚本

套用AI给我们的脚本，我修改了一下payload，产物`exp/exp.py`，配置好token靶机和flag靶机后，直接`python exp.py`即可......

#### 纠正！

没有得到预期的结果，让我们进入汇编语言中再看看，而不是还是关注反编译代码！

```
add     esp, 8
xor     eax, eax
mov     ecx, [ebp+var_4]
xor     ecx, ebp        ; StackCookie
call    @__security_check_cookie@4 ; __security_check_cookie(x)
mov     esp, ebp
pop     ebp
```

最后两行是正常的return语言，但是在打印`Hello`之后，`ret`之前，还call了一个函数：

```
cmp     ecx, ___security_cookie
jnz     short loc_401173
retn
loc_401173:
jmp     sub_4013F4
```

那我们肯定是想要这个函数完整结束的，也就是执行`retn`，这需要`ecx`和`___security_cookie`相同！（内容`0xBB40E64E`）。

推导过程如下：

- `add esp, 8`和`xor eax, eax`都没啥用，`[ebp+var_4]`是写入的`257-260`字节，并且`ecx = ebp xor [ebp+var_4]`。

- 现在`ecx = 0xBB40E64E`，所以`[ebp+var_4] = ebp xor 0xBB40E64E`。

- `v5`的地址告诉了我们（直接连接时），是`0x0019FE24`，所以`ebp = 0x0019FE24 + 0x104 = 0x0019FF28`

- 计算出`[ebp+var_4] = 0x0019FF28 xor 0xBB40E64E = 0xBB591966`

最终payload是：256字节任意字符+`0xBB591966`+4字节任意字符+`0x00401000`

还是不对！**原来每次生成的`cookie`都不一样！**`ecx = 0xBB40E64E`不绝对，必须按照当时会话的来！payload修改对应部分。

这次对了！我让AI按需求修改一下脚本，脚本`exp/exp.py`。配置好token靶机和flag靶机后，直接`python exp.py`即可！（真的）

#### 总结与防御建议

总结，依旧从字符串入手，依旧`ret2text`，必要时看汇编代码，over。

防御建议：依旧关注一切形式的溢出，用户输入限制长度应该与缓冲区大小匹配。


