### 系统层漏洞利用与逆向分析-DEP数据执行保护利用-G3

#### 缓冲区存在溢出风险

连接，返回`Secure vault. Unlock before accessing.`还有一个`Input`输入框。输入一个1后没发生啥。

打开IDA，`Input`的逻辑在`vuln`中，它很简单：

```c
int vuln()
{
  char v1[256]; // [esp+0h] [ebp-100h] BYREF

  sub_401140(aInput, v1[0]);
  return sub_406405(v1);
}
```

`sub_406405`是一个对缓冲区输入函数，其中的最大写入限制设置`-1`，也就是无限写入，存在缓冲区溢出风险！

对`vuln`按`X`，发现另一个函数调用了它（我重命名为`call_vuln`），里面包含打印`Secure vault. Unlock before accessing.`的逻辑，但是这个函数没啥用，就不讨论了。

既然存在缓冲区溢出，那么就看`ret2text`还能不能用。

#### 利用链确定

```c
int get_flag()
{
  if ( dword_41D9B8 == -889275714 )
  {
    GetFlag();
    ExitProcess(0);
  }
  return echo_(aNotUnlockedCur);
}
```

`get_flag()`含有一个检查，`dword_41D9B8`是一个处于数据段的全局变量。我们无法通过直接溢出覆写写到它，但是按`X`，可以看到函数`set_key`使用了它！

```c
int __cdecl set_key(int a1)
{
  int result; // eax

  result = a1;
  dword_41D9B8 = a1;
  return result;
}
```

那这题就没什么好说的了：
先调用`set_key`设置`dword_41D9B8`为`0xCAFEBABE`；
再调用`get_flag`获取token。

#### 计算偏移量

要一次性先后触发两个函数，就让我们先试试第一层吧！

`vuln`函数缓冲区写入260个字节内容（256缓冲区大小+4 saved ebp），再在`vuln ret addr`中写入`set_key`的地址。

进入`set_key`中，在原先`vuln ret addr`的位置写入`set_key saved ebp`，拿取`set_key ebp+8`的内容，然后修改了那个全局变量，最后pop`set_key saved ebp`，**并且把<u>原先</u>`set_key ebp+4`作为它的`set_key ret addr`返回**。*最后这句说明我们还有重定向空间！*

如果我们把运行时的`set_key ebp+4`写回`get_flag`，那么我们就完成了第二次调用！

而`set_key ebp+4`其实就是第一次的`vuln ret addr+4`的位置；不占用`set_key`参数的`vuln ret addr+8`的位置。

这么推导就懂了吧！让我们构造payload：

```
0-259字节：任意
260-263字节：`set_key`位置
264-267字节：`get_flag`位置
268-271字节：`0xCAFEBABE`
```

最终我还是使用老脚本修改一下payload，一键获取flag！(`exp/exp.py`)

配置好token靶机地址和flag靶机地址，再`python exp.py`即可。

#### 总结

还是栈帧调用关系，仔细一考虑就行了，越想越熟练了。

防御策略依旧是：**关注任何形式的溢出，限制长度和缓冲区大小匹配**。
