### 高级工具与逆向专项-Ghidra工具使用-G4

这仍然是一个flag判断程序，其中核心的函数是`verify`这个函数。

让我们分析一下它！

```c
bool verify(char *param_1)

{
  int iVar1;
  size_t sVar2;
  longlong lVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  bool bVar6;
  undefined1 local_78;
  undefined1 local_77;
  undefined1 local_76;
  undefined1 local_75;
  undefined1 local_74;
  undefined4 local_73 [9];
  undefined1 local_4f;
  undefined1 local_4e;
  undefined4 local_48 [12];
  
  sVar2 = strlen(param_1);
  bVar6 = false;
  if ((sVar2 == 0x2a) && (param_1[0x29] == '}')) {
    puVar4 = local_48;//数组退化
    for (lVar3 = 0x25; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined1 *)puVar4 = 0;
      puVar4 = (undefined4 *)((longlong)puVar4 + 1);
    }//for循环初始化local_48缓冲区，这是一个37字节缓冲区
    vm_run(0x140004060,(longlong)local_48);//对缓冲区进行操作
    local_78 = 0x66;//0x66是f，local_78是栈上真实flag的缓冲区，42字节
    local_77 = 0x6c;
    local_76 = 0x61;
    local_75 = 0x67;
    local_74 = 0x7b;
    puVar4 = local_48;
    puVar5 = local_73;
    for (lVar3 = 9; lVar3 != 0; lVar3 = lVar3 + -1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }//这是在搬local_48缓冲区的内容到，local_78的缓冲区上——puvar4、5都是4字节指针，36字节办9次循环
    local_4f = 0x7d;
    local_4e = 0;
    iVar1 = memcmp(param_1,&local_78,0x2b);//比较
    bVar6 = iVar1 == 0;
  }
  return bVar6;
}


```

看来现在需要跟进`vm_run`这个函数了！

```c
void vm_run(longlong param_1,longlong param_2)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  byte abStack_48 [72];
  
  iVar2 = 0;
  iVar4 = 0;
  while( true ) {
    iVar3 = iVar2 + 1;
    if (5 < *(byte *)(param_1 + iVar2)) break;
                    /* WARNING: Could not find normalized switch variable to match jumptable */
    switch(*(undefined1 *)(param_1 + iVar2)) {
    case 0:
      goto switchD_1400014c5_caseD_0;
    case 1:
      iVar2 = iVar2 + 2;
      abStack_48[iVar4] = *(byte *)(param_1 + iVar3);
      iVar4 = iVar4 + 1;
      break;
    case 2:
      abStack_48[iVar4 + -2] = abStack_48[iVar4 + -2] ^ abStack_48[iVar4 + -1];
      iVar2 = iVar3;
      iVar4 = iVar4 + -1;
      break;
    case 3:
      pbVar1 = abStack_48 + (iVar4 + -1);
      *pbVar1 = *pbVar1 << 1 | (char)*pbVar1 < '\0';
      iVar2 = iVar3;
      break;
    case 4:
      abStack_48[iVar4 + -1] = abStack_48[iVar4 + -1] + *(char *)(param_1 + iVar3);
      iVar2 = iVar2 + 2;
      break;
    case 5:
      *(byte *)(param_2 + (ulonglong)*(byte *)(param_1 + iVar3)) = abStack_48[iVar4 + -1];
      iVar2 = iVar2 + 2;
      iVar4 = iVar4 + -1;
    }
  }
switchD_1400014c5_caseD_0:
  return;
}


```

- 整个函数对输入的`0x140004060`用`*(byte *)(param_1 + iVar2)`只做读操作。

- 整个函数是在模拟指令执行，有1-5五种指令，0表示退出。它用计算的方式防止flag在程序中硬编码，必须模拟跑一遍该程序（反静态分析）。

- 该程序用到的数据，即输入的`0x140004060`开始的字节流，把他dump下来，咱们本地重构一下该函数，运行即可。

脚本（AI重构）放在`get_flag/get_flag.py`，所有内容均为硬编码，直接`python get_flag.py`即可。
