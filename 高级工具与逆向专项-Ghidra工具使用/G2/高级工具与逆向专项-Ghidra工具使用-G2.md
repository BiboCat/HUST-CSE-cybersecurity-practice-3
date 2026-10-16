### 高级工具与逆向专项-Ghidra工具使用-G2

核心函数是`verify`，重写后的代码如下：

```c
bool verify(char *input_flag)
{
    uint8_t     b0, b1, key;
    int         cmp_result;
    size_t      flag_len;
    longlong    wipe_i;
    uint        sum;
    char       *out_ptr;
    Node       *cur_node;

    char        rebuilt[56];
    bool        ok;

    flag_len = strlen(input_flag);
    ok = false;

    if (flag_len == 0x2A) {
        cmp_result = strncmp(input_flag, "flag{", 5);
        if (cmp_result == 0) {
            ok = false;
            if (input_flag[0x29] == '}') { 
                //清空 37(=0x25) 字节的输出缓冲区
                out_ptr = &g_output;
                for (wipe_i = 0x25; wipe_i != 0; wipe_i--) {
                    *out_ptr = 0;
                    out_ptr++;
                }

                //遍历链表，按 key 指定的下标写入解密字符
                for (cur_node = g_head; cur_node != NULL; cur_node = cur_node->next) {
                    b0  = cur_node->b0;
                    b1  = cur_node->b1;
                    key = cur_node->key;
                    sum = (uint)b0 + (uint)b1 + (uint)key;

                    //校验和自洽
                    if (cur_node->chk == (uint8_t)sum && key < 0x24) {
                        (&g_output)[(int)(uint)key] = b0 ^ b1;
                    }
                }

                //拼回完整 flag 并比较
                g_output_end = 0;
                snprintf(rebuilt, 0x2B, "flag{%s}", &g_output);
                cmp_result = strcmp(input_flag, rebuilt);
                ok = (cmp_result == 0);
            }
        } else {
            ok = false;
        }
    }
    return ok;
}
```

链表数据结构大致如下：

```c
typedef struct Node {
    uint8_t b0;
    uint8_t b1;//b0 ^ b1是真实flag字符
    uint8_t key;
    uint8_t chk;//和key一起发挥作用，用于自检，只有满足 chk == (b0+b1+key) & 0xFF 的节点才会被采信
    //4 字节 padding
    struct Node *next;//+8取next
} Node;
```

所以现在只需要拿到链表内容，即可自己异或出明文了！

对链表头交叉引用，定位到`init_list`函数：

```c
void init_list(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined1 *puVar3;
  
  puVar3 = &g_raw;
  puVar1 = &DAT_140007084;
  iVar2 = 0;
  while( true ) {
    *(undefined1 *)(puVar1 + -1) = *puVar3;
    *(undefined1 *)((longlong)puVar1 + -3) = puVar3[1];
    *(undefined1 *)((longlong)puVar1 + -2) = puVar3[2];
    *(undefined1 *)((longlong)puVar1 + -1) = puVar3[3];
    *puVar1 = 0;
    if (iVar2 == 0x26) break;
    *(undefined4 **)(puVar1 + 1) = puVar1 + 3;
    iVar2 = iVar2 + 1;
    puVar3 = puVar3 + 4;
    puVar1 = puVar1 + 4;
  }
  _DAT_1400072e8 = 0;
  g_head = &g_nodes;
  return;
}
```

大致逻辑就是只想一个叫`g_raw`的变量，里面硬编码的是链表的数据。

值得注意的是，数据有39*4字节，共39个节点；而我们只需要36个节点数据——这说明其中很可能有三个是无效节点（chk校验不通过）。

按照以上思路写出解题脚本，位置`get_flag/get_flag.py`，直接`python get_flag.py`即可。
