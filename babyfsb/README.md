# babyfsb

# Reverse

Kiểm tra thông số của file babyfsb
```sh
thanhnt@THANGNT-ZIR:/mnt/c/Users/n18dc/OneDrive/Desktop$ file babyfsb
babyfsb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a9751ebe4ad3531ce23247319eeb5992e99bf328, not stripped
```
Dùng lệnh checksec để xem một số cơ chế bảo vệ file

```sh
pwndbg> checksec
[*] '/mnt/c/Users/n18dc/OneDrive/Desktop/babyfsb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

pwndbg>
```

Partial RELRO = dễ dàng ghi đè vùng GOT.
Canary found = ngăn chặn BOF (buffer overflow), nếu ghi dè vùng này, chương trình sẽ báo lỗi.

Dùng IDA để xem pseudo code của file.
![main_func](https://github.com/zirami/HackCTF/blob/main/babyfsb/images/mainv2.png)

Chương trình in ra dòng "hello", sau đó cho nhập 0x40 byte vào biến char buffer[56] - (BOF), và in ra giá trị buffer vừa nhập - FSB.


# Exploit

Trước hết cần phải tạo vòng lặp cho chương trình quay về hàm main sau khi thực hiện print(buf), nhưng sau hàm print(buf) không thấy hàm nào khác được gọi.
Nhưng chúng ta có Canary found, chức năng thêm Canary vào stack nhằm ngăn chặn việc BOF, nếu ghi đè chương trình sẽ gọi một hàm khác gọi là <__stack_chk_fail@plt> để hiển thị thông báo và thoát.

```sh
*** stack smashing detected ***: <unknown> terminated
Aborted
```
Lợi dùng việc tràn canary, gọi hàm __stack_chk_fail@plt để quay về main, bằng việc thay đổi __stack_chk_fail@got = main

Sau đó, sẽ thực hiện leak địa chỉ libc, tính libc_base và gọi shell.

# FLAG HackCTF{v3ry_v3ry_345y_f5b!!!}