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

# Exploit