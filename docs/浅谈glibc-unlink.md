---
title: 浅谈glibc-unlink
date: 2019-03-29 00:42:56
tags:
---

刚开始看ctf-wiki上的unlink的原理介绍的时候简直一脸懵逼，后来上手这题stkof实战，同时看了其他writeup之后，终于算是有了些浅薄的理解。因此把unlink的过程记录下来，防止以后忘了。

<!--more-->

#### 什么是unlink？

unlink就是把一个空闲chunk从双向链表（如small bin）中拿出来，例如分配新chunk，或是free(p)时和p物理相邻的空闲chunk会和p进行前/后向合并（本文主要讲这种）。unlink的基本过程如下（图来自ctf-wiki）：

![1553697853937](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/figure/unlink_smallbin_intro.png)

当有物理地址相邻的两个chunk，按地址从低到高chunk1-chunk2，其中chunk1是空闲状态，chunk2是分配状态，且chunk2为small chunk（large chunk似乎也可以，以后再研究下），这时候执行free(chunk2)，就会进行如下检测：

###### 后向合并：

检测chunk2的prev_in_use位，看chunk1是否为空闲，若为空闲，则两个chunk内存合并，指向chunk2的指针改为指向chunk1，接着使用unlink宏，把chunk1从双向链表中移除，chunk1进入unsorted bin。

```c
if (!prev_inuse(p)) {
    prevsize = prev_size(p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    unlink(av, p, bck, fwd);
}
```

###### 前向合并：

跟后向合并原理相似，检测chunk2的下个chunk（chunk3，物理地址比chunk2高）是否为空闲，空闲则合并，触发unlink宏，把chunk3从双向链表中移除。



#### 利用：

###### 理想：

了解了unlink的触发机制后，我们就要想怎么利用它了。显然，要把chunk1从链表中移除，最重要的就是fd和bk指针了，所以我们从它下手。回到上面的图中，我们构造：（P为chunk1地址）

- `FD=P->fd = target addr -12`
- `BK=P->bk = expect value`

根据unlink宏，会有以下操作：

- `FD->bk = BK`，即 `FD->bk= *(target addr-12+12)=BK=expect value`，即 `*(target addr)=expect value`
- `BK->fd = FD`，即 `*(expect value +8) = FD = target addr-12`

由此可实现任意地址写，例如修改GOT表项。虽然expect value +8地址的值被覆盖了有可能有小问题。

###### 现实：

理想很丰满，现实很骨感，怎么可能随随便便就让你利用。。。实际上，在glibc中还有这个检测机制：

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
```

按照上面构造，则有FD->bk=*(target addr)，若为GOT表项则不可能等于P，因此出错。但既然只是地址比较，那我们只要找（或者伪造）一个地址，里面存着P的地址不就解决了？所以我们可以考虑这样绕过检测机制：

先定义`chunk1->fd=fakeFD，chunk1->bk=fakeBK，*Q=P`

然后构造使得

- `fakeFD->bk==P`，即`*(fakeFD+12)=P，Q=fakeFD+12``
- `fakeBK->fd=P`，即`*(fakeBK+8)=P，Q=fakeBK+8``

| 地址          | 值   |
| :------------ | :--- |
| +00:   fakeFD |      |
| +04:   fakeBK |      |
| +08           |      |
| +12:     Q    | P    |

这样便满足条件，绕过了检测机制，从而调用unlink宏：

- `fakeFD->bk=fakeBK`，即`*(fakeFD+12)=fakeBK`
- `fakeBK->fd=fakeFD`，即`*(fakeBK+8)=fakeFD`

又由上面的构造条件可得：

- `*Q=Q-8`
- `*Q=Q-12`

至此，Q处的值被改为Q-12。

**PS：以上都是以32位系统为前提，若为64位系统，则偏移相应要修改，如+12变为+0x18，+8变为+0x10。**



对应题目：[2014HITCON stkof](https://github.com/CP32/ctf-pwn/tree/master/2014%20HITCON%20stkof)



参考资料：

[CTF-Wiki Unlink](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/unlink/)

