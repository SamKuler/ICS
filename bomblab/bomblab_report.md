# Bomb Lab 实验报告
###### By Zeng GuanYang

---

根据`bomb.c`的文件，炸弹的每个阶段都会读入一行字符串，作为每个阶段函数的参数。第六个阶段没有打印字符串，这可能是隐藏阶段的入口。

对于ELF文件，采用`objdump -S`或者`objdump -D`来反编译。
运行时采用`gdb`进行调试。采用`layout regs`查看汇编以及寄存器情况。

### Phase1

<details>
<summary>
利用objdump得到反编译结果。
</summary>

```s
0000000000001607 <phase_1>:
    1607:	f3 0f 1e fa          	endbr64 
    160b:	48 83 ec 08          	sub    $0x8,%rsp
    160f:	48 8d 35 ba 1c 00 00 	lea    0x1cba(%rip),%rsi        # 32d0 <_IO_stdin_used+0x2d0>
    1616:	e8 0e 05 00 00       	call   1b29 <strings_not_equal>
    161b:	85 c0                	test   %eax,%eax
    161d:	75 05                	jne    1624 <phase_1+0x1d>
    161f:	48 83 c4 08          	add    $0x8,%rsp
    1623:	c3                   	ret    
    1624:	e8 23 06 00 00       	call   1c4c <explode_bomb>
    1629:	eb f4                	jmp    161f <phase_1+0x18>
```
</details>

可以看到，`phase_1`首先计算`0x1cba(%rip)`，放入`%rsi`，作为`strings_not_equal`的第二个参数，第一个参数就是`phase_1`的参数。
<details>
<summary>
看到strings_not_equal函数
</summary>

```s
0000000000001b29 <strings_not_equal>:
    1b29:	f3 0f 1e fa          	endbr64 
    1b2d:	41 54                	push   %r12
    1b2f:	55                   	push   %rbp
    1b30:	53                   	push   %rbx
    1b31:	48 89 fb             	mov    %rdi,%rbx
    1b34:	48 89 f5             	mov    %rsi,%rbp
    1b37:	e8 cc ff ff ff       	call   1b08 <string_length>
    1b3c:	41 89 c4             	mov    %eax,%r12d
    1b3f:	48 89 ef             	mov    %rbp,%rdi
    1b42:	e8 c1 ff ff ff       	call   1b08 <string_length>
    1b47:	89 c2                	mov    %eax,%edx
    1b49:	b8 01 00 00 00       	mov    $0x1,%eax
    1b4e:	41 39 d4             	cmp    %edx,%r12d
    1b51:	75 31                	jne    1b84 <strings_not_equal+0x5b>
    1b53:	0f b6 13             	movzbl (%rbx),%edx
    1b56:	84 d2                	test   %dl,%dl
    1b58:	74 1e                	je     1b78 <strings_not_equal+0x4f>
    1b5a:	b8 00 00 00 00       	mov    $0x0,%eax
    1b5f:	38 54 05 00          	cmp    %dl,0x0(%rbp,%rax,1)
    1b63:	75 1a                	jne    1b7f <strings_not_equal+0x56>
    1b65:	48 83 c0 01          	add    $0x1,%rax
    1b69:	0f b6 14 03          	movzbl (%rbx,%rax,1),%edx
    1b6d:	84 d2                	test   %dl,%dl
    1b6f:	75 ee                	jne    1b5f <strings_not_equal+0x36>
    1b71:	b8 00 00 00 00       	mov    $0x0,%eax
    1b76:	eb 0c                	jmp    1b84 <strings_not_equal+0x5b>
    1b78:	b8 00 00 00 00       	mov    $0x0,%eax
    1b7d:	eb 05                	jmp    1b84 <strings_not_equal+0x5b>
    1b7f:	b8 01 00 00 00       	mov    $0x1,%eax
    1b84:	5b                   	pop    %rbx
    1b85:	5d                   	pop    %rbp
    1b86:	41 5c                	pop    %r12
    1b88:	c3                   	ret    
```
看到首先调用了`string_length`函数。
<details>
<summary>
看到string_length函数。
</summary>

```s
0000000000001b08 <string_length>:
    1b08:	f3 0f 1e fa          	endbr64 
    1b0c:	80 3f 00             	cmpb   $0x0,(%rdi)
    1b0f:	74 12                	je     1b23 <string_length+0x1b>
    1b11:	b8 00 00 00 00       	mov    $0x0,%eax
    1b16:	48 83 c7 01          	add    $0x1,%rdi
    1b1a:	83 c0 01             	add    $0x1,%eax
    1b1d:	80 3f 00             	cmpb   $0x0,(%rdi)
    1b20:	75 f4                	jne    1b16 <string_length+0xe>
    1b22:	c3                   	ret    
    1b23:	b8 00 00 00 00       	mov    $0x0,%eax
    1b28:	c3                   	ret  
```
这个函数首先判断了`%rdi`存的指针是否为空，空则返回0，否则循环判断，类似于
```c
for(eax=0;rdi!=NULL;rdi++,eax++);
```
`%rdi`的值发生了改变。调用者保存了原来的地址值。
</details>

此时`%r12d`储存第一个字符串的长度，`%edx`储存第二个字符串的长度。若二者不相等，则函数直接返回1（`%eax`赋值储存）。随后检测`%rbx`（即第一个参数）是否为空，是则返回0，否则依字符比较每一位，类似于
```c
dl=*rbx
eax=0;
while (dl==*(rpb+eax))
{
    eax++;
    dl = *(rbx+eax);
    if ( dl==0 )
        return 0LL;
}
return 1LL;
```
此时两字符串相等返回0，否则返回1。
</details>

由`test`知，要求函数返回值为0。故`input`的要求即是`0x1cba(%rip)`所在字符串。运行时利用gdb可知，此时的地址是`0x0x5555555572d0`，利用`x/s 0x5555555572d0`得到要输入的字符串就是
```
Verbosity leads to unclear, inarticulate things.
```
第一个阶段拆除。

### Phase2

<details>
<summary>
反编译结果
</summary>

```s
000000000000162b <phase_2>:
    162b:	f3 0f 1e fa          	endbr64 
    162f:	55                   	push   %rbp
    1630:	53                   	push   %rbx
    1631:	48 83 ec 28          	sub    $0x28,%rsp
    1635:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    163c:	00 00 
    163e:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    1643:	31 c0                	xor    %eax,%eax
    1645:	48 89 e6             	mov    %rsp,%rsi
    1648:	e8 2b 06 00 00       	call   1c78 <read_six_numbers>
    164d:	83 3c 24 01          	cmpl   $0x1,(%rsp)
    1651:	75 0a                	jne    165d <phase_2+0x32>
    1653:	48 89 e3             	mov    %rsp,%rbx
    1656:	48 8d 6c 24 14       	lea    0x14(%rsp),%rbp
    165b:	eb 10                	jmp    166d <phase_2+0x42>
    165d:	e8 ea 05 00 00       	call   1c4c <explode_bomb>
    1662:	eb ef                	jmp    1653 <phase_2+0x28>
    1664:	48 83 c3 04          	add    $0x4,%rbx
    1668:	48 39 eb             	cmp    %rbp,%rbx
    166b:	74 10                	je     167d <phase_2+0x52>
    166d:	8b 03                	mov    (%rbx),%eax
    166f:	01 c0                	add    %eax,%eax
    1671:	39 43 04             	cmp    %eax,0x4(%rbx)
    1674:	74 ee                	je     1664 <phase_2+0x39>
    1676:	e8 d1 05 00 00       	call   1c4c <explode_bomb>
    167b:	eb e7                	jmp    1664 <phase_2+0x39>
    167d:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
    1682:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    1689:	00 00 
    168b:	75 07                	jne    1694 <phase_2+0x69>
    168d:	48 83 c4 28          	add    $0x28,%rsp
    1691:	5b                   	pop    %rbx
    1692:	5d                   	pop    %rbp
    1693:	c3                   	ret    
    1694:	e8 c7 fb ff ff       	call   1260 <_init+0x260>
```
</details>

首先开辟了0x28即40个字节的栈空间，随后将`%rsp`高0x18字节的位置设置为fs:0x28的值，用于异常检测。随后将栈顶指针作为第二个参数传入`read_six_numbers`，第一个参数就是`phase_2`的参数字符串。
<details>
<summary>
看到read_six_numbers函数。
</summary>

```s
0000000000001c78 <read_six_numbers>:
    1c78:	f3 0f 1e fa          	endbr64 
    1c7c:	48 83 ec 08          	sub    $0x8,%rsp
    1c80:	48 89 f2             	mov    %rsi,%rdx
    1c83:	48 8d 4e 04          	lea    0x4(%rsi),%rcx
    1c87:	48 8d 46 14          	lea    0x14(%rsi),%rax
    1c8b:	50                   	push   %rax
    1c8c:	48 8d 46 10          	lea    0x10(%rsi),%rax
    1c90:	50                   	push   %rax
    1c91:	4c 8d 4e 0c          	lea    0xc(%rsi),%r9
    1c95:	4c 8d 46 08          	lea    0x8(%rsi),%r8
    1c99:	48 8d 35 29 14 00 00 	lea    0x1429(%rip),%rsi        # 30c9 <_IO_stdin_used+0xc9>
    1ca0:	b8 00 00 00 00       	mov    $0x0,%eax
    1ca5:	e8 66 f6 ff ff       	call   1310 <_init+0x310>
    1caa:	48 83 c4 10          	add    $0x10,%rsp
    1cae:	83 f8 05             	cmp    $0x5,%eax
    1cb1:	7e 05                	jle    1cb8 <read_six_numbers+0x40>
    1cb3:	48 83 c4 08          	add    $0x8,%rsp
    1cb7:	c3                   	ret    
    1cb8:	e8 8f ff ff ff       	call   1c4c <explode_bomb>
```
此时要调用1310处的函数，此时同过栈的方式传参。这个函数的第一个参数`%rdi`就是参数字符串，第二个参数`%rsi`是0x1429(%rip)处的值，gdb确定为`"%d %d %d %d %d %d"`，其余参数为`%rdx,%rcx,%r8,%r9`以及依次压入栈中的`%rax`值。
代码相当于
```c
sscanf(rdi,"%d %d %d %d %d %d",rsi,rsi+4,rsi+8,rsi+12,rsi+16,rsi+20);
```
将字符串中的数字读入了传入的整数数组中。
最后判断返回值是不是大于5，以验证是否读入了六个数字，否则爆炸。
</details>

我们通过这个函数获得了字符串中的六个数字。  
随后开始对这六个数字进行判断。
```s
    164d:	83 3c 24 01          	cmpl   $0x1,(%rsp)
    1651:	75 0a                	jne    165d <phase_2+0x32>
```
判断第一个数是不是1，否则爆炸。
```s
    1653:	48 89 e3             	mov    %rsp,%rbx
    1656:	48 8d 6c 24 14       	lea    0x14(%rsp),%rbp
    165b:	eb 10                	jmp    166d <phase_2+0x42>
```
将数组指针放到`%rbx`保存，也是第一个元素位置，将`%rsp+20`，也就是数组最后一个元素放入`%rbp`保存，也是最后一个元素位置。随后跳转。
```s
    1664:	48 83 c3 04          	add    $0x4,%rbx
    1668:	48 39 eb             	cmp    %rbp,%rbx
    166b:	74 10                	je     167d <phase_2+0x52>
    166d:	8b 03                	mov    (%rbx),%eax
    166f:	01 c0                	add    %eax,%eax
    1671:	39 43 04             	cmp    %eax,0x4(%rbx)
    1674:	74 ee                	je     1664 <phase_2+0x39>
    1676:	e8 d1 05 00 00       	call   1c4c <explode_bomb>
    167b:	eb e7                	jmp    1664 <phase_2+0x39>
```
这一部分代码相当于
```c
do
{
    eax=*rbx;//DWORD
    eax=eax+eax;
    if(eax!=*(rbx+4))
        explode_bomb();
    rbx+=4;
}while(rbx!=rbp);
```
也就是要求这个数列是一个公比为2的等比数列。
代码其余部分为恢复栈空间以及保存的值、检测异常。

因此要求的输入为
```
1 2 4 8 16 32
```
第二个阶段拆除。

### Phase3

<details>
<summary>
反编译结果
</summary>

```s
0000000000001699 <phase_3>:
    1699:	f3 0f 1e fa          	endbr64 
    169d:	48 83 ec 18          	sub    $0x18,%rsp
    16a1:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    16a8:	00 00 
    16aa:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    16af:	31 c0                	xor    %eax,%eax
    16b1:	48 8d 4c 24 04       	lea    0x4(%rsp),%rcx
    16b6:	48 89 e2             	mov    %rsp,%rdx
    16b9:	48 8d 35 15 1a 00 00 	lea    0x1a15(%rip),%rsi        # 30d5 <_IO_stdin_used+0xd5>
    16c0:	e8 4b fc ff ff       	call   1310 <_init+0x310>
    16c5:	83 f8 01             	cmp    $0x1,%eax
    16c8:	7e 1a                	jle    16e4 <phase_3+0x4b>
    16ca:	83 3c 24 07          	cmpl   $0x7,(%rsp)
    16ce:	77 65                	ja     1735 <phase_3+0x9c>
    16d0:	8b 04 24             	mov    (%rsp),%eax
    16d3:	48 8d 15 06 1e 00 00 	lea    0x1e06(%rip),%rdx        # 34e0 <_IO_stdin_used+0x4e0>
    16da:	48 63 04 82          	movslq (%rdx,%rax,4),%rax
    16de:	48 01 d0             	add    %rdx,%rax
    16e1:	3e ff e0             	notrack jmp *%rax
    16e4:	e8 63 05 00 00       	call   1c4c <explode_bomb>
    16e9:	eb df                	jmp    16ca <phase_3+0x31>
    16eb:	b8 d2 00 00 00       	mov    $0xd2,%eax
    16f0:	39 44 24 04          	cmp    %eax,0x4(%rsp)
    16f4:	75 52                	jne    1748 <phase_3+0xaf>
    16f6:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    16fb:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    1702:	00 00 
    1704:	75 49                	jne    174f <phase_3+0xb6>
    1706:	48 83 c4 18          	add    $0x18,%rsp
    170a:	c3                   	ret    
    170b:	b8 fa 02 00 00       	mov    $0x2fa,%eax
    1710:	eb de                	jmp    16f0 <phase_3+0x57>
    1712:	b8 89 00 00 00       	mov    $0x89,%eax
    1717:	eb d7                	jmp    16f0 <phase_3+0x57>
    1719:	b8 9b 01 00 00       	mov    $0x19b,%eax
    171e:	eb d0                	jmp    16f0 <phase_3+0x57>
    1720:	b8 cf 01 00 00       	mov    $0x1cf,%eax
    1725:	eb c9                	jmp    16f0 <phase_3+0x57>
    1727:	b8 94 02 00 00       	mov    $0x294,%eax
    172c:	eb c2                	jmp    16f0 <phase_3+0x57>
    172e:	b8 77 00 00 00       	mov    $0x77,%eax
    1733:	eb bb                	jmp    16f0 <phase_3+0x57>
    1735:	e8 12 05 00 00       	call   1c4c <explode_bomb>
    173a:	b8 00 00 00 00       	mov    $0x0,%eax
    173f:	eb af                	jmp    16f0 <phase_3+0x57>
    1741:	b8 e2 02 00 00       	mov    $0x2e2,%eax
    1746:	eb a8                	jmp    16f0 <phase_3+0x57>
    1748:	e8 ff 04 00 00       	call   1c4c <explode_bomb>
    174d:	eb a7                	jmp    16f6 <phase_3+0x5d>
    174f:	e8 0c fb ff ff       	call   1260 <_init+0x260>
```
</details>

逐段分析。
```s
    169d:	48 83 ec 18          	sub    $0x18,%rsp
    16a1:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    16a8:	00 00 
    16aa:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    16af:	31 c0                	xor    %eax,%eax
    16b1:	48 8d 4c 24 04       	lea    0x4(%rsp),%rcx
    16b6:	48 89 e2             	mov    %rsp,%rdx
    16b9:	48 8d 35 15 1a 00 00 	lea    0x1a15(%rip),%rsi        # 30d5 <_IO_stdin_used+0xd5>
    16c0:	e8 4b fc ff ff       	call   1310 <_init+0x310>
```
开辟了24字节栈空间，`%fs:0x28`即是金丝雀保护。
随后将`%rsp`，`%rsp+4`作为`%rdx`，`%rcx`，也就是要调用的函数的第三、第四个参数传入。
gdb调用可以看到，`x/s 0x5555555570d5`为`"%d %d"`。
故这部分代码相当于
```c
sscanf(rdi,"%d %d",rsp,rsp+4);
```
随后对结果比较确保了输入的数大于1个，否则explode。
接着对`%rsp`处的值判断是否大于7，是则explode。（对应`default case`）
否则继续执行。
```s
    16d0:	8b 04 24             	mov    (%rsp),%eax
    16d3:	48 8d 15 06 1e 00 00 	lea    0x1e06(%rip),%rdx        # 34e0 <_IO_stdin_used+0x4e0>
    16da:	48 63 04 82          	movslq (%rdx,%rax,4),%rax
    16de:	48 01 d0             	add    %rdx,%rax
    16e1:	3e ff e0             	notrack jmp *%rax
    16e4:	e8 63 05 00 00       	call   1c4c <explode_bomb>
    16e9:	eb df                	jmp    16ca <phase_3+0x31>
    16eb:	b8 d2 00 00 00       	mov    $0xd2,%eax
    16f0:	39 44 24 04          	cmp    %eax,0x4(%rsp)
    16f4:	75 52                	jne    1748 <phase_3+0xaf>
    16f6:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    16fb:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    1702:	00 00 
    1704:	75 49                	jne    174f <phase_3+0xb6>
    1706:	48 83 c4 18          	add    $0x18,%rsp
    170a:	c3                   	ret    
    170b:	b8 fa 02 00 00       	mov    $0x2fa,%eax
    1710:	eb de                	jmp    16f0 <phase_3+0x57>
    1712:	b8 89 00 00 00       	mov    $0x89,%eax
    1717:	eb d7                	jmp    16f0 <phase_3+0x57>
    1719:	b8 9b 01 00 00       	mov    $0x19b,%eax
    171e:	eb d0                	jmp    16f0 <phase_3+0x57>
    1720:	b8 cf 01 00 00       	mov    $0x1cf,%eax
    1725:	eb c9                	jmp    16f0 <phase_3+0x57>
    1727:	b8 94 02 00 00       	mov    $0x294,%eax
    172c:	eb c2                	jmp    16f0 <phase_3+0x57>
    172e:	b8 77 00 00 00       	mov    $0x77,%eax
    1733:	eb bb                	jmp    16f0 <phase_3+0x57>
```
此时将`%rsp`处读取的32位值放入`%eax`中，将0x1e06(%rip)得到的值放入`%rdx`中。
由gdb查看该处内容（`x/16x 0x5555555574e0`）得到
```
(gdb)x/16x x5555555574e0
0x5555555574e0: 0x0b    0xe2    0xff    0xff    0x61    0xe2    0xff    0xff  
0x5555555574e8: 0x2b    0xe2    0xff    0xff    0x32    0xe2    0xff    0xff
0x5555555574f0: 0x39    0xe2    0xff    0xff    0x40    0xe2    0xff    0xff
0x5555555574f8: 0x47    0xe2    0xff    0xff    0x4e    0xe2    0xff    0xff
```
此时会根据`%rax`值来获得下面`jmp`要跳转的地址为`%rdx+(%rdx+4*%rax)`
利用gdb可得到跳表为
| %eax          | 0              | 1              | 2              | 3              | 4              | 5              | 6              | 7              |
| ------------- | -------------- | -------------- | -------------- | -------------- | -------------- | -------------- | -------------- | -------------- |
| (%rdx+4*%rax) | 0xffffe20b     | 0xffffe261     | 0xffffe22b     | 0xffffe232     | 0xffffe239     | 0xffffe240     | 0xffffe247     | 0xffffe24e     |
| 跳转地址      | 0x5555555556eb | 0x555555555741 | 0x55555555570b | 0x555555555712 | 0x555555555719 | 0x555555555720 | 0x555555555727 | 0x55555555572e |

在这些跳转地址处，均有`mov`指令，将一个常数放入`%eax`中，然后跳转到`16f0`处，比较`%eax`和`0x4(%rsp)`的值。
因此，可能的输入有8对，（也就是switch的各个分支）。
```
0 210
1 738
2 762
3 137
4 411
5 463
6 660
7 119
```
第三个阶段拆除。

### Phase4

<details>
<summary>
反编译结果
</summary>

```s
0000000000001795 <phase_4>:
    1795:	f3 0f 1e fa          	endbr64 
    1799:	48 83 ec 18          	sub    $0x18,%rsp
    179d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    17a4:	00 00 
    17a6:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    17ab:	31 c0                	xor    %eax,%eax
    17ad:	48 8d 4c 24 04       	lea    0x4(%rsp),%rcx
    17b2:	48 89 e2             	mov    %rsp,%rdx
    17b5:	48 8d 35 19 19 00 00 	lea    0x1919(%rip),%rsi        # 30d5 <_IO_stdin_used+0xd5>
    17bc:	e8 4f fb ff ff       	call   1310 <_init+0x310>
    17c1:	83 f8 02             	cmp    $0x2,%eax
    17c4:	75 06                	jne    17cc <phase_4+0x37>
    17c6:	83 3c 24 0e          	cmpl   $0xe,(%rsp)
    17ca:	76 05                	jbe    17d1 <phase_4+0x3c>
    17cc:	e8 7b 04 00 00       	call   1c4c <explode_bomb>
    17d1:	ba 0e 00 00 00       	mov    $0xe,%edx
    17d6:	be 00 00 00 00       	mov    $0x0,%esi
    17db:	8b 3c 24             	mov    (%rsp),%edi
    17de:	e8 71 ff ff ff       	call   1754 <func4>
    17e3:	0b 44 24 04          	or     0x4(%rsp),%eax
    17e7:	74 05                	je     17ee <phase_4+0x59>
    17e9:	e8 5e 04 00 00       	call   1c4c <explode_bomb>
    17ee:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    17f3:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    17fa:	00 00 
    17fc:	75 05                	jne    1803 <phase_4+0x6e>
    17fe:	48 83 c4 18          	add    $0x18,%rsp
    1802:	c3                   	ret    
    1803:	e8 58 fa ff ff       	call   1260 <_init+0x260>
```
</details>

分段来看：
```s
    1799:	48 83 ec 18          	sub    $0x18,%rsp
    179d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    17a4:	00 00 
    17a6:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    17ab:	31 c0                	xor    %eax,%eax
    17ad:	48 8d 4c 24 04       	lea    0x4(%rsp),%rcx
    17b2:	48 89 e2             	mov    %rsp,%rdx
    17b5:	48 8d 35 19 19 00 00 	lea    0x1919(%rip),%rsi        # 30d5 <_IO_stdin_used+0xd5>
    17bc:	e8 4f fb ff ff       	call   1310 <_init+0x310>
    17c1:	83 f8 02             	cmp    $0x2,%eax
    17c4:	75 06                	jne    17cc <phase_4+0x37>
    17c6:	83 3c 24 0e          	cmpl   $0xe,(%rsp)
    17ca:	76 05                	jbe    17d1 <phase_4+0x3c>
    17cc:	e8 7b 04 00 00       	call   1c4c <explode_bomb>
```
由Phase3可知，`call <_init+0x310>`实际上是调用`__isoc99_sscanf`。
并且要求读取个数为2，%rsp处的值要小于等于14。
因此这一部分代码相当于
```c
if(sscanf(rdi,"%d %d",rsp,rsp+4)!=2||*(rsp)>14)
    explode_bomb();
```
接着
```s
    17d1:	ba 0e 00 00 00       	mov    $0xe,%edx
    17d6:	be 00 00 00 00       	mov    $0x0,%esi
    17db:	8b 3c 24             	mov    (%rsp),%edi
    17de:	e8 71 ff ff ff       	call   1754 <func4>
    17e3:	0b 44 24 04          	or     0x4(%rsp),%eax
    17e7:	74 05                	je     17ee <phase_4+0x59>
    17e9:	e8 5e 04 00 00       	call   1c4c <explode_bomb>
```
调用了`fun4`函数，此时参数分别为`(%rsp)`，0，14。

<details>
<summary>
看到func4函数
</summary>

```s
0000000000001754 <func4>:
    1754:	f3 0f 1e fa          	endbr64 
    1758:	48 83 ec 08          	sub    $0x8,%rsp
    175c:	89 d0                	mov    %edx,%eax
    175e:	29 f0                	sub    %esi,%eax
    1760:	89 c1                	mov    %eax,%ecx
    1762:	c1 e9 1f             	shr    $0x1f,%ecx
    1765:	01 c1                	add    %eax,%ecx
    1767:	d1 f9                	sar    %ecx
    1769:	01 f1                	add    %esi,%ecx
    176b:	39 f9                	cmp    %edi,%ecx
    176d:	7f 0c                	jg     177b <func4+0x27>
    176f:	b8 00 00 00 00       	mov    $0x0,%eax
    1774:	7c 11                	jl     1787 <func4+0x33>
    1776:	48 83 c4 08          	add    $0x8,%rsp
    177a:	c3                   	ret    
    177b:	8d 51 ff             	lea    -0x1(%rcx),%edx
    177e:	e8 d1 ff ff ff       	call   1754 <func4>
    1783:	01 c0                	add    %eax,%eax
    1785:	eb ef                	jmp    1776 <func4+0x22>
    1787:	8d 71 01             	lea    0x1(%rcx),%esi
    178a:	e8 c5 ff ff ff       	call   1754 <func4>
    178f:	8d 44 00 01          	lea    0x1(%rax,%rax,1),%eax
    1793:	eb e1                	jmp    1776 <func4+0x22>
```
此时是递归调用。
整理后相当于
```c
int func4(rdi,rsi,rdx)
{
    int ecx=(edx-esi)/2+esi;
    if(ecx>edi)
    {
        return 2*func4(rdi,rsi,rcx-1);
    }
    eax=0;
    if(ecx<edi)
    {
        return 2*func4(rdi,rcx+1,rdx)+1;
    }
    return eax;
}
```
因此，`func4`相当于二分递归，直到范围确定到`%rdi`，此时再返回0。
</details>

最后判断`func4`的返回值或上`%rsp+4`处的值，结果为0则通过，否则爆炸。
此时代码相当于
```c
if(func4(*rsp,0,14)|*(rsp+4))
    explode_bomb();
```
因此我们可以设计输入为
```
0 0
```
此时`func4`由于一直向左端逼近，因此最后返回值是0。故第二个输入为0可通过。  
第四个阶段拆除。

### Phase5

<details>
<summary>
反编译结果
</summary>

```s
0000000000001808 <phase_5>:
    1808:	f3 0f 1e fa          	endbr64 
    180c:	53                   	push   %rbx
    180d:	48 89 fb             	mov    %rdi,%rbx
    1810:	e8 f3 02 00 00       	call   1b08 <string_length>
    1815:	83 f8 06             	cmp    $0x6,%eax
    1818:	75 2c                	jne    1846 <phase_5+0x3e>
    181a:	48 89 d8             	mov    %rbx,%rax
    181d:	48 8d 7b 06          	lea    0x6(%rbx),%rdi
    1821:	b9 00 00 00 00       	mov    $0x0,%ecx
    1826:	48 8d 35 d3 1c 00 00 	lea    0x1cd3(%rip),%rsi        # 3500 <array.0>
    182d:	0f b6 10             	movzbl (%rax),%edx
    1830:	83 e2 0f             	and    $0xf,%edx
    1833:	03 0c 96             	add    (%rsi,%rdx,4),%ecx
    1836:	48 83 c0 01          	add    $0x1,%rax
    183a:	48 39 f8             	cmp    %rdi,%rax
    183d:	75 ee                	jne    182d <phase_5+0x25>
    183f:	83 f9 3b             	cmp    $0x3b,%ecx
    1842:	75 09                	jne    184d <phase_5+0x45>
    1844:	5b                   	pop    %rbx
    1845:	c3                   	ret    
    1846:	e8 01 04 00 00       	call   1c4c <explode_bomb>
    184b:	eb cd                	jmp    181a <phase_5+0x12>
    184d:	e8 fa 03 00 00       	call   1c4c <explode_bomb>
    1852:	eb f0                	jmp    1844 <phase_5+0x3c>
```
</details>

分段来看。
```s
    180d:	48 89 fb             	mov    %rdi,%rbx
    1810:	e8 f3 02 00 00       	call   1b08 <string_length>
    1815:	83 f8 06             	cmp    $0x6,%eax
    1818:	75 2c                	jne    1846 <phase_5+0x3e>
```
此时调用了`string_length`函数，并且判断长度是否为6。否则爆炸（`jne`跳转）。因此输入的字符串长度要求为6。
```s
    181a:	48 89 d8             	mov    %rbx,%rax
    181d:	48 8d 7b 06          	lea    0x6(%rbx),%rdi
    1821:	b9 00 00 00 00       	mov    $0x0,%ecx
    1826:	48 8d 35 d3 1c 00 00 	lea    0x1cd3(%rip),%rsi        # 3500 <array.0>
    182d:	0f b6 10             	movzbl (%rax),%edx
    1830:	83 e2 0f             	and    $0xf,%edx
    1833:	03 0c 96             	add    (%rsi,%rdx,4),%ecx
    1836:	48 83 c0 01          	add    $0x1,%rax
    183a:	48 39 f8             	cmp    %rdi,%rax
    183d:	75 ee                	jne    182d <phase_5+0x25>
    183f:	83 f9 3b             	cmp    $0x3b,%ecx
    1842:	75 09                	jne    184d <phase_5+0x45>
```
这一部分为循环。有之前的操作，`%rbx`保存了字符串的起始位置，因此181d行在`%rdi`处保存了字符串的结束位置。  
`%ecx`作为了累加器，`%rax`作为了变化下标。`%edx`作为了循环的中间变量。  
注意1826行，此时`%rsi`指向了0x1cd3(%rip)的地址，推测为静态数组的起始位置。  
利用gdb可得到这一地址的内容（<array.0>）为
```
(gdb) x/16a 0x555555557500 
0x555555557500 <array.0>:       0xa00000002   0x100000006
0x555555557510 <array.0+16>:    0x100000000c  0x300000009
0x555555557520 <array.0+32>:    0x700000004   0x50000000e
0x555555557530 <array.0+48>:    0x80000000b   0xd0000000f
0x555555557540: 0x10c3b031b01   0xffffdae000000020
...
```
我们可以得到`array.0`的内容为
```c
array_0[16]={2,0xA,6,1,0xC,0x10,9,3,4,7,0xE,5,0xB,8,0xF,0xD}
```
因此我们可以得到这一部分代码相当于
```c
rbx=rax;
rdi=rbx+6;
ecx=0;
rsi=array_0;
do
{
    edx=*(rax)&0xf;
    ecx+=*(rsi+4*rdx);
    rax++;
}while(rax!=rdi);
if(ecx!=0x3b)
    explode_bomb();
```
也就是取输入字符串每一位对应的ASCII值的低四位，作为数组的下标，将数组这个元素的值累加。
最后判断累加值是否为0x3b，也就是59，否则爆炸。
不妨设计$59=15+14+13+9+5+3$，因此对应的数组下标为`14,10,15,6,11,7`（EAF6B7），因此由ASCII码可得到输入为
```
NJOFKG
```
第五个阶段拆除。

### Phase6

<details>
<summary>
反编译结果
</summary>

```s
0000000000001854 <phase_6>:
    1854:	f3 0f 1e fa          	endbr64 
    1858:	41 57                	push   %r15
    185a:	41 56                	push   %r14
    185c:	41 55                	push   %r13
    185e:	41 54                	push   %r12
    1860:	55                   	push   %rbp
    1861:	53                   	push   %rbx
    1862:	48 83 ec 78          	sub    $0x78,%rsp
    1866:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    186d:	00 00 
    186f:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
    1874:	31 c0                	xor    %eax,%eax
    1876:	4c 8d 7c 24 10       	lea    0x10(%rsp),%r15
    187b:	4c 89 7c 24 08       	mov    %r15,0x8(%rsp)
    1880:	4c 89 fe             	mov    %r15,%rsi
    1883:	e8 f0 03 00 00       	call   1c78 <read_six_numbers>
    1888:	4d 89 fc             	mov    %r15,%r12
    188b:	41 be 01 00 00 00    	mov    $0x1,%r14d
    1891:	4d 89 fd             	mov    %r15,%r13
    1894:	e9 fb 00 00 00       	jmp    1994 <phase_6+0x140>
    1899:	e8 ae 03 00 00       	call   1c4c <explode_bomb>
    189e:	41 83 fe 05          	cmp    $0x5,%r14d
    18a2:	0f 8e 08 01 00 00    	jle    19b0 <phase_6+0x15c>
    18a8:	eb 2c                	jmp    18d6 <phase_6+0x82>
    18aa:	48 83 c3 01          	add    $0x1,%rbx
    18ae:	83 fb 05             	cmp    $0x5,%ebx
    18b1:	0f 8f d5 00 00 00    	jg     198c <phase_6+0x138>
    18b7:	41 8b 44 9d 00       	mov    0x0(%r13,%rbx,4),%eax
    18bc:	39 45 00             	cmp    %eax,0x0(%rbp)
    18bf:	75 e9                	jne    18aa <phase_6+0x56>
    18c1:	e8 86 03 00 00       	call   1c4c <explode_bomb>
    18c6:	eb e2                	jmp    18aa <phase_6+0x56>
    18c8:	49 83 c6 01          	add    $0x1,%r14
    18cc:	49 83 fe 07          	cmp    $0x7,%r14
    18d0:	0f 85 96 00 00 00    	jne    196c <phase_6+0x118>
    18d6:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    18db:	48 83 c2 18          	add    $0x18,%rdx
    18df:	b9 07 00 00 00       	mov    $0x7,%ecx
    18e4:	89 c8                	mov    %ecx,%eax
    18e6:	41 2b 04 24          	sub    (%r12),%eax
    18ea:	41 89 04 24          	mov    %eax,(%r12)
    18ee:	49 83 c4 04          	add    $0x4,%r12
    18f2:	49 39 d4             	cmp    %rdx,%r12
    18f5:	75 ed                	jne    18e4 <phase_6+0x90>
    18f7:	be 00 00 00 00       	mov    $0x0,%esi
    18fc:	8b 4c b4 10          	mov    0x10(%rsp,%rsi,4),%ecx
    1900:	b8 01 00 00 00       	mov    $0x1,%eax
    1905:	48 8d 15 04 39 00 00 	lea    0x3904(%rip),%rdx        # 5210 <node1>
    190c:	83 f9 01             	cmp    $0x1,%ecx
    190f:	7e 0b                	jle    191c <phase_6+0xc8>
    1911:	48 8b 52 08          	mov    0x8(%rdx),%rdx
    1915:	83 c0 01             	add    $0x1,%eax
    1918:	39 c8                	cmp    %ecx,%eax
    191a:	75 f5                	jne    1911 <phase_6+0xbd>
    191c:	48 89 54 f4 30       	mov    %rdx,0x30(%rsp,%rsi,8)
    1921:	48 83 c6 01          	add    $0x1,%rsi
    1925:	48 83 fe 06          	cmp    $0x6,%rsi
    1929:	75 d1                	jne    18fc <phase_6+0xa8>
    192b:	48 8b 5c 24 30       	mov    0x30(%rsp),%rbx
    1930:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    1935:	48 89 43 08          	mov    %rax,0x8(%rbx)
    1939:	48 8b 54 24 40       	mov    0x40(%rsp),%rdx
    193e:	48 89 50 08          	mov    %rdx,0x8(%rax)
    1942:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    1947:	48 89 42 08          	mov    %rax,0x8(%rdx)
    194b:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
    1950:	48 89 50 08          	mov    %rdx,0x8(%rax)
    1954:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    1959:	48 89 42 08          	mov    %rax,0x8(%rdx)
    195d:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
    1964:	00 
    1965:	bd 05 00 00 00       	mov    $0x5,%ebp
    196a:	eb 0f                	jmp    197b <phase_6+0x127>
    196c:	49 83 c7 04          	add    $0x4,%r15
    1970:	eb 22                	jmp    1994 <phase_6+0x140>
    1972:	48 8b 5b 08          	mov    0x8(%rbx),%rbx
    1976:	83 ed 01             	sub    $0x1,%ebp
    1979:	74 3d                	je     19b8 <phase_6+0x164>
    197b:	48 8b 43 08          	mov    0x8(%rbx),%rax
    197f:	8b 00                	mov    (%rax),%eax
    1981:	39 03                	cmp    %eax,(%rbx)
    1983:	7d ed                	jge    1972 <phase_6+0x11e>
    1985:	e8 c2 02 00 00       	call   1c4c <explode_bomb>
    198a:	eb e6                	jmp    1972 <phase_6+0x11e>
    198c:	49 83 c7 04          	add    $0x4,%r15
    1990:	49 83 c6 01          	add    $0x1,%r14
    1994:	4c 89 fd             	mov    %r15,%rbp
    1997:	41 8b 07             	mov    (%r15),%eax
    199a:	83 e8 01             	sub    $0x1,%eax
    199d:	83 f8 05             	cmp    $0x5,%eax
    19a0:	0f 87 f3 fe ff ff    	ja     1899 <phase_6+0x45>
    19a6:	41 83 fe 05          	cmp    $0x5,%r14d
    19aa:	0f 8f 18 ff ff ff    	jg     18c8 <phase_6+0x74>
    19b0:	4c 89 f3             	mov    %r14,%rbx
    19b3:	e9 ff fe ff ff       	jmp    18b7 <phase_6+0x63>
    19b8:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
    19bd:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    19c4:	00 00 
    19c6:	75 0f                	jne    19d7 <phase_6+0x183>
    19c8:	48 83 c4 78          	add    $0x78,%rsp
    19cc:	5b                   	pop    %rbx
    19cd:	5d                   	pop    %rbp
    19ce:	41 5c                	pop    %r12
    19d0:	41 5d                	pop    %r13
    19d2:	41 5e                	pop    %r14
    19d4:	41 5f                	pop    %r15
    19d6:	c3                   	ret    
    19d7:	e8 84 f8 ff ff       	call   1260 <_init+0x260>
```
</details>

分段分析。
```s
    1876:	4c 8d 7c 24 10       	lea    0x10(%rsp),%r15
    187b:	4c 89 7c 24 08       	mov    %r15,0x8(%rsp)
    1880:	4c 89 fe             	mov    %r15,%rsi
    1883:	e8 f0 03 00 00       	call   1c78 <read_six_numbers>
```
由Phase2的`read_six_numbers`，可知，读取的六个整数数值存入`%rsp+0x10`后连续的24字节，并且将开始地址存入`%rsp+0x8`处以便后续访问。
之后
```s
    1888:	4d 89 fc             	mov    %r15,%r12
    188b:	41 be 01 00 00 00    	mov    $0x1,%r14d
    1891:	4d 89 fd             	mov    %r15,%r13
    1894:	e9 fb 00 00 00       	jmp    1994 <phase_6+0x140>
```
将`%r15`存入`%r12`，`%r13`；`%r14`存1，并且跳转到`1994`处。
```s
    198c:	49 83 c7 04          	add    $0x4,%r15
    1990:	49 83 c6 01          	add    $0x1,%r14
    1994:	4c 89 fd             	mov    %r15,%rbp
    1997:	41 8b 07             	mov    (%r15),%eax
    199a:	83 e8 01             	sub    $0x1,%eax
    199d:	83 f8 05             	cmp    $0x5,%eax
    19a0:	0f 87 f3 fe ff ff    	ja     1899 <phase_6+0x45>
    19a6:	41 83 fe 05          	cmp    $0x5,%r14d
    19aa:	0f 8f 18 ff ff ff    	jg     18c8 <phase_6+0x74>
    19b0:	4c 89 f3             	mov    %r14,%rbx
    19b3:	e9 ff fe ff ff       	jmp    18b7 <phase_6+0x63> 
```
此时继续将`%r15`存入`%rbp`，并且取`(%r15)`的值减1，判断是否大于5，如果是则跳转到`1899`处，即`explode_bomb`。
这就要求输入的第一个数要小于等于6。注意到这里使用了无符号数的比较，也就是说，如果`%eax`为0，此时减去1会是一个很大的数，这样就不能满足比较的条件。
之后判断`%r14d`是否大于5，如果是则跳转到`18c8`处，由于最开始`%r14d`为1，并未跳转，此时将`%r14`存入`%rbx`，并且跳转到`18b7`处。
```s
    18aa:	48 83 c3 01          	add    $0x1,%rbx
    18ae:	83 fb 05             	cmp    $0x5,%ebx
    18b1:	0f 8f d5 00 00 00    	jg     198c <phase_6+0x138>
    18b7:	41 8b 44 9d 00       	mov    0x0(%r13,%rbx,4),%eax
    18bc:	39 45 00             	cmp    %eax,0x0(%rbp)
    18bf:	75 e9                	jne    18aa <phase_6+0x56>
    18c1:	e8 86 03 00 00       	call   1c4c <explode_bomb>
    18c6:	eb e2                	jmp    18aa <phase_6+0x56>
```
此时将`0x0(%r13,%rbx,4)`的值存入`%eax`，与`0x0(%rbp)`的值比较，如果不相等则爆炸，否则跳转到`18aa`处。
此时构成一个循环，退出条件为`%rbx`大于5。此时就是要求第一个元素不能和之后的所有元素相等。
退出循环跳转到`198c`处，此时将`%r15`加4，`%r14`加1，并且判断该数组元素是否大于6。随后将`%r14`存入`%rbx`，继续执行18b7处的指令。
此时同样构成一个循环，退出条件为`%r14`大于5。
因此这些可以理解为
```c
r13=r15;
r14=1;
while(1)
{
    rbp=r15;
    if((unsigned)*(r15)-1>5)
        explode_bomb();
    if(r14>5)
        break;
    rbx=r14;
    do
    {
        if(*(r13+rbx*4)!=*(rbp))
            explode_bomb();
        rbx++;
    }while(rbx<=5);
    r15+=4;
    r14++;
}
```
因此我们得知，输入的六个数不能相等，并且都在要求在1-6之间。
这时循环结束，程序跳转到18c8。
```s
    18c8:	49 83 c6 01          	add    $0x1,%r14
    18cc:	49 83 fe 07          	cmp    $0x7,%r14
    18d0:	0f 85 96 00 00 00    	jne    196c <phase_6+0x118>
    18d6:	48 8b 54 24 08       	mov    0x8(%rsp),%rdx
    18db:	48 83 c2 18          	add    $0x18,%rdx
    18df:	b9 07 00 00 00       	mov    $0x7,%ecx
    18e4:	89 c8                	mov    %ecx,%eax
    18e6:	41 2b 04 24          	sub    (%r12),%eax
    18ea:	41 89 04 24          	mov    %eax,(%r12)
    18ee:	49 83 c4 04          	add    $0x4,%r12
    18f2:	49 39 d4             	cmp    %rdx,%r12
    18f5:	75 ed                	jne    18e4 <phase_6+0x90>
```
上一步循环正常结束后，`%r14`的值应当为6。此时将继续执行18d6处的指令。
如果`%r14`不为7，则跳转到196c处，此时执行将`%r15`加4指向下一个元素，重新开始循环，不在赘述。
18d6开始的指令将最开始的数组地址存入`%rdx`，并且将`%rdx`加24，指向数组的最后一个元素，作为循环的结束条件。
由于`%r12`存的是数组的第一个元素的地址，因此这个循环相当于
```c
rdx=rsp+0x8+0x18;
do
{
    *r12=7-*r12;
    r12+=4;
}while(r12!=rdx);
```
也就是说，这一部分将数组的每一个元素变为7减去原来的值。
之后指令为18f7。
```s
    18f7:	be 00 00 00 00       	mov    $0x0,%esi
    18fc:	8b 4c b4 10          	mov    0x10(%rsp,%rsi,4),%ecx
    1900:	b8 01 00 00 00       	mov    $0x1,%eax
    1905:	48 8d 15 04 39 00 00 	lea    0x3904(%rip),%rdx        # 5210 <node1>
    190c:	83 f9 01             	cmp    $0x1,%ecx
    190f:	7e 0b                	jle    191c <phase_6+0xc8>
    1911:	48 8b 52 08          	mov    0x8(%rdx),%rdx
    1915:	83 c0 01             	add    $0x1,%eax
    1918:	39 c8                	cmp    %ecx,%eax
    191a:	75 f5                	jne    1911 <phase_6+0xbd>
    191c:	48 89 54 f4 30       	mov    %rdx,0x30(%rsp,%rsi,8)
    1921:	48 83 c6 01          	add    $0x1,%rsi
    1925:	48 83 fe 06          	cmp    $0x6,%rsi
    1929:	75 d1                	jne    18fc <phase_6+0xa8>
```
先查看0x3904(%rip)处的地址。由gdb知
```
(gdb) x/16a 0x555555559210
0x555555559210 <node1>: 0x10000024f 0x555555559220<node2>
0x555555559220 <node2>: 0x2000003a5 0x555555559230<node3>
0x555555559230 <node3>: 0x3000001fa 0x555555559240<node4>
0x555555559240 <node4>: 0x400000315 0x555555559250<node5>
0x555555559250 <node5>: 0x5000002e8 0x555555559110<node6>
...
```
此时还有node6不知道。
```
(gdb) x/16a 0x555555559110
0x555555559110 <node6>: 0x6000000b2 0x0
```
我们可以得知这是一个类似于链表的结构。并且每个节点的后8个字节存的是下一个节点的地址。而前8个字节存的是包含编号以及数据。
因此node的结构为
```c
struct node
{
    int data;
    int index;
    struct node* next;
};
```
利用gdb，我们得到每个node下的数据为
| node  | data  | index | next  |
| ----- | ----- | ----- | ----- |
| node1 | 0x24f | 1     | node2 |
| node2 | 0x3a5 | 2     | node3 |
| node3 | 0x1fa | 3     | node4 |
| node4 | 0x315 | 4     | node5 |
| node5 | 0x2e8 | 5     | node6 |
| node6 | 0x0b2 | 6     | 0     |

`%rdx`指向了node1，`%ecx`为数组的第一个元素值，`%eax`为1。
下面为判断。
如果`%ecx`小于等于1，则跳转到191c处。
此时将`%rdx`存入`0x30(%rsp,%rsi,8)`，且`%rsi`加1，如果`%rsi`不等于6，则跳转到18fc处。
如果`%ecx`大于1，则`%rdx`指向node1的下一个节点，`%eax`加1，如果`%eax`不等于`%ecx`，则跳转到1911处。此处实现了获得链表的第`%ecx`个节点。
因此这一部分相当于
```c
for(int rsi=0;rsi!=6;rsi++)
{
    ecx=*(rsp+0x10+rsi*4);
    eax=1;
    rdx=&node1;
    if(ecx>1)
    {
        while(eax!=ecx)
        {
            rdx=rdx->next;
            eax++;
        }
    }
    rsp[rsi*8+0x30]=rdx;
}
```
此时相当于将node1到node6的地址按照上面几步处理后的顺序存入了rsp+0x30到rsp+0x60的位置。
下一步为192b。
```s
    192b:	48 8b 5c 24 30       	mov    0x30(%rsp),%rbx
    1930:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    1935:	48 89 43 08          	mov    %rax,0x8(%rbx)
    1939:	48 8b 54 24 40       	mov    0x40(%rsp),%rdx
    193e:	48 89 50 08          	mov    %rdx,0x8(%rax)
    1942:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    1947:	48 89 42 08          	mov    %rax,0x8(%rdx)
    194b:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
    1950:	48 89 50 08          	mov    %rdx,0x8(%rax)
    1954:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    1959:	48 89 42 08          	mov    %rax,0x8(%rdx)
    195d:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
```
可见，重新打乱的链表连接的顺序。
不妨设最开始的数组经过前几部分的处理后为arr。
且`node[7]={0,node1,node2,node3,node4,node5,node6}`。
此时`%rsp+0x30`到`%rsp+0x60`的位置存的是依次是`node[arr[1->6]]`。
因此上述代码相当于
```c
node[arr[0]]->next=node[arr[1]];
node[arr[1]]->next=node[arr[2]];
node[arr[2]]->next=node[arr[3]];
node[arr[3]]->next=node[arr[4]];
node[arr[4]]->next=node[arr[5]];
node[arr[5]]->next=0;
```
也就是按照栈中的顺序将链表重新连接起来。
最后指令为1965。
```s
    1965:	bd 05 00 00 00       	mov    $0x5,%ebp
    196a:	eb 0f                	jmp    197b <phase_6+0x127>
    196c:	49 83 c7 04          	add    $0x4,%r15
    1970:	eb 22                	jmp    1994 <phase_6+0x140>
    1972:	48 8b 5b 08          	mov    0x8(%rbx),%rbx
    1976:	83 ed 01             	sub    $0x1,%ebp
    1979:	74 3d                	je     19b8 <phase_6+0x164>
    197b:	48 8b 43 08          	mov    0x8(%rbx),%rax
    197f:	8b 00                	mov    (%rax),%eax
    1981:	39 03                	cmp    %eax,(%rbx)
    1983:	7d ed                	jge    1972 <phase_6+0x11e>
    1985:	e8 c2 02 00 00       	call   1c4c <explode_bomb>
    198a:	eb e6                	jmp    1972 <phase_6+0x11e>
```
此时将`%ebp`存为5，跳转到197b处。由上部分汇编代码，此时的`%rbx`指向了node[arr[0]]。
`0x8(%rbx)`取出了node存储的next，放入`%rax`。通过`mov`指令取地址指向的值。
因此`%eax`中存的是`node[arr[0]]->next->data`
此时比较`%rbx`对应的data和next->data，如果小于则爆炸。大于等于时跳转到1972处，此时`%rbx`指向了`node[arr[0]]->next`。
`%ebp`减1，如果为0则跳转到19b8处，否则继续循环。
也就是说，最后得到的链表应当是一个递减的链表。
这一部分的指令相当于
```c
rbx=&node[arr[0]];
ebp=5;
do
{
    rax=rbx->next;
    if(rbx->data<rax->data)
        explode_bomb();
    rbx=rbx->next;
    ebp--;
}while(ebp!=0);
```
故我们得到此时输入的数组应当使得链表按照数组的顺序重新连接后，应当是递减的。
根据`node`中存放的数据，得知输入应该为
```
2 4 5 1 3 6
```
由于arr[i]=7-arr[i]，因此输入应该为
```
5 3 2 6 4 1
```
第六个阶段拆除。

### SecretPhase

在`bomb.c`中，我们看到在拆除之后并没有输出字符串，但是结果有输出。我们看到`phase_defused`函数。
我们得到在这个里面，有一个同样`call 1310 <_init+0x310>`的指令。由之前的分析得出其为sscanf。
调用的第一个参数是`0x399e(%rip)`也就是`<input_strings+0xf0>`。
由`read_line`函数，我们得知每次调用时往`input_strings`中写入的字符串长度为80。
因此我们得知这个sscanf的第一个参数对应的时`phase_4`的`input`。
gdb查看`0x12e4(%rip)`处的内容为`"%d %d %s"`。
在1e76处调用了`strings_not_equal`，gdb查看`0x12c2(%rip)`处的内容为`"DrEvil"`。
因此我们得到进入`secret_phase`的条件为在`phase_4`中输入两个整数后继续输入`DrEvil`。

在`secret_phase`中，首先读取了一行字符串，将返回的字符串地址作为第一个参数，0，10分别作为第二、第三个参数传给了12f0处的函数。
由gdb得知函数为`strtol`。此时将读入的字符串转化为十进制下的数字。并且要求其减1后要小于等于0x3e8，也就是1000。
之后，`%esi`为读取的数字，`%rdi`为`0x36e2(%rip)`地址，通过gdb得到其为`0x555555559130`
查看该处内容，得到
```
(gdb) x/128a 0x555555559130
0x555555559130 <n1>:    0x24    0x555555559150 <n21>
0x555555559140 <n1+16>: 0x555555559170 <n22>    0x0
0x555555559150 <n21>:   0x8     0x5555555591d0 <n31>
0x555555559160 <n21+16>:        0x555555559190 <n32>    0x0
0x555555559170 <n22>:   0x32    0x5555555591b0 <n33>
0x555555559180 <n22+16>:        0x5555555591f0 <n34>    0x0
0x555555559190 <n32>:   0x16    0x5555555590b0 <n43>
0x5555555591a0 <n32+16>:        0x555555559070 <n44>    0x0
0x5555555591b0 <n33>:   0x2d    0x555555559010 <n45>
0x5555555591c0 <n33+16>:        0x5555555590d0 <n46>    0x0
0x5555555591d0 <n31>:   0x6     0x555555559030 <n41>
0x5555555591e0 <n31+16>:        0x555555559090 <n42>    0x0
0x5555555591f0 <n34>:   0x6b    0x555555559050 <n47>
0x555555559200 <n34+16>:        0x5555555590f0 <n48>    0x0
...
其余为
0x555555559010 <n45>:   0x28    0x0
0x555555559020 <n45+16>:        0x0     0x0
0x555555559030 <n41>:   0x1     0x0
0x555555559040 <n41+16>:        0x0     0x0
0x555555559050 <n47>:   0x63    0x0
0x555555559060 <n47+16>:        0x0     0x0
0x555555559070 <n44>:   0x23    0x0
0x555555559080 <n44+16>:        0x0     0x0
0x555555559090 <n42>:   0x7     0x0
0x5555555590a0 <n42+16>:        0x0     0x0
0x5555555590b0 <n43>:   0x14    0x0
0x5555555590c0 <n43+16>:        0x0     0x0
0x5555555590d0 <n46>:   0x2f    0x0
0x5555555590e0 <n46+16>:        0x0     0x0
0x5555555590f0 <n48>:   0x3e9   0x0
0x555555559100 <n48+16>:        0x0     0x0
```
猜想结构为`data,lchild,rchild`，因此我们大致可以得到一个树状结构
```
                              n1(36)
             /                                 \
        n21(8)                                n22(50)
       /         \                        /              \
   n31 (6)      n32 (22)               n33 (45)        n34 (107)
   /   \        /      \                /   \           /    \
n41(1) n42(7) n43(20) n44(35)   n45(40) n46(47) n47(99) n48(1001)
```
之后调用了`fun7`函数，将`%rdi`，`%esi`，`%rdx`作为参数传入。

关注`fun7`函数。
```s
00000000000019dc <fun7>:
    19dc:	f3 0f 1e fa          	endbr64 
    19e0:	48 85 ff             	test   %rdi,%rdi
    19e3:	74 32                	je     1a17 <fun7+0x3b>
    19e5:	48 83 ec 08          	sub    $0x8,%rsp
    19e9:	8b 17                	mov    (%rdi),%edx
    19eb:	39 f2                	cmp    %esi,%edx
    19ed:	7f 0c                	jg     19fb <fun7+0x1f>
    19ef:	b8 00 00 00 00       	mov    $0x0,%eax
    19f4:	75 12                	jne    1a08 <fun7+0x2c>
    19f6:	48 83 c4 08          	add    $0x8,%rsp
    19fa:	c3                   	ret    
    19fb:	48 8b 7f 08          	mov    0x8(%rdi),%rdi
    19ff:	e8 d8 ff ff ff       	call   19dc <fun7>
    1a04:	01 c0                	add    %eax,%eax
    1a06:	eb ee                	jmp    19f6 <fun7+0x1a>
    1a08:	48 8b 7f 10          	mov    0x10(%rdi),%rdi
    1a0c:	e8 cb ff ff ff       	call   19dc <fun7>
    1a11:	8d 44 00 01          	lea    0x1(%rax,%rax,1),%eax
    1a15:	eb df                	jmp    19f6 <fun7+0x1a>
    1a17:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1a1c:	c3                   	ret    
```
也是递归。等效的代码为
```c
if ( !rdi )
  return 0xFFFFFFFF;
if ( *(int *)rdi > rsi )
  return 2 * (unsigned int)fun7(rdi->lchild);
eax = 0;
if ( *(int*)rdi != rsi )
  return 2 * (unsigned int)fun7(rdi->rchild) + 1;
return eax;
```
也就是根据二叉树查找访问的时左右子树来判断返回值。

因此，在`secret_phase`中，要求函数返回值为2。
故我们应当查找的数字为22。
因此输入应该为
```
22
```
隐藏阶段拆除。
