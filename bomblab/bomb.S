
bomb:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 3f 00 00 	mov    0x3fd9(%rip),%rax        # 4fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 c2 3e 00 00    	push   0x3ec2(%rip)        # 4ee8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 c4 3e 00 00    	jmp    *0x3ec4(%rip)        # 4ef0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   $0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <_init+0x20>
    103e:	66 90                	xchg   %ax,%ax
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   $0x1
    1049:	e9 d2 ff ff ff       	jmp    1020 <_init+0x20>
    104e:	66 90                	xchg   %ax,%ax
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   $0x2
    1059:	e9 c2 ff ff ff       	jmp    1020 <_init+0x20>
    105e:	66 90                	xchg   %ax,%ax
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	push   $0x3
    1069:	e9 b2 ff ff ff       	jmp    1020 <_init+0x20>
    106e:	66 90                	xchg   %ax,%ax
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	push   $0x4
    1079:	e9 a2 ff ff ff       	jmp    1020 <_init+0x20>
    107e:	66 90                	xchg   %ax,%ax
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	push   $0x5
    1089:	e9 92 ff ff ff       	jmp    1020 <_init+0x20>
    108e:	66 90                	xchg   %ax,%ax
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	push   $0x6
    1099:	e9 82 ff ff ff       	jmp    1020 <_init+0x20>
    109e:	66 90                	xchg   %ax,%ax
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	push   $0x7
    10a9:	e9 72 ff ff ff       	jmp    1020 <_init+0x20>
    10ae:	66 90                	xchg   %ax,%ax
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	push   $0x8
    10b9:	e9 62 ff ff ff       	jmp    1020 <_init+0x20>
    10be:	66 90                	xchg   %ax,%ax
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	push   $0x9
    10c9:	e9 52 ff ff ff       	jmp    1020 <_init+0x20>
    10ce:	66 90                	xchg   %ax,%ax
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	push   $0xa
    10d9:	e9 42 ff ff ff       	jmp    1020 <_init+0x20>
    10de:	66 90                	xchg   %ax,%ax
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	68 0b 00 00 00       	push   $0xb
    10e9:	e9 32 ff ff ff       	jmp    1020 <_init+0x20>
    10ee:	66 90                	xchg   %ax,%ax
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	68 0c 00 00 00       	push   $0xc
    10f9:	e9 22 ff ff ff       	jmp    1020 <_init+0x20>
    10fe:	66 90                	xchg   %ax,%ax
    1100:	f3 0f 1e fa          	endbr64 
    1104:	68 0d 00 00 00       	push   $0xd
    1109:	e9 12 ff ff ff       	jmp    1020 <_init+0x20>
    110e:	66 90                	xchg   %ax,%ax
    1110:	f3 0f 1e fa          	endbr64 
    1114:	68 0e 00 00 00       	push   $0xe
    1119:	e9 02 ff ff ff       	jmp    1020 <_init+0x20>
    111e:	66 90                	xchg   %ax,%ax
    1120:	f3 0f 1e fa          	endbr64 
    1124:	68 0f 00 00 00       	push   $0xf
    1129:	e9 f2 fe ff ff       	jmp    1020 <_init+0x20>
    112e:	66 90                	xchg   %ax,%ax
    1130:	f3 0f 1e fa          	endbr64 
    1134:	68 10 00 00 00       	push   $0x10
    1139:	e9 e2 fe ff ff       	jmp    1020 <_init+0x20>
    113e:	66 90                	xchg   %ax,%ax
    1140:	f3 0f 1e fa          	endbr64 
    1144:	68 11 00 00 00       	push   $0x11
    1149:	e9 d2 fe ff ff       	jmp    1020 <_init+0x20>
    114e:	66 90                	xchg   %ax,%ax
    1150:	f3 0f 1e fa          	endbr64 
    1154:	68 12 00 00 00       	push   $0x12
    1159:	e9 c2 fe ff ff       	jmp    1020 <_init+0x20>
    115e:	66 90                	xchg   %ax,%ax
    1160:	f3 0f 1e fa          	endbr64 
    1164:	68 13 00 00 00       	push   $0x13
    1169:	e9 b2 fe ff ff       	jmp    1020 <_init+0x20>
    116e:	66 90                	xchg   %ax,%ax
    1170:	f3 0f 1e fa          	endbr64 
    1174:	68 14 00 00 00       	push   $0x14
    1179:	e9 a2 fe ff ff       	jmp    1020 <_init+0x20>
    117e:	66 90                	xchg   %ax,%ax
    1180:	f3 0f 1e fa          	endbr64 
    1184:	68 15 00 00 00       	push   $0x15
    1189:	e9 92 fe ff ff       	jmp    1020 <_init+0x20>
    118e:	66 90                	xchg   %ax,%ax
    1190:	f3 0f 1e fa          	endbr64 
    1194:	68 16 00 00 00       	push   $0x16
    1199:	e9 82 fe ff ff       	jmp    1020 <_init+0x20>
    119e:	66 90                	xchg   %ax,%ax
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	68 17 00 00 00       	push   $0x17
    11a9:	e9 72 fe ff ff       	jmp    1020 <_init+0x20>
    11ae:	66 90                	xchg   %ax,%ax
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	68 18 00 00 00       	push   $0x18
    11b9:	e9 62 fe ff ff       	jmp    1020 <_init+0x20>
    11be:	66 90                	xchg   %ax,%ax
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	68 19 00 00 00       	push   $0x19
    11c9:	e9 52 fe ff ff       	jmp    1020 <_init+0x20>
    11ce:	66 90                	xchg   %ax,%ax
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	68 1a 00 00 00       	push   $0x1a
    11d9:	e9 42 fe ff ff       	jmp    1020 <_init+0x20>
    11de:	66 90                	xchg   %ax,%ax
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	68 1b 00 00 00       	push   $0x1b
    11e9:	e9 32 fe ff ff       	jmp    1020 <_init+0x20>
    11ee:	66 90                	xchg   %ax,%ax

Disassembly of section .plt.got:

00000000000011f0 <.plt.got>:
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	ff 25 fe 3d 00 00    	jmp    *0x3dfe(%rip)        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    11fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001200 <.plt.sec>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	ff 25 ee 3c 00 00    	jmp    *0x3cee(%rip)        # 4ef8 <getenv@GLIBC_2.2.5>
    120a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1210:	f3 0f 1e fa          	endbr64 
    1214:	ff 25 e6 3c 00 00    	jmp    *0x3ce6(%rip)        # 4f00 <__errno_location@GLIBC_2.2.5>
    121a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1220:	f3 0f 1e fa          	endbr64 
    1224:	ff 25 de 3c 00 00    	jmp    *0x3cde(%rip)        # 4f08 <strcpy@GLIBC_2.2.5>
    122a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1230:	f3 0f 1e fa          	endbr64 
    1234:	ff 25 d6 3c 00 00    	jmp    *0x3cd6(%rip)        # 4f10 <puts@GLIBC_2.2.5>
    123a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1240:	f3 0f 1e fa          	endbr64 
    1244:	ff 25 ce 3c 00 00    	jmp    *0x3cce(%rip)        # 4f18 <write@GLIBC_2.2.5>
    124a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1250:	f3 0f 1e fa          	endbr64 
    1254:	ff 25 c6 3c 00 00    	jmp    *0x3cc6(%rip)        # 4f20 <strlen@GLIBC_2.2.5>
    125a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1260:	f3 0f 1e fa          	endbr64 
    1264:	ff 25 be 3c 00 00    	jmp    *0x3cbe(%rip)        # 4f28 <__stack_chk_fail@GLIBC_2.4>
    126a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1270:	f3 0f 1e fa          	endbr64 
    1274:	ff 25 b6 3c 00 00    	jmp    *0x3cb6(%rip)        # 4f30 <alarm@GLIBC_2.2.5>
    127a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1280:	f3 0f 1e fa          	endbr64 
    1284:	ff 25 ae 3c 00 00    	jmp    *0x3cae(%rip)        # 4f38 <close@GLIBC_2.2.5>
    128a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1290:	f3 0f 1e fa          	endbr64 
    1294:	ff 25 a6 3c 00 00    	jmp    *0x3ca6(%rip)        # 4f40 <read@GLIBC_2.2.5>
    129a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	ff 25 9e 3c 00 00    	jmp    *0x3c9e(%rip)        # 4f48 <strcmp@GLIBC_2.2.5>
    12aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12b0:	f3 0f 1e fa          	endbr64 
    12b4:	ff 25 96 3c 00 00    	jmp    *0x3c96(%rip)        # 4f50 <signal@GLIBC_2.2.5>
    12ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	ff 25 8e 3c 00 00    	jmp    *0x3c8e(%rip)        # 4f58 <gethostbyname@GLIBC_2.2.5>
    12ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12d0:	f3 0f 1e fa          	endbr64 
    12d4:	ff 25 86 3c 00 00    	jmp    *0x3c86(%rip)        # 4f60 <__memmove_chk@GLIBC_2.3.4>
    12da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12e0:	f3 0f 1e fa          	endbr64 
    12e4:	ff 25 7e 3c 00 00    	jmp    *0x3c7e(%rip)        # 4f68 <__memcpy_chk@GLIBC_2.3.4>
    12ea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    12f0:	f3 0f 1e fa          	endbr64 
    12f4:	ff 25 76 3c 00 00    	jmp    *0x3c76(%rip)        # 4f70 <strtol@GLIBC_2.2.5>
    12fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1300:	f3 0f 1e fa          	endbr64 
    1304:	ff 25 6e 3c 00 00    	jmp    *0x3c6e(%rip)        # 4f78 <fflush@GLIBC_2.2.5>
    130a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1310:	f3 0f 1e fa          	endbr64 
    1314:	ff 25 66 3c 00 00    	jmp    *0x3c66(%rip)        # 4f80 <__isoc99_sscanf@GLIBC_2.7>
    131a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1320:	f3 0f 1e fa          	endbr64 
    1324:	ff 25 5e 3c 00 00    	jmp    *0x3c5e(%rip)        # 4f88 <__fgets_chk@GLIBC_2.4>
    132a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1330:	f3 0f 1e fa          	endbr64 
    1334:	ff 25 56 3c 00 00    	jmp    *0x3c56(%rip)        # 4f90 <__printf_chk@GLIBC_2.3.4>
    133a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1340:	f3 0f 1e fa          	endbr64 
    1344:	ff 25 4e 3c 00 00    	jmp    *0x3c4e(%rip)        # 4f98 <fopen@GLIBC_2.2.5>
    134a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1350:	f3 0f 1e fa          	endbr64 
    1354:	ff 25 46 3c 00 00    	jmp    *0x3c46(%rip)        # 4fa0 <exit@GLIBC_2.2.5>
    135a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1360:	f3 0f 1e fa          	endbr64 
    1364:	ff 25 3e 3c 00 00    	jmp    *0x3c3e(%rip)        # 4fa8 <connect@GLIBC_2.2.5>
    136a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1370:	f3 0f 1e fa          	endbr64 
    1374:	ff 25 36 3c 00 00    	jmp    *0x3c36(%rip)        # 4fb0 <__fprintf_chk@GLIBC_2.3.4>
    137a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1380:	f3 0f 1e fa          	endbr64 
    1384:	ff 25 2e 3c 00 00    	jmp    *0x3c2e(%rip)        # 4fb8 <sleep@GLIBC_2.2.5>
    138a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1390:	f3 0f 1e fa          	endbr64 
    1394:	ff 25 26 3c 00 00    	jmp    *0x3c26(%rip)        # 4fc0 <__ctype_b_loc@GLIBC_2.3>
    139a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    13a0:	f3 0f 1e fa          	endbr64 
    13a4:	ff 25 1e 3c 00 00    	jmp    *0x3c1e(%rip)        # 4fc8 <__sprintf_chk@GLIBC_2.3.4>
    13aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    13b0:	f3 0f 1e fa          	endbr64 
    13b4:	ff 25 16 3c 00 00    	jmp    *0x3c16(%rip)        # 4fd0 <socket@GLIBC_2.2.5>
    13ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000013c0 <_start>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	31 ed                	xor    %ebp,%ebp
    13c6:	49 89 d1             	mov    %rdx,%r9
    13c9:	5e                   	pop    %rsi
    13ca:	48 89 e2             	mov    %rsp,%rdx
    13cd:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    13d1:	50                   	push   %rax
    13d2:	54                   	push   %rsp
    13d3:	45 31 c0             	xor    %r8d,%r8d
    13d6:	31 c9                	xor    %ecx,%ecx
    13d8:	48 8d 3d ca 00 00 00 	lea    0xca(%rip),%rdi        # 14a9 <main>
    13df:	ff 15 f3 3b 00 00    	call   *0x3bf3(%rip)        # 4fd8 <__libc_start_main@GLIBC_2.34>
    13e5:	f4                   	hlt    
    13e6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    13ed:	00 00 00 

00000000000013f0 <deregister_tm_clones>:
    13f0:	48 8d 3d 69 42 00 00 	lea    0x4269(%rip),%rdi        # 5660 <stdout@GLIBC_2.2.5>
    13f7:	48 8d 05 62 42 00 00 	lea    0x4262(%rip),%rax        # 5660 <stdout@GLIBC_2.2.5>
    13fe:	48 39 f8             	cmp    %rdi,%rax
    1401:	74 15                	je     1418 <deregister_tm_clones+0x28>
    1403:	48 8b 05 d6 3b 00 00 	mov    0x3bd6(%rip),%rax        # 4fe0 <_ITM_deregisterTMCloneTable@Base>
    140a:	48 85 c0             	test   %rax,%rax
    140d:	74 09                	je     1418 <deregister_tm_clones+0x28>
    140f:	ff e0                	jmp    *%rax
    1411:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1418:	c3                   	ret    
    1419:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001420 <register_tm_clones>:
    1420:	48 8d 3d 39 42 00 00 	lea    0x4239(%rip),%rdi        # 5660 <stdout@GLIBC_2.2.5>
    1427:	48 8d 35 32 42 00 00 	lea    0x4232(%rip),%rsi        # 5660 <stdout@GLIBC_2.2.5>
    142e:	48 29 fe             	sub    %rdi,%rsi
    1431:	48 89 f0             	mov    %rsi,%rax
    1434:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1438:	48 c1 f8 03          	sar    $0x3,%rax
    143c:	48 01 c6             	add    %rax,%rsi
    143f:	48 d1 fe             	sar    %rsi
    1442:	74 14                	je     1458 <register_tm_clones+0x38>
    1444:	48 8b 05 a5 3b 00 00 	mov    0x3ba5(%rip),%rax        # 4ff0 <_ITM_registerTMCloneTable@Base>
    144b:	48 85 c0             	test   %rax,%rax
    144e:	74 08                	je     1458 <register_tm_clones+0x38>
    1450:	ff e0                	jmp    *%rax
    1452:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1458:	c3                   	ret    
    1459:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001460 <__do_global_dtors_aux>:
    1460:	f3 0f 1e fa          	endbr64 
    1464:	80 3d 1d 42 00 00 00 	cmpb   $0x0,0x421d(%rip)        # 5688 <completed.0>
    146b:	75 2b                	jne    1498 <__do_global_dtors_aux+0x38>
    146d:	55                   	push   %rbp
    146e:	48 83 3d 82 3b 00 00 	cmpq   $0x0,0x3b82(%rip)        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    1475:	00 
    1476:	48 89 e5             	mov    %rsp,%rbp
    1479:	74 0c                	je     1487 <__do_global_dtors_aux+0x27>
    147b:	48 8b 3d 86 3b 00 00 	mov    0x3b86(%rip),%rdi        # 5008 <__dso_handle>
    1482:	e8 69 fd ff ff       	call   11f0 <_init+0x1f0>
    1487:	e8 64 ff ff ff       	call   13f0 <deregister_tm_clones>
    148c:	c6 05 f5 41 00 00 01 	movb   $0x1,0x41f5(%rip)        # 5688 <completed.0>
    1493:	5d                   	pop    %rbp
    1494:	c3                   	ret    
    1495:	0f 1f 00             	nopl   (%rax)
    1498:	c3                   	ret    
    1499:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000014a0 <frame_dummy>:
    14a0:	f3 0f 1e fa          	endbr64 
    14a4:	e9 77 ff ff ff       	jmp    1420 <register_tm_clones>

00000000000014a9 <main>:
    14a9:	f3 0f 1e fa          	endbr64 
    14ad:	53                   	push   %rbx
    14ae:	83 ff 01             	cmp    $0x1,%edi
    14b1:	0f 84 f8 00 00 00    	je     15af <main+0x106>
    14b7:	48 89 f3             	mov    %rsi,%rbx
    14ba:	83 ff 02             	cmp    $0x2,%edi
    14bd:	0f 85 21 01 00 00    	jne    15e4 <main+0x13b>
    14c3:	48 8b 7e 08          	mov    0x8(%rsi),%rdi
    14c7:	48 8d 35 36 1b 00 00 	lea    0x1b36(%rip),%rsi        # 3004 <_IO_stdin_used+0x4>
    14ce:	e8 6d fe ff ff       	call   1340 <_init+0x340>
    14d3:	48 89 05 b6 41 00 00 	mov    %rax,0x41b6(%rip)        # 5690 <infile>
    14da:	48 85 c0             	test   %rax,%rax
    14dd:	0f 84 df 00 00 00    	je     15c2 <main+0x119>
    14e3:	e8 a1 06 00 00       	call   1b89 <initialize_bomb>
__fortify_function int
__NTH (vsnprintf (char *__restrict __s, size_t __n,
		  const char *__restrict __fmt, __gnuc_va_list __ap))
{
  return __builtin___vsnprintf_chk (__s, __n, __USE_FORTIFY_LEVEL - 1,
				    __glibc_objsize (__s), __fmt, __ap);
    14e8:	48 8d 3d 19 1d 00 00 	lea    0x1d19(%rip),%rdi        # 3208 <_IO_stdin_used+0x208>
    14ef:	e8 3c fd ff ff       	call   1230 <_init+0x230>
    14f4:	48 8d 3d 4d 1d 00 00 	lea    0x1d4d(%rip),%rdi        # 3248 <_IO_stdin_used+0x248>
    14fb:	e8 30 fd ff ff       	call   1230 <_init+0x230>
    1500:	e8 b8 07 00 00       	call   1cbd <read_line>
    1505:	48 89 c7             	mov    %rax,%rdi
    1508:	e8 fa 00 00 00       	call   1607 <phase_1>
    150d:	e8 ed 08 00 00       	call   1dff <phase_defused>
    1512:	48 8d 3d 5f 1d 00 00 	lea    0x1d5f(%rip),%rdi        # 3278 <_IO_stdin_used+0x278>
    1519:	e8 12 fd ff ff       	call   1230 <_init+0x230>
    151e:	e8 9a 07 00 00       	call   1cbd <read_line>
    1523:	48 89 c7             	mov    %rax,%rdi
    1526:	e8 00 01 00 00       	call   162b <phase_2>
    152b:	e8 cf 08 00 00       	call   1dff <phase_defused>
    1530:	48 8d 3d 06 1b 00 00 	lea    0x1b06(%rip),%rdi        # 303d <_IO_stdin_used+0x3d>
    1537:	e8 f4 fc ff ff       	call   1230 <_init+0x230>
    153c:	e8 7c 07 00 00       	call   1cbd <read_line>
    1541:	48 89 c7             	mov    %rax,%rdi
    1544:	e8 50 01 00 00       	call   1699 <phase_3>
    1549:	e8 b1 08 00 00       	call   1dff <phase_defused>
    154e:	48 8d 3d 06 1b 00 00 	lea    0x1b06(%rip),%rdi        # 305b <_IO_stdin_used+0x5b>
    1555:	e8 d6 fc ff ff       	call   1230 <_init+0x230>
    155a:	e8 5e 07 00 00       	call   1cbd <read_line>
    155f:	48 89 c7             	mov    %rax,%rdi
    1562:	e8 2e 02 00 00       	call   1795 <phase_4>
    1567:	e8 93 08 00 00       	call   1dff <phase_defused>
    156c:	48 8d 3d 35 1d 00 00 	lea    0x1d35(%rip),%rdi        # 32a8 <_IO_stdin_used+0x2a8>
    1573:	e8 b8 fc ff ff       	call   1230 <_init+0x230>
    1578:	e8 40 07 00 00       	call   1cbd <read_line>
    157d:	48 89 c7             	mov    %rax,%rdi
    1580:	e8 83 02 00 00       	call   1808 <phase_5>
    1585:	e8 75 08 00 00       	call   1dff <phase_defused>
    158a:	48 8d 3d d9 1a 00 00 	lea    0x1ad9(%rip),%rdi        # 306a <_IO_stdin_used+0x6a>
    1591:	e8 9a fc ff ff       	call   1230 <_init+0x230>
    1596:	e8 22 07 00 00       	call   1cbd <read_line>
    159b:	48 89 c7             	mov    %rax,%rdi
    159e:	e8 b1 02 00 00       	call   1854 <phase_6>
    15a3:	e8 57 08 00 00       	call   1dff <phase_defused>
    15a8:	b8 00 00 00 00       	mov    $0x0,%eax
    15ad:	5b                   	pop    %rbx
    15ae:	c3                   	ret    
    15af:	48 8b 05 ba 40 00 00 	mov    0x40ba(%rip),%rax        # 5670 <stdin@GLIBC_2.2.5>
    15b6:	48 89 05 d3 40 00 00 	mov    %rax,0x40d3(%rip)        # 5690 <infile>
    15bd:	e9 21 ff ff ff       	jmp    14e3 <main+0x3a>
    15c2:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
    15c6:	48 8b 13             	mov    (%rbx),%rdx
    15c9:	48 8d 35 36 1a 00 00 	lea    0x1a36(%rip),%rsi        # 3006 <_IO_stdin_used+0x6>
    15d0:	bf 02 00 00 00       	mov    $0x2,%edi
    15d5:	e8 56 fd ff ff       	call   1330 <_init+0x330>
    15da:	bf 08 00 00 00       	mov    $0x8,%edi
    15df:	e8 6c fd ff ff       	call   1350 <_init+0x350>
    15e4:	48 8b 16             	mov    (%rsi),%rdx
    15e7:	48 8d 35 35 1a 00 00 	lea    0x1a35(%rip),%rsi        # 3023 <_IO_stdin_used+0x23>
    15ee:	bf 02 00 00 00       	mov    $0x2,%edi
    15f3:	b8 00 00 00 00       	mov    $0x0,%eax
    15f8:	e8 33 fd ff ff       	call   1330 <_init+0x330>
    15fd:	bf 08 00 00 00       	mov    $0x8,%edi
    1602:	e8 49 fd ff ff       	call   1350 <_init+0x350>

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

0000000000001a1d <secret_phase>:
    1a1d:	f3 0f 1e fa          	endbr64 
    1a21:	53                   	push   %rbx
    1a22:	e8 96 02 00 00       	call   1cbd <read_line>
    1a27:	48 89 c7             	mov    %rax,%rdi
    1a2a:	ba 0a 00 00 00       	mov    $0xa,%edx
    1a2f:	be 00 00 00 00       	mov    $0x0,%esi
    1a34:	e8 b7 f8 ff ff       	call   12f0 <_init+0x2f0>
    1a39:	89 c3                	mov    %eax,%ebx
    1a3b:	83 e8 01             	sub    $0x1,%eax
    1a3e:	3d e8 03 00 00       	cmp    $0x3e8,%eax
    1a43:	77 26                	ja     1a6b <secret_phase+0x4e>
    1a45:	89 de                	mov    %ebx,%esi
    1a47:	48 8d 3d e2 36 00 00 	lea    0x36e2(%rip),%rdi        # 5130 <n1>
    1a4e:	e8 89 ff ff ff       	call   19dc <fun7>
    1a53:	83 f8 02             	cmp    $0x2,%eax
    1a56:	75 1a                	jne    1a72 <secret_phase+0x55>
    1a58:	48 8d 3d a9 18 00 00 	lea    0x18a9(%rip),%rdi        # 3308 <_IO_stdin_used+0x308>
    1a5f:	e8 cc f7 ff ff       	call   1230 <_init+0x230>
    1a64:	e8 96 03 00 00       	call   1dff <phase_defused>
    1a69:	5b                   	pop    %rbx
    1a6a:	c3                   	ret    
    1a6b:	e8 dc 01 00 00       	call   1c4c <explode_bomb>
    1a70:	eb d3                	jmp    1a45 <secret_phase+0x28>
    1a72:	e8 d5 01 00 00       	call   1c4c <explode_bomb>
    1a77:	eb df                	jmp    1a58 <secret_phase+0x3b>

0000000000001a79 <sig_handler>:
    1a79:	f3 0f 1e fa          	endbr64 
    1a7d:	50                   	push   %rax
    1a7e:	58                   	pop    %rax
    1a7f:	48 83 ec 08          	sub    $0x8,%rsp
    1a83:	48 8d 3d a6 18 00 00 	lea    0x18a6(%rip),%rdi        # 3330 <_IO_stdin_used+0x330>
    1a8a:	e8 a1 f7 ff ff       	call   1230 <_init+0x230>
    1a8f:	bf 03 00 00 00       	mov    $0x3,%edi
    1a94:	e8 e7 f8 ff ff       	call   1380 <_init+0x380>
    1a99:	48 8d 35 e8 15 00 00 	lea    0x15e8(%rip),%rsi        # 3088 <_IO_stdin_used+0x88>
    1aa0:	bf 02 00 00 00       	mov    $0x2,%edi
    1aa5:	b8 00 00 00 00       	mov    $0x0,%eax
    1aaa:	e8 81 f8 ff ff       	call   1330 <_init+0x330>
    1aaf:	48 8b 3d aa 3b 00 00 	mov    0x3baa(%rip),%rdi        # 5660 <stdout@GLIBC_2.2.5>
    1ab6:	e8 45 f8 ff ff       	call   1300 <_init+0x300>
    1abb:	bf 01 00 00 00       	mov    $0x1,%edi
    1ac0:	e8 bb f8 ff ff       	call   1380 <_init+0x380>
    1ac5:	48 8d 3d c4 15 00 00 	lea    0x15c4(%rip),%rdi        # 3090 <_IO_stdin_used+0x90>
    1acc:	e8 5f f7 ff ff       	call   1230 <_init+0x230>
    1ad1:	bf 10 00 00 00       	mov    $0x10,%edi
    1ad6:	e8 75 f8 ff ff       	call   1350 <_init+0x350>

0000000000001adb <invalid_phase>:
    1adb:	f3 0f 1e fa          	endbr64 
    1adf:	50                   	push   %rax
    1ae0:	58                   	pop    %rax
    1ae1:	48 83 ec 08          	sub    $0x8,%rsp
    1ae5:	48 89 fa             	mov    %rdi,%rdx
    1ae8:	48 8d 35 a9 15 00 00 	lea    0x15a9(%rip),%rsi        # 3098 <_IO_stdin_used+0x98>
    1aef:	bf 02 00 00 00       	mov    $0x2,%edi
    1af4:	b8 00 00 00 00       	mov    $0x0,%eax
    1af9:	e8 32 f8 ff ff       	call   1330 <_init+0x330>
    1afe:	bf 08 00 00 00       	mov    $0x8,%edi
    1b03:	e8 48 f8 ff ff       	call   1350 <_init+0x350>

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

0000000000001b89 <initialize_bomb>:
    1b89:	f3 0f 1e fa          	endbr64 
    1b8d:	48 83 ec 08          	sub    $0x8,%rsp
    1b91:	48 8d 35 e1 fe ff ff 	lea    -0x11f(%rip),%rsi        # 1a79 <sig_handler>
    1b98:	bf 02 00 00 00       	mov    $0x2,%edi
    1b9d:	e8 0e f7 ff ff       	call   12b0 <_init+0x2b0>
    1ba2:	48 83 c4 08          	add    $0x8,%rsp
    1ba6:	c3                   	ret    

0000000000001ba7 <initialize_bomb_solve>:
    1ba7:	f3 0f 1e fa          	endbr64 
    1bab:	c3                   	ret    

0000000000001bac <blank_line>:
    1bac:	f3 0f 1e fa          	endbr64 
    1bb0:	55                   	push   %rbp
    1bb1:	53                   	push   %rbx
    1bb2:	48 83 ec 08          	sub    $0x8,%rsp
    1bb6:	48 89 fd             	mov    %rdi,%rbp
    1bb9:	0f b6 5d 00          	movzbl 0x0(%rbp),%ebx
    1bbd:	84 db                	test   %bl,%bl
    1bbf:	74 1e                	je     1bdf <blank_line+0x33>
    1bc1:	e8 ca f7 ff ff       	call   1390 <_init+0x390>
    1bc6:	48 83 c5 01          	add    $0x1,%rbp
    1bca:	48 0f be db          	movsbq %bl,%rbx
    1bce:	48 8b 00             	mov    (%rax),%rax
    1bd1:	f6 44 58 01 20       	testb  $0x20,0x1(%rax,%rbx,2)
    1bd6:	75 e1                	jne    1bb9 <blank_line+0xd>
    1bd8:	b8 00 00 00 00       	mov    $0x0,%eax
    1bdd:	eb 05                	jmp    1be4 <blank_line+0x38>
    1bdf:	b8 01 00 00 00       	mov    $0x1,%eax
    1be4:	48 83 c4 08          	add    $0x8,%rsp
    1be8:	5b                   	pop    %rbx
    1be9:	5d                   	pop    %rbp
    1bea:	c3                   	ret    

0000000000001beb <skip>:
    1beb:	f3 0f 1e fa          	endbr64 
    1bef:	55                   	push   %rbp
    1bf0:	53                   	push   %rbx
    1bf1:	48 83 ec 08          	sub    $0x8,%rsp
    1bf5:	48 8d 1d 04 3b 00 00 	lea    0x3b04(%rip),%rbx        # 5700 <input_strings>
    1bfc:	48 63 05 ed 3a 00 00 	movslq 0x3aed(%rip),%rax        # 56f0 <num_input_strings>
    1c03:	48 8d 3c 80          	lea    (%rax,%rax,4),%rdi
    1c07:	48 c1 e7 04          	shl    $0x4,%rdi
    1c0b:	be 40 06 00 00       	mov    $0x640,%esi
    1c10:	48 39 f7             	cmp    %rsi,%rdi
    1c13:	48 0f 43 f7          	cmovae %rdi,%rsi
    1c17:	48 29 fe             	sub    %rdi,%rsi
    1c1a:	48 01 df             	add    %rbx,%rdi
    1c1d:	48 8b 0d 6c 3a 00 00 	mov    0x3a6c(%rip),%rcx        # 5690 <infile>
    1c24:	ba 50 00 00 00       	mov    $0x50,%edx
    1c29:	e8 f2 f6 ff ff       	call   1320 <_init+0x320>
    1c2e:	48 89 c5             	mov    %rax,%rbp
    1c31:	48 85 c0             	test   %rax,%rax
    1c34:	74 0c                	je     1c42 <skip+0x57>
    1c36:	48 89 c7             	mov    %rax,%rdi
    1c39:	e8 6e ff ff ff       	call   1bac <blank_line>
    1c3e:	85 c0                	test   %eax,%eax
    1c40:	75 ba                	jne    1bfc <skip+0x11>
    1c42:	48 89 e8             	mov    %rbp,%rax
    1c45:	48 83 c4 08          	add    $0x8,%rsp
    1c49:	5b                   	pop    %rbx
    1c4a:	5d                   	pop    %rbp
    1c4b:	c3                   	ret    

0000000000001c4c <explode_bomb>:
    1c4c:	f3 0f 1e fa          	endbr64 
    1c50:	50                   	push   %rax
    1c51:	58                   	pop    %rax
    1c52:	48 83 ec 08          	sub    $0x8,%rsp
    1c56:	48 8d 3d 4c 14 00 00 	lea    0x144c(%rip),%rdi        # 30a9 <_IO_stdin_used+0xa9>
    1c5d:	e8 ce f5 ff ff       	call   1230 <_init+0x230>
    1c62:	48 8d 3d 49 14 00 00 	lea    0x1449(%rip),%rdi        # 30b2 <_IO_stdin_used+0xb2>
    1c69:	e8 c2 f5 ff ff       	call   1230 <_init+0x230>
    1c6e:	bf 08 00 00 00       	mov    $0x8,%edi
    1c73:	e8 d8 f6 ff ff       	call   1350 <_init+0x350>

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

0000000000001cbd <read_line>:
    1cbd:	f3 0f 1e fa          	endbr64 
    1cc1:	55                   	push   %rbp
    1cc2:	53                   	push   %rbx
    1cc3:	48 83 ec 08          	sub    $0x8,%rsp
    1cc7:	b8 00 00 00 00       	mov    $0x0,%eax
    1ccc:	e8 1a ff ff ff       	call   1beb <skip>
    1cd1:	48 85 c0             	test   %rax,%rax
    1cd4:	74 5d                	je     1d33 <read_line+0x76>
    1cd6:	8b 2d 14 3a 00 00    	mov    0x3a14(%rip),%ebp        # 56f0 <num_input_strings>
    1cdc:	48 63 c5             	movslq %ebp,%rax
    1cdf:	48 8d 1c 80          	lea    (%rax,%rax,4),%rbx
    1ce3:	48 c1 e3 04          	shl    $0x4,%rbx
    1ce7:	48 8d 05 12 3a 00 00 	lea    0x3a12(%rip),%rax        # 5700 <input_strings>
    1cee:	48 01 c3             	add    %rax,%rbx
    1cf1:	48 89 df             	mov    %rbx,%rdi
    1cf4:	e8 57 f5 ff ff       	call   1250 <_init+0x250>
    1cf9:	83 f8 4e             	cmp    $0x4e,%eax
    1cfc:	0f 8f a9 00 00 00    	jg     1dab <read_line+0xee>
    1d02:	83 e8 01             	sub    $0x1,%eax
    1d05:	48 98                	cltq   
    1d07:	48 63 d5             	movslq %ebp,%rdx
    1d0a:	48 8d 0c 92          	lea    (%rdx,%rdx,4),%rcx
    1d0e:	48 c1 e1 04          	shl    $0x4,%rcx
    1d12:	48 8d 15 e7 39 00 00 	lea    0x39e7(%rip),%rdx        # 5700 <input_strings>
    1d19:	48 01 ca             	add    %rcx,%rdx
    1d1c:	c6 04 02 00          	movb   $0x0,(%rdx,%rax,1)
    1d20:	83 c5 01             	add    $0x1,%ebp
    1d23:	89 2d c7 39 00 00    	mov    %ebp,0x39c7(%rip)        # 56f0 <num_input_strings>
    1d29:	48 89 d8             	mov    %rbx,%rax
    1d2c:	48 83 c4 08          	add    $0x8,%rsp
    1d30:	5b                   	pop    %rbx
    1d31:	5d                   	pop    %rbp
    1d32:	c3                   	ret    
    1d33:	48 8b 05 36 39 00 00 	mov    0x3936(%rip),%rax        # 5670 <stdin@GLIBC_2.2.5>
    1d3a:	48 39 05 4f 39 00 00 	cmp    %rax,0x394f(%rip)        # 5690 <infile>
    1d41:	74 1b                	je     1d5e <read_line+0xa1>
    1d43:	48 8d 3d af 13 00 00 	lea    0x13af(%rip),%rdi        # 30f9 <_IO_stdin_used+0xf9>
    1d4a:	e8 b1 f4 ff ff       	call   1200 <_init+0x200>
    1d4f:	48 85 c0             	test   %rax,%rax
    1d52:	74 20                	je     1d74 <read_line+0xb7>
    1d54:	bf 00 00 00 00       	mov    $0x0,%edi
    1d59:	e8 f2 f5 ff ff       	call   1350 <_init+0x350>
    1d5e:	48 8d 3d 76 13 00 00 	lea    0x1376(%rip),%rdi        # 30db <_IO_stdin_used+0xdb>
    1d65:	e8 c6 f4 ff ff       	call   1230 <_init+0x230>
    1d6a:	bf 08 00 00 00       	mov    $0x8,%edi
    1d6f:	e8 dc f5 ff ff       	call   1350 <_init+0x350>
    1d74:	48 8b 05 f5 38 00 00 	mov    0x38f5(%rip),%rax        # 5670 <stdin@GLIBC_2.2.5>
    1d7b:	48 89 05 0e 39 00 00 	mov    %rax,0x390e(%rip)        # 5690 <infile>
    1d82:	b8 00 00 00 00       	mov    $0x0,%eax
    1d87:	e8 5f fe ff ff       	call   1beb <skip>
    1d8c:	48 85 c0             	test   %rax,%rax
    1d8f:	0f 85 41 ff ff ff    	jne    1cd6 <read_line+0x19>
    1d95:	48 8d 3d 3f 13 00 00 	lea    0x133f(%rip),%rdi        # 30db <_IO_stdin_used+0xdb>
    1d9c:	e8 8f f4 ff ff       	call   1230 <_init+0x230>
    1da1:	bf 00 00 00 00       	mov    $0x0,%edi
    1da6:	e8 a5 f5 ff ff       	call   1350 <_init+0x350>
    1dab:	48 8d 3d 52 13 00 00 	lea    0x1352(%rip),%rdi        # 3104 <_IO_stdin_used+0x104>
    1db2:	e8 79 f4 ff ff       	call   1230 <_init+0x230>
    1db7:	8b 05 33 39 00 00    	mov    0x3933(%rip),%eax        # 56f0 <num_input_strings>
    1dbd:	8d 50 01             	lea    0x1(%rax),%edx
    1dc0:	89 15 2a 39 00 00    	mov    %edx,0x392a(%rip)        # 56f0 <num_input_strings>
    1dc6:	48 98                	cltq   
    1dc8:	48 6b c0 50          	imul   $0x50,%rax,%rax
    1dcc:	ba 40 06 00 00       	mov    $0x640,%edx
    1dd1:	48 39 d0             	cmp    %rdx,%rax
    1dd4:	48 0f 43 d0          	cmovae %rax,%rdx
    1dd8:	48 89 d1             	mov    %rdx,%rcx
    1ddb:	48 29 c1             	sub    %rax,%rcx
    1dde:	48 8d 15 1b 39 00 00 	lea    0x391b(%rip),%rdx        # 5700 <input_strings>
    1de5:	48 8d 3c 10          	lea    (%rax,%rdx,1),%rdi
    1de9:	ba 10 00 00 00       	mov    $0x10,%edx
    1dee:	48 8d 35 2a 13 00 00 	lea    0x132a(%rip),%rsi        # 311f <_IO_stdin_used+0x11f>
    1df5:	e8 e6 f4 ff ff       	call   12e0 <_init+0x2e0>
    1dfa:	e8 4d fe ff ff       	call   1c4c <explode_bomb>

0000000000001dff <phase_defused>:
    1dff:	f3 0f 1e fa          	endbr64 
    1e03:	48 83 ec 78          	sub    $0x78,%rsp
    1e07:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1e0e:	00 00 
    1e10:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
    1e15:	31 c0                	xor    %eax,%eax
    1e17:	83 3d d2 38 00 00 06 	cmpl   $0x6,0x38d2(%rip)        # 56f0 <num_input_strings>
    1e1e:	74 15                	je     1e35 <phase_defused+0x36>
    1e20:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
    1e25:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    1e2c:	00 00 
    1e2e:	75 73                	jne    1ea3 <phase_defused+0xa4>
    1e30:	48 83 c4 78          	add    $0x78,%rsp
    1e34:	c3                   	ret    
    1e35:	48 8d 4c 24 0c       	lea    0xc(%rsp),%rcx
    1e3a:	48 8d 54 24 08       	lea    0x8(%rsp),%rdx
    1e3f:	4c 8d 44 24 10       	lea    0x10(%rsp),%r8
    1e44:	48 8d 35 e4 12 00 00 	lea    0x12e4(%rip),%rsi        # 312f <_IO_stdin_used+0x12f>
    1e4b:	48 8d 3d 9e 39 00 00 	lea    0x399e(%rip),%rdi        # 57f0 <input_strings+0xf0>
    1e52:	e8 b9 f4 ff ff       	call   1310 <_init+0x310>
    1e57:	83 f8 03             	cmp    $0x3,%eax
    1e5a:	74 0e                	je     1e6a <phase_defused+0x6b>
    1e5c:	48 8d 3d 65 15 00 00 	lea    0x1565(%rip),%rdi        # 33c8 <_IO_stdin_used+0x3c8>
    1e63:	e8 c8 f3 ff ff       	call   1230 <_init+0x230>
    1e68:	eb b6                	jmp    1e20 <phase_defused+0x21>
    1e6a:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
    1e6f:	48 8d 35 c2 12 00 00 	lea    0x12c2(%rip),%rsi        # 3138 <_IO_stdin_used+0x138>
    1e76:	e8 ae fc ff ff       	call   1b29 <strings_not_equal>
    1e7b:	85 c0                	test   %eax,%eax
    1e7d:	75 dd                	jne    1e5c <phase_defused+0x5d>
    1e7f:	48 8d 3d e2 14 00 00 	lea    0x14e2(%rip),%rdi        # 3368 <_IO_stdin_used+0x368>
    1e86:	e8 a5 f3 ff ff       	call   1230 <_init+0x230>
    1e8b:	48 8d 3d fe 14 00 00 	lea    0x14fe(%rip),%rdi        # 3390 <_IO_stdin_used+0x390>
    1e92:	e8 99 f3 ff ff       	call   1230 <_init+0x230>
    1e97:	b8 00 00 00 00       	mov    $0x0,%eax
    1e9c:	e8 7c fb ff ff       	call   1a1d <secret_phase>
    1ea1:	eb b9                	jmp    1e5c <phase_defused+0x5d>
    1ea3:	e8 b8 f3 ff ff       	call   1260 <_init+0x260>

0000000000001ea8 <sigalrm_handler>:
    1ea8:	f3 0f 1e fa          	endbr64 
    1eac:	50                   	push   %rax
    1ead:	58                   	pop    %rax
    1eae:	48 83 ec 08          	sub    $0x8,%rsp
    1eb2:	b9 00 00 00 00       	mov    $0x0,%ecx
    1eb7:	48 8d 15 3a 15 00 00 	lea    0x153a(%rip),%rdx        # 33f8 <_IO_stdin_used+0x3f8>
    1ebe:	be 02 00 00 00       	mov    $0x2,%esi
    1ec3:	48 8b 3d b6 37 00 00 	mov    0x37b6(%rip),%rdi        # 5680 <stderr@GLIBC_2.2.5>
    1eca:	b8 00 00 00 00       	mov    $0x0,%eax
    1ecf:	e8 9c f4 ff ff       	call   1370 <_init+0x370>
    1ed4:	bf 01 00 00 00       	mov    $0x1,%edi
    1ed9:	e8 72 f4 ff ff       	call   1350 <_init+0x350>

0000000000001ede <rio_readlineb>:
    1ede:	41 56                	push   %r14
    1ee0:	41 55                	push   %r13
    1ee2:	41 54                	push   %r12
    1ee4:	55                   	push   %rbp
    1ee5:	53                   	push   %rbx
    1ee6:	49 89 f4             	mov    %rsi,%r12
    1ee9:	48 83 fa 01          	cmp    $0x1,%rdx
    1eed:	0f 86 90 00 00 00    	jbe    1f83 <rio_readlineb+0xa5>
    1ef3:	48 89 fb             	mov    %rdi,%rbx
    1ef6:	4c 8d 74 16 ff       	lea    -0x1(%rsi,%rdx,1),%r14
    1efb:	41 bd 01 00 00 00    	mov    $0x1,%r13d
    1f01:	48 8d 6f 10          	lea    0x10(%rdi),%rbp
    1f05:	eb 54                	jmp    1f5b <rio_readlineb+0x7d>
    1f07:	e8 04 f3 ff ff       	call   1210 <_init+0x210>
    1f0c:	83 38 04             	cmpl   $0x4,(%rax)
    1f0f:	75 53                	jne    1f64 <rio_readlineb+0x86>
    1f11:	8b 3b                	mov    (%rbx),%edi
    1f13:	ba 00 20 00 00       	mov    $0x2000,%edx
    1f18:	48 89 ee             	mov    %rbp,%rsi
    1f1b:	e8 70 f3 ff ff       	call   1290 <_init+0x290>
    1f20:	89 c2                	mov    %eax,%edx
    1f22:	89 43 04             	mov    %eax,0x4(%rbx)
    1f25:	85 c0                	test   %eax,%eax
    1f27:	78 de                	js     1f07 <rio_readlineb+0x29>
    1f29:	74 42                	je     1f6d <rio_readlineb+0x8f>
    1f2b:	48 89 6b 08          	mov    %rbp,0x8(%rbx)
    1f2f:	48 8b 43 08          	mov    0x8(%rbx),%rax
    1f33:	0f b6 08             	movzbl (%rax),%ecx
    1f36:	48 83 c0 01          	add    $0x1,%rax
    1f3a:	48 89 43 08          	mov    %rax,0x8(%rbx)
    1f3e:	83 ea 01             	sub    $0x1,%edx
    1f41:	89 53 04             	mov    %edx,0x4(%rbx)
    1f44:	49 83 c4 01          	add    $0x1,%r12
    1f48:	41 88 4c 24 ff       	mov    %cl,-0x1(%r12)
    1f4d:	80 f9 0a             	cmp    $0xa,%cl
    1f50:	74 3c                	je     1f8e <rio_readlineb+0xb0>
    1f52:	41 83 c5 01          	add    $0x1,%r13d
    1f56:	4d 39 f4             	cmp    %r14,%r12
    1f59:	74 30                	je     1f8b <rio_readlineb+0xad>
    1f5b:	8b 53 04             	mov    0x4(%rbx),%edx
    1f5e:	85 d2                	test   %edx,%edx
    1f60:	7e af                	jle    1f11 <rio_readlineb+0x33>
    1f62:	eb cb                	jmp    1f2f <rio_readlineb+0x51>
    1f64:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    1f6b:	eb 05                	jmp    1f72 <rio_readlineb+0x94>
    1f6d:	b8 00 00 00 00       	mov    $0x0,%eax
    1f72:	85 c0                	test   %eax,%eax
    1f74:	75 29                	jne    1f9f <rio_readlineb+0xc1>
    1f76:	b8 00 00 00 00       	mov    $0x0,%eax
    1f7b:	41 83 fd 01          	cmp    $0x1,%r13d
    1f7f:	75 0d                	jne    1f8e <rio_readlineb+0xb0>
    1f81:	eb 13                	jmp    1f96 <rio_readlineb+0xb8>
    1f83:	41 bd 01 00 00 00    	mov    $0x1,%r13d
    1f89:	eb 03                	jmp    1f8e <rio_readlineb+0xb0>
    1f8b:	4d 89 f4             	mov    %r14,%r12
    1f8e:	41 c6 04 24 00       	movb   $0x0,(%r12)
    1f93:	49 63 c5             	movslq %r13d,%rax
    1f96:	5b                   	pop    %rbx
    1f97:	5d                   	pop    %rbp
    1f98:	41 5c                	pop    %r12
    1f9a:	41 5d                	pop    %r13
    1f9c:	41 5e                	pop    %r14
    1f9e:	c3                   	ret    
    1f9f:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    1fa6:	eb ee                	jmp    1f96 <rio_readlineb+0xb8>

0000000000001fa8 <submitr>:
    1fa8:	f3 0f 1e fa          	endbr64 
    1fac:	41 57                	push   %r15
    1fae:	41 56                	push   %r14
    1fb0:	41 55                	push   %r13
    1fb2:	41 54                	push   %r12
    1fb4:	55                   	push   %rbp
    1fb5:	53                   	push   %rbx
    1fb6:	4c 8d 9c 24 00 60 ff 	lea    -0xa000(%rsp),%r11
    1fbd:	ff 
    1fbe:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    1fc5:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    1fca:	4c 39 dc             	cmp    %r11,%rsp
    1fcd:	75 ef                	jne    1fbe <submitr+0x16>
    1fcf:	48 83 ec 68          	sub    $0x68,%rsp
    1fd3:	49 89 fd             	mov    %rdi,%r13
    1fd6:	89 f5                	mov    %esi,%ebp
    1fd8:	48 89 14 24          	mov    %rdx,(%rsp)
    1fdc:	48 89 4c 24 08       	mov    %rcx,0x8(%rsp)
    1fe1:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
    1fe6:	4c 89 4c 24 10       	mov    %r9,0x10(%rsp)
    1feb:	48 8b 9c 24 a0 a0 00 	mov    0xa0a0(%rsp),%rbx
    1ff2:	00 
    1ff3:	4c 8b bc 24 a8 a0 00 	mov    0xa0a8(%rsp),%r15
    1ffa:	00 
    1ffb:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2002:	00 00 
    2004:	48 89 84 24 58 a0 00 	mov    %rax,0xa058(%rsp)
    200b:	00 
    200c:	31 c0                	xor    %eax,%eax
    200e:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%rsp)
    2015:	00 
    2016:	ba 00 00 00 00       	mov    $0x0,%edx
    201b:	be 01 00 00 00       	mov    $0x1,%esi
    2020:	bf 02 00 00 00       	mov    $0x2,%edi
    2025:	e8 86 f3 ff ff       	call   13b0 <_init+0x3b0>
    202a:	85 c0                	test   %eax,%eax
    202c:	0f 88 04 01 00 00    	js     2136 <submitr+0x18e>
    2032:	41 89 c4             	mov    %eax,%r12d
    2035:	4c 89 ef             	mov    %r13,%rdi
    2038:	e8 83 f2 ff ff       	call   12c0 <_init+0x2c0>
    203d:	48 85 c0             	test   %rax,%rax
    2040:	0f 84 3f 01 00 00    	je     2185 <submitr+0x1dd>
    2046:	4c 8d 6c 24 30       	lea    0x30(%rsp),%r13
    204b:	48 c7 44 24 32 00 00 	movq   $0x0,0x32(%rsp)
    2052:	00 00 
    2054:	48 c7 44 24 38 00 00 	movq   $0x0,0x38(%rsp)
    205b:	00 00 
    205d:	66 c7 44 24 30 02 00 	movw   $0x2,0x30(%rsp)
    2064:	48 63 50 14          	movslq 0x14(%rax),%rdx
    2068:	48 8b 40 18          	mov    0x18(%rax),%rax
    206c:	48 8b 30             	mov    (%rax),%rsi
    206f:	48 8d 7c 24 34       	lea    0x34(%rsp),%rdi
    2074:	b9 0c 00 00 00       	mov    $0xc,%ecx
    2079:	e8 52 f2 ff ff       	call   12d0 <_init+0x2d0>
    207e:	66 c1 c5 08          	rol    $0x8,%bp
    2082:	66 89 6c 24 32       	mov    %bp,0x32(%rsp)
    2087:	ba 10 00 00 00       	mov    $0x10,%edx
    208c:	4c 89 ee             	mov    %r13,%rsi
    208f:	44 89 e7             	mov    %r12d,%edi
    2092:	e8 c9 f2 ff ff       	call   1360 <_init+0x360>
    2097:	85 c0                	test   %eax,%eax
    2099:	0f 88 4b 01 00 00    	js     21ea <submitr+0x242>
    209f:	48 89 df             	mov    %rbx,%rdi
    20a2:	e8 a9 f1 ff ff       	call   1250 <_init+0x250>
    20a7:	48 89 c5             	mov    %rax,%rbp
    20aa:	48 8b 3c 24          	mov    (%rsp),%rdi
    20ae:	e8 9d f1 ff ff       	call   1250 <_init+0x250>
    20b3:	49 89 c6             	mov    %rax,%r14
    20b6:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
    20bb:	e8 90 f1 ff ff       	call   1250 <_init+0x250>
    20c0:	49 89 c5             	mov    %rax,%r13
    20c3:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
    20c8:	e8 83 f1 ff ff       	call   1250 <_init+0x250>
    20cd:	48 89 c2             	mov    %rax,%rdx
    20d0:	4b 8d 84 2e 80 00 00 	lea    0x80(%r14,%r13,1),%rax
    20d7:	00 
    20d8:	48 01 d0             	add    %rdx,%rax
    20db:	48 8d 54 6d 00       	lea    0x0(%rbp,%rbp,2),%rdx
    20e0:	48 01 d0             	add    %rdx,%rax
    20e3:	48 3d 00 20 00 00    	cmp    $0x2000,%rax
    20e9:	0f 87 52 01 00 00    	ja     2241 <submitr+0x299>
    20ef:	48 8d 94 24 50 40 00 	lea    0x4050(%rsp),%rdx
    20f6:	00 
    20f7:	b9 00 04 00 00       	mov    $0x400,%ecx
    20fc:	b8 00 00 00 00       	mov    $0x0,%eax
    2101:	48 89 d7             	mov    %rdx,%rdi
    2104:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    2107:	48 89 df             	mov    %rbx,%rdi
    210a:	e8 41 f1 ff ff       	call   1250 <_init+0x250>
    210f:	85 c0                	test   %eax,%eax
    2111:	0f 84 47 02 00 00    	je     235e <submitr+0x3b6>
    2117:	8d 40 ff             	lea    -0x1(%rax),%eax
    211a:	4c 8d 6c 03 01       	lea    0x1(%rbx,%rax,1),%r13
    211f:	48 8d ac 24 50 40 00 	lea    0x4050(%rsp),%rbp
    2126:	00 
    2127:	49 be d9 ff 00 00 00 	movabs $0x2000000000ffd9,%r14
    212e:	00 20 00 
    2131:	e9 99 01 00 00       	jmp    22cf <submitr+0x327>
    2136:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    213d:	3a 20 43 
    2140:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    2147:	20 75 6e 
    214a:	49 89 07             	mov    %rax,(%r15)
    214d:	49 89 57 08          	mov    %rdx,0x8(%r15)
    2151:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    2158:	74 6f 20 
    215b:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
    2162:	65 20 73 
    2165:	49 89 47 10          	mov    %rax,0x10(%r15)
    2169:	49 89 57 18          	mov    %rdx,0x18(%r15)
    216d:	48 b8 20 73 6f 63 6b 	movabs $0x74656b636f7320,%rax
    2174:	65 74 00 
    2177:	49 89 47 1e          	mov    %rax,0x1e(%r15)
    217b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2180:	e9 d4 04 00 00       	jmp    2659 <submitr+0x6b1>
    2185:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
    218c:	3a 20 44 
    218f:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
    2196:	20 75 6e 
    2199:	49 89 07             	mov    %rax,(%r15)
    219c:	49 89 57 08          	mov    %rdx,0x8(%r15)
    21a0:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    21a7:	74 6f 20 
    21aa:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
    21b1:	76 65 20 
    21b4:	49 89 47 10          	mov    %rax,0x10(%r15)
    21b8:	49 89 57 18          	mov    %rdx,0x18(%r15)
    21bc:	48 b8 20 73 65 72 76 	movabs $0x2072657672657320,%rax
    21c3:	65 72 20 
    21c6:	48 ba 61 64 64 72 65 	movabs $0x73736572646461,%rdx
    21cd:	73 73 00 
    21d0:	49 89 47 1f          	mov    %rax,0x1f(%r15)
    21d4:	49 89 57 27          	mov    %rdx,0x27(%r15)
    21d8:	44 89 e7             	mov    %r12d,%edi
    21db:	e8 a0 f0 ff ff       	call   1280 <_init+0x280>
    21e0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    21e5:	e9 6f 04 00 00       	jmp    2659 <submitr+0x6b1>
    21ea:	48 b8 45 72 72 6f 72 	movabs $0x55203a726f727245,%rax
    21f1:	3a 20 55 
    21f4:	48 ba 6e 61 62 6c 65 	movabs $0x6f7420656c62616e,%rdx
    21fb:	20 74 6f 
    21fe:	49 89 07             	mov    %rax,(%r15)
    2201:	49 89 57 08          	mov    %rdx,0x8(%r15)
    2205:	48 b8 20 63 6f 6e 6e 	movabs $0x7463656e6e6f6320,%rax
    220c:	65 63 74 
    220f:	48 ba 20 74 6f 20 74 	movabs $0x20656874206f7420,%rdx
    2216:	68 65 20 
    2219:	49 89 47 10          	mov    %rax,0x10(%r15)
    221d:	49 89 57 18          	mov    %rdx,0x18(%r15)
    2221:	48 b8 20 73 65 72 76 	movabs $0x72657672657320,%rax
    2228:	65 72 00 
    222b:	49 89 47 1f          	mov    %rax,0x1f(%r15)
    222f:	44 89 e7             	mov    %r12d,%edi
    2232:	e8 49 f0 ff ff       	call   1280 <_init+0x280>
    2237:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    223c:	e9 18 04 00 00       	jmp    2659 <submitr+0x6b1>
    2241:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
    2248:	3a 20 52 
    224b:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
    2252:	20 73 74 
    2255:	49 89 07             	mov    %rax,(%r15)
    2258:	49 89 57 08          	mov    %rdx,0x8(%r15)
    225c:	48 b8 72 69 6e 67 20 	movabs $0x6f6f7420676e6972,%rax
    2263:	74 6f 6f 
    2266:	48 ba 20 6c 61 72 67 	movabs $0x202e656772616c20,%rdx
    226d:	65 2e 20 
    2270:	49 89 47 10          	mov    %rax,0x10(%r15)
    2274:	49 89 57 18          	mov    %rdx,0x18(%r15)
    2278:	48 b8 49 6e 63 72 65 	movabs $0x6573616572636e49,%rax
    227f:	61 73 65 
    2282:	48 ba 20 53 55 42 4d 	movabs $0x5254494d42555320,%rdx
    2289:	49 54 52 
    228c:	49 89 47 20          	mov    %rax,0x20(%r15)
    2290:	49 89 57 28          	mov    %rdx,0x28(%r15)
    2294:	48 b8 5f 4d 41 58 42 	movabs $0x46554258414d5f,%rax
    229b:	55 46 00 
    229e:	49 89 47 30          	mov    %rax,0x30(%r15)
    22a2:	44 89 e7             	mov    %r12d,%edi
    22a5:	e8 d6 ef ff ff       	call   1280 <_init+0x280>
    22aa:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    22af:	e9 a5 03 00 00       	jmp    2659 <submitr+0x6b1>
    22b4:	49 0f a3 c6          	bt     %rax,%r14
    22b8:	73 21                	jae    22db <submitr+0x333>
    22ba:	44 88 45 00          	mov    %r8b,0x0(%rbp)
    22be:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
    22c2:	48 83 c3 01          	add    $0x1,%rbx
    22c6:	49 39 dd             	cmp    %rbx,%r13
    22c9:	0f 84 8f 00 00 00    	je     235e <submitr+0x3b6>
    22cf:	44 0f b6 03          	movzbl (%rbx),%r8d
    22d3:	41 8d 40 d6          	lea    -0x2a(%r8),%eax
    22d7:	3c 35                	cmp    $0x35,%al
    22d9:	76 d9                	jbe    22b4 <submitr+0x30c>
    22db:	44 89 c0             	mov    %r8d,%eax
    22de:	83 e0 df             	and    $0xffffffdf,%eax
    22e1:	83 e8 41             	sub    $0x41,%eax
    22e4:	3c 19                	cmp    $0x19,%al
    22e6:	76 d2                	jbe    22ba <submitr+0x312>
    22e8:	41 80 f8 20          	cmp    $0x20,%r8b
    22ec:	74 63                	je     2351 <submitr+0x3a9>
    22ee:	41 8d 40 e0          	lea    -0x20(%r8),%eax
    22f2:	3c 5f                	cmp    $0x5f,%al
    22f4:	76 0a                	jbe    2300 <submitr+0x358>
    22f6:	41 80 f8 09          	cmp    $0x9,%r8b
    22fa:	0f 85 f5 03 00 00    	jne    26f5 <submitr+0x74d>
    2300:	48 8d bc 24 50 80 00 	lea    0x8050(%rsp),%rdi
    2307:	00 
    2308:	45 0f b6 c0          	movzbl %r8b,%r8d
    230c:	48 8d 0d 93 0e 00 00 	lea    0xe93(%rip),%rcx        # 31a6 <_IO_stdin_used+0x1a6>
    2313:	ba 08 00 00 00       	mov    $0x8,%edx
    2318:	be 02 00 00 00       	mov    $0x2,%esi
    231d:	b8 00 00 00 00       	mov    $0x0,%eax
    2322:	e8 79 f0 ff ff       	call   13a0 <_init+0x3a0>
    2327:	0f b6 84 24 50 80 00 	movzbl 0x8050(%rsp),%eax
    232e:	00 
    232f:	88 45 00             	mov    %al,0x0(%rbp)
    2332:	0f b6 84 24 51 80 00 	movzbl 0x8051(%rsp),%eax
    2339:	00 
    233a:	88 45 01             	mov    %al,0x1(%rbp)
    233d:	0f b6 84 24 52 80 00 	movzbl 0x8052(%rsp),%eax
    2344:	00 
    2345:	88 45 02             	mov    %al,0x2(%rbp)
    2348:	48 8d 6d 03          	lea    0x3(%rbp),%rbp
    234c:	e9 71 ff ff ff       	jmp    22c2 <submitr+0x31a>
    2351:	c6 45 00 2b          	movb   $0x2b,0x0(%rbp)
    2355:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
    2359:	e9 64 ff ff ff       	jmp    22c2 <submitr+0x31a>
    235e:	48 8d 9c 24 50 20 00 	lea    0x2050(%rsp),%rbx
    2365:	00 
    2366:	48 83 ec 08          	sub    $0x8,%rsp
    236a:	48 8d 84 24 58 40 00 	lea    0x4058(%rsp),%rax
    2371:	00 
    2372:	50                   	push   %rax
    2373:	ff 74 24 20          	push   0x20(%rsp)
    2377:	ff 74 24 30          	push   0x30(%rsp)
    237b:	4c 8b 4c 24 28       	mov    0x28(%rsp),%r9
    2380:	4c 8b 44 24 20       	mov    0x20(%rsp),%r8
    2385:	48 8d 0d 94 10 00 00 	lea    0x1094(%rip),%rcx        # 3420 <_IO_stdin_used+0x420>
    238c:	ba 00 20 00 00       	mov    $0x2000,%edx
    2391:	be 02 00 00 00       	mov    $0x2,%esi
    2396:	48 89 df             	mov    %rbx,%rdi
    2399:	b8 00 00 00 00       	mov    $0x0,%eax
    239e:	e8 fd ef ff ff       	call   13a0 <_init+0x3a0>
    23a3:	48 83 c4 20          	add    $0x20,%rsp
    23a7:	48 89 df             	mov    %rbx,%rdi
    23aa:	e8 a1 ee ff ff       	call   1250 <_init+0x250>
    23af:	48 89 c3             	mov    %rax,%rbx
    23b2:	48 85 c0             	test   %rax,%rax
    23b5:	74 33                	je     23ea <submitr+0x442>
    23b7:	48 8d ac 24 50 20 00 	lea    0x2050(%rsp),%rbp
    23be:	00 
    23bf:	eb 0e                	jmp    23cf <submitr+0x427>
    23c1:	e8 4a ee ff ff       	call   1210 <_init+0x210>
    23c6:	83 38 04             	cmpl   $0x4,(%rax)
    23c9:	0f 85 37 01 00 00    	jne    2506 <submitr+0x55e>
    23cf:	48 89 da             	mov    %rbx,%rdx
    23d2:	48 89 ee             	mov    %rbp,%rsi
    23d5:	44 89 e7             	mov    %r12d,%edi
    23d8:	e8 63 ee ff ff       	call   1240 <_init+0x240>
    23dd:	48 85 c0             	test   %rax,%rax
    23e0:	7e df                	jle    23c1 <submitr+0x419>
    23e2:	48 01 c5             	add    %rax,%rbp
    23e5:	48 29 c3             	sub    %rax,%rbx
    23e8:	75 e5                	jne    23cf <submitr+0x427>
    23ea:	44 89 64 24 40       	mov    %r12d,0x40(%rsp)
    23ef:	c7 44 24 44 00 00 00 	movl   $0x0,0x44(%rsp)
    23f6:	00 
    23f7:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
    23fc:	48 8d 44 24 50       	lea    0x50(%rsp),%rax
    2401:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
    2406:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
    240d:	00 
    240e:	ba 00 20 00 00       	mov    $0x2000,%edx
    2413:	e8 c6 fa ff ff       	call   1ede <rio_readlineb>
    2418:	48 85 c0             	test   %rax,%rax
    241b:	0f 8e 4a 01 00 00    	jle    256b <submitr+0x5c3>
    2421:	48 8d 4c 24 2c       	lea    0x2c(%rsp),%rcx
    2426:	48 8d 94 24 50 60 00 	lea    0x6050(%rsp),%rdx
    242d:	00 
    242e:	48 8d bc 24 50 20 00 	lea    0x2050(%rsp),%rdi
    2435:	00 
    2436:	4c 8d 84 24 50 80 00 	lea    0x8050(%rsp),%r8
    243d:	00 
    243e:	48 8d 35 68 0d 00 00 	lea    0xd68(%rip),%rsi        # 31ad <_IO_stdin_used+0x1ad>
    2445:	b8 00 00 00 00       	mov    $0x0,%eax
    244a:	e8 c1 ee ff ff       	call   1310 <_init+0x310>
    244f:	44 8b 44 24 2c       	mov    0x2c(%rsp),%r8d
    2454:	41 81 f8 c8 00 00 00 	cmp    $0xc8,%r8d
    245b:	0f 85 7a 01 00 00    	jne    25db <submitr+0x633>
    2461:	48 8d 1d 56 0d 00 00 	lea    0xd56(%rip),%rbx        # 31be <_IO_stdin_used+0x1be>
    2468:	48 8d bc 24 50 20 00 	lea    0x2050(%rsp),%rdi
    246f:	00 
    2470:	48 89 de             	mov    %rbx,%rsi
    2473:	e8 28 ee ff ff       	call   12a0 <_init+0x2a0>
    2478:	85 c0                	test   %eax,%eax
    247a:	0f 84 92 01 00 00    	je     2612 <submitr+0x66a>
    2480:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
    2487:	00 
    2488:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
    248d:	ba 00 20 00 00       	mov    $0x2000,%edx
    2492:	e8 47 fa ff ff       	call   1ede <rio_readlineb>
    2497:	48 85 c0             	test   %rax,%rax
    249a:	7f cc                	jg     2468 <submitr+0x4c0>
    249c:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    24a3:	3a 20 43 
    24a6:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    24ad:	20 75 6e 
    24b0:	49 89 07             	mov    %rax,(%r15)
    24b3:	49 89 57 08          	mov    %rdx,0x8(%r15)
    24b7:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    24be:	74 6f 20 
    24c1:	48 ba 72 65 61 64 20 	movabs $0x6165682064616572,%rdx
    24c8:	68 65 61 
    24cb:	49 89 47 10          	mov    %rax,0x10(%r15)
    24cf:	49 89 57 18          	mov    %rdx,0x18(%r15)
    24d3:	48 b8 64 65 72 73 20 	movabs $0x6f72662073726564,%rax
    24da:	66 72 6f 
    24dd:	48 ba 6d 20 73 65 72 	movabs $0x726576726573206d,%rdx
    24e4:	76 65 72 
    24e7:	49 89 47 20          	mov    %rax,0x20(%r15)
    24eb:	49 89 57 28          	mov    %rdx,0x28(%r15)
    24ef:	41 c6 47 30 00       	movb   $0x0,0x30(%r15)
    24f4:	44 89 e7             	mov    %r12d,%edi
    24f7:	e8 84 ed ff ff       	call   1280 <_init+0x280>
    24fc:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2501:	e9 53 01 00 00       	jmp    2659 <submitr+0x6b1>
    2506:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    250d:	3a 20 43 
    2510:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    2517:	20 75 6e 
    251a:	49 89 07             	mov    %rax,(%r15)
    251d:	49 89 57 08          	mov    %rdx,0x8(%r15)
    2521:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    2528:	74 6f 20 
    252b:	48 ba 77 72 69 74 65 	movabs $0x6f74206574697277,%rdx
    2532:	20 74 6f 
    2535:	49 89 47 10          	mov    %rax,0x10(%r15)
    2539:	49 89 57 18          	mov    %rdx,0x18(%r15)
    253d:	48 b8 65 20 74 6f 20 	movabs $0x656874206f742065,%rax
    2544:	74 68 65 
    2547:	48 ba 20 73 65 72 76 	movabs $0x72657672657320,%rdx
    254e:	65 72 00 
    2551:	49 89 47 1c          	mov    %rax,0x1c(%r15)
    2555:	49 89 57 24          	mov    %rdx,0x24(%r15)
    2559:	44 89 e7             	mov    %r12d,%edi
    255c:	e8 1f ed ff ff       	call   1280 <_init+0x280>
    2561:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2566:	e9 ee 00 00 00       	jmp    2659 <submitr+0x6b1>
    256b:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    2572:	3a 20 43 
    2575:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    257c:	20 75 6e 
    257f:	49 89 07             	mov    %rax,(%r15)
    2582:	49 89 57 08          	mov    %rdx,0x8(%r15)
    2586:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    258d:	74 6f 20 
    2590:	48 ba 72 65 61 64 20 	movabs $0x7269662064616572,%rdx
    2597:	66 69 72 
    259a:	49 89 47 10          	mov    %rax,0x10(%r15)
    259e:	49 89 57 18          	mov    %rdx,0x18(%r15)
    25a2:	48 b8 73 74 20 68 65 	movabs $0x6564616568207473,%rax
    25a9:	61 64 65 
    25ac:	48 ba 72 20 66 72 6f 	movabs $0x73206d6f72662072,%rdx
    25b3:	6d 20 73 
    25b6:	49 89 47 20          	mov    %rax,0x20(%r15)
    25ba:	49 89 57 28          	mov    %rdx,0x28(%r15)
    25be:	48 b8 20 73 65 72 76 	movabs $0x72657672657320,%rax
    25c5:	65 72 00 
    25c8:	49 89 47 2e          	mov    %rax,0x2e(%r15)
    25cc:	44 89 e7             	mov    %r12d,%edi
    25cf:	e8 ac ec ff ff       	call   1280 <_init+0x280>
    25d4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    25d9:	eb 7e                	jmp    2659 <submitr+0x6b1>
    25db:	4c 8d 8c 24 50 80 00 	lea    0x8050(%rsp),%r9
    25e2:	00 
    25e3:	48 8d 0d 8e 0e 00 00 	lea    0xe8e(%rip),%rcx        # 3478 <_IO_stdin_used+0x478>
    25ea:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    25f1:	be 02 00 00 00       	mov    $0x2,%esi
    25f6:	4c 89 ff             	mov    %r15,%rdi
    25f9:	b8 00 00 00 00       	mov    $0x0,%eax
    25fe:	e8 9d ed ff ff       	call   13a0 <_init+0x3a0>
    2603:	44 89 e7             	mov    %r12d,%edi
    2606:	e8 75 ec ff ff       	call   1280 <_init+0x280>
    260b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2610:	eb 47                	jmp    2659 <submitr+0x6b1>
    2612:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
    2619:	00 
    261a:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
    261f:	ba 00 20 00 00       	mov    $0x2000,%edx
    2624:	e8 b5 f8 ff ff       	call   1ede <rio_readlineb>
    2629:	48 85 c0             	test   %rax,%rax
    262c:	7e 54                	jle    2682 <submitr+0x6da>
    262e:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
    2635:	00 
    2636:	4c 89 ff             	mov    %r15,%rdi
    2639:	e8 e2 eb ff ff       	call   1220 <_init+0x220>
    263e:	44 89 e7             	mov    %r12d,%edi
    2641:	e8 3a ec ff ff       	call   1280 <_init+0x280>
    2646:	48 8d 35 74 0b 00 00 	lea    0xb74(%rip),%rsi        # 31c1 <_IO_stdin_used+0x1c1>
    264d:	4c 89 ff             	mov    %r15,%rdi
    2650:	e8 4b ec ff ff       	call   12a0 <_init+0x2a0>
    2655:	f7 d8                	neg    %eax
    2657:	19 c0                	sbb    %eax,%eax
    2659:	48 8b 94 24 58 a0 00 	mov    0xa058(%rsp),%rdx
    2660:	00 
    2661:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    2668:	00 00 
    266a:	0f 85 0e 01 00 00    	jne    277e <submitr+0x7d6>
    2670:	48 81 c4 68 a0 00 00 	add    $0xa068,%rsp
    2677:	5b                   	pop    %rbx
    2678:	5d                   	pop    %rbp
    2679:	41 5c                	pop    %r12
    267b:	41 5d                	pop    %r13
    267d:	41 5e                	pop    %r14
    267f:	41 5f                	pop    %r15
    2681:	c3                   	ret    
    2682:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    2689:	3a 20 43 
    268c:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    2693:	20 75 6e 
    2696:	49 89 07             	mov    %rax,(%r15)
    2699:	49 89 57 08          	mov    %rdx,0x8(%r15)
    269d:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    26a4:	74 6f 20 
    26a7:	48 ba 72 65 61 64 20 	movabs $0x6174732064616572,%rdx
    26ae:	73 74 61 
    26b1:	49 89 47 10          	mov    %rax,0x10(%r15)
    26b5:	49 89 57 18          	mov    %rdx,0x18(%r15)
    26b9:	48 b8 74 75 73 20 6d 	movabs $0x7373656d20737574,%rax
    26c0:	65 73 73 
    26c3:	48 ba 61 67 65 20 66 	movabs $0x6d6f726620656761,%rdx
    26ca:	72 6f 6d 
    26cd:	49 89 47 20          	mov    %rax,0x20(%r15)
    26d1:	49 89 57 28          	mov    %rdx,0x28(%r15)
    26d5:	48 b8 20 73 65 72 76 	movabs $0x72657672657320,%rax
    26dc:	65 72 00 
    26df:	49 89 47 30          	mov    %rax,0x30(%r15)
    26e3:	44 89 e7             	mov    %r12d,%edi
    26e6:	e8 95 eb ff ff       	call   1280 <_init+0x280>
    26eb:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    26f0:	e9 64 ff ff ff       	jmp    2659 <submitr+0x6b1>
    26f5:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
    26fc:	3a 20 52 
    26ff:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
    2706:	20 73 74 
    2709:	49 89 07             	mov    %rax,(%r15)
    270c:	49 89 57 08          	mov    %rdx,0x8(%r15)
    2710:	48 b8 72 69 6e 67 20 	movabs $0x6e6f6320676e6972,%rax
    2717:	63 6f 6e 
    271a:	48 ba 74 61 69 6e 73 	movabs $0x6e6120736e696174,%rdx
    2721:	20 61 6e 
    2724:	49 89 47 10          	mov    %rax,0x10(%r15)
    2728:	49 89 57 18          	mov    %rdx,0x18(%r15)
    272c:	48 b8 20 69 6c 6c 65 	movabs $0x6c6167656c6c6920,%rax
    2733:	67 61 6c 
    2736:	48 ba 20 6f 72 20 75 	movabs $0x72706e7520726f20,%rdx
    273d:	6e 70 72 
    2740:	49 89 47 20          	mov    %rax,0x20(%r15)
    2744:	49 89 57 28          	mov    %rdx,0x28(%r15)
    2748:	48 b8 69 6e 74 61 62 	movabs $0x20656c6261746e69,%rax
    274f:	6c 65 20 
    2752:	48 ba 63 68 61 72 61 	movabs $0x6574636172616863,%rdx
    2759:	63 74 65 
    275c:	49 89 47 30          	mov    %rax,0x30(%r15)
    2760:	49 89 57 38          	mov    %rdx,0x38(%r15)
    2764:	41 c7 47 3f 65 72 2e 	movl   $0x2e7265,0x3f(%r15)
    276b:	00 
    276c:	44 89 e7             	mov    %r12d,%edi
    276f:	e8 0c eb ff ff       	call   1280 <_init+0x280>
    2774:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2779:	e9 db fe ff ff       	jmp    2659 <submitr+0x6b1>
    277e:	e8 dd ea ff ff       	call   1260 <_init+0x260>

0000000000002783 <init_timeout>:
    2783:	f3 0f 1e fa          	endbr64 
    2787:	85 ff                	test   %edi,%edi
    2789:	75 01                	jne    278c <init_timeout+0x9>
    278b:	c3                   	ret    
    278c:	53                   	push   %rbx
    278d:	89 fb                	mov    %edi,%ebx
    278f:	48 8d 35 12 f7 ff ff 	lea    -0x8ee(%rip),%rsi        # 1ea8 <sigalrm_handler>
    2796:	bf 0e 00 00 00       	mov    $0xe,%edi
    279b:	e8 10 eb ff ff       	call   12b0 <_init+0x2b0>
    27a0:	85 db                	test   %ebx,%ebx
    27a2:	b8 00 00 00 00       	mov    $0x0,%eax
    27a7:	0f 49 c3             	cmovns %ebx,%eax
    27aa:	89 c7                	mov    %eax,%edi
    27ac:	e8 bf ea ff ff       	call   1270 <_init+0x270>
    27b1:	5b                   	pop    %rbx
    27b2:	c3                   	ret    

00000000000027b3 <init_driver>:
    27b3:	f3 0f 1e fa          	endbr64 
    27b7:	41 54                	push   %r12
    27b9:	55                   	push   %rbp
    27ba:	53                   	push   %rbx
    27bb:	48 83 ec 20          	sub    $0x20,%rsp
    27bf:	48 89 fd             	mov    %rdi,%rbp
    27c2:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    27c9:	00 00 
    27cb:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    27d0:	31 c0                	xor    %eax,%eax
    27d2:	be 01 00 00 00       	mov    $0x1,%esi
    27d7:	bf 0d 00 00 00       	mov    $0xd,%edi
    27dc:	e8 cf ea ff ff       	call   12b0 <_init+0x2b0>
    27e1:	be 01 00 00 00       	mov    $0x1,%esi
    27e6:	bf 1d 00 00 00       	mov    $0x1d,%edi
    27eb:	e8 c0 ea ff ff       	call   12b0 <_init+0x2b0>
    27f0:	be 01 00 00 00       	mov    $0x1,%esi
    27f5:	bf 1d 00 00 00       	mov    $0x1d,%edi
    27fa:	e8 b1 ea ff ff       	call   12b0 <_init+0x2b0>
    27ff:	ba 00 00 00 00       	mov    $0x0,%edx
    2804:	be 01 00 00 00       	mov    $0x1,%esi
    2809:	bf 02 00 00 00       	mov    $0x2,%edi
    280e:	e8 9d eb ff ff       	call   13b0 <_init+0x3b0>
    2813:	85 c0                	test   %eax,%eax
    2815:	0f 88 9d 00 00 00    	js     28b8 <init_driver+0x105>
    281b:	89 c3                	mov    %eax,%ebx
    281d:	48 8d 3d a0 09 00 00 	lea    0x9a0(%rip),%rdi        # 31c4 <_IO_stdin_used+0x1c4>
    2824:	e8 97 ea ff ff       	call   12c0 <_init+0x2c0>
    2829:	48 85 c0             	test   %rax,%rax
    282c:	0f 84 d3 00 00 00    	je     2905 <init_driver+0x152>
    2832:	49 89 e4             	mov    %rsp,%r12
    2835:	48 c7 44 24 02 00 00 	movq   $0x0,0x2(%rsp)
    283c:	00 00 
    283e:	48 c7 44 24 08 00 00 	movq   $0x0,0x8(%rsp)
    2845:	00 00 
    2847:	66 c7 04 24 02 00    	movw   $0x2,(%rsp)
    284d:	48 63 50 14          	movslq 0x14(%rax),%rdx
    2851:	48 8b 40 18          	mov    0x18(%rax),%rax
    2855:	48 8b 30             	mov    (%rax),%rsi
    2858:	48 8d 7c 24 04       	lea    0x4(%rsp),%rdi
    285d:	b9 0c 00 00 00       	mov    $0xc,%ecx
    2862:	e8 69 ea ff ff       	call   12d0 <_init+0x2d0>
    2867:	66 c7 44 24 02 3b 6e 	movw   $0x6e3b,0x2(%rsp)
    286e:	ba 10 00 00 00       	mov    $0x10,%edx
    2873:	4c 89 e6             	mov    %r12,%rsi
    2876:	89 df                	mov    %ebx,%edi
    2878:	e8 e3 ea ff ff       	call   1360 <_init+0x360>
    287d:	85 c0                	test   %eax,%eax
    287f:	0f 88 e5 00 00 00    	js     296a <init_driver+0x1b7>
    2885:	89 df                	mov    %ebx,%edi
    2887:	e8 f4 e9 ff ff       	call   1280 <_init+0x280>
    288c:	66 c7 45 00 4f 4b    	movw   $0x4b4f,0x0(%rbp)
    2892:	c6 45 02 00          	movb   $0x0,0x2(%rbp)
    2896:	b8 00 00 00 00       	mov    $0x0,%eax
    289b:	48 8b 54 24 18       	mov    0x18(%rsp),%rdx
    28a0:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    28a7:	00 00 
    28a9:	0f 85 f3 00 00 00    	jne    29a2 <init_driver+0x1ef>
    28af:	48 83 c4 20          	add    $0x20,%rsp
    28b3:	5b                   	pop    %rbx
    28b4:	5d                   	pop    %rbp
    28b5:	41 5c                	pop    %r12
    28b7:	c3                   	ret    
    28b8:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
    28bf:	3a 20 43 
    28c2:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
    28c9:	20 75 6e 
    28cc:	48 89 45 00          	mov    %rax,0x0(%rbp)
    28d0:	48 89 55 08          	mov    %rdx,0x8(%rbp)
    28d4:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    28db:	74 6f 20 
    28de:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
    28e5:	65 20 73 
    28e8:	48 89 45 10          	mov    %rax,0x10(%rbp)
    28ec:	48 89 55 18          	mov    %rdx,0x18(%rbp)
    28f0:	48 b8 20 73 6f 63 6b 	movabs $0x74656b636f7320,%rax
    28f7:	65 74 00 
    28fa:	48 89 45 1e          	mov    %rax,0x1e(%rbp)
    28fe:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2903:	eb 96                	jmp    289b <init_driver+0xe8>
    2905:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
    290c:	3a 20 44 
    290f:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
    2916:	20 75 6e 
    2919:	48 89 45 00          	mov    %rax,0x0(%rbp)
    291d:	48 89 55 08          	mov    %rdx,0x8(%rbp)
    2921:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
    2928:	74 6f 20 
    292b:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
    2932:	76 65 20 
    2935:	48 89 45 10          	mov    %rax,0x10(%rbp)
    2939:	48 89 55 18          	mov    %rdx,0x18(%rbp)
    293d:	48 b8 20 73 65 72 76 	movabs $0x2072657672657320,%rax
    2944:	65 72 20 
    2947:	48 ba 61 64 64 72 65 	movabs $0x73736572646461,%rdx
    294e:	73 73 00 
    2951:	48 89 45 1f          	mov    %rax,0x1f(%rbp)
    2955:	48 89 55 27          	mov    %rdx,0x27(%rbp)
    2959:	89 df                	mov    %ebx,%edi
    295b:	e8 20 e9 ff ff       	call   1280 <_init+0x280>
    2960:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2965:	e9 31 ff ff ff       	jmp    289b <init_driver+0xe8>
    296a:	4c 8d 05 53 08 00 00 	lea    0x853(%rip),%r8        # 31c4 <_IO_stdin_used+0x1c4>
    2971:	48 8d 0d 30 0b 00 00 	lea    0xb30(%rip),%rcx        # 34a8 <_IO_stdin_used+0x4a8>
    2978:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
    297f:	be 02 00 00 00       	mov    $0x2,%esi
    2984:	48 89 ef             	mov    %rbp,%rdi
    2987:	b8 00 00 00 00       	mov    $0x0,%eax
    298c:	e8 0f ea ff ff       	call   13a0 <_init+0x3a0>
    2991:	89 df                	mov    %ebx,%edi
    2993:	e8 e8 e8 ff ff       	call   1280 <_init+0x280>
    2998:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    299d:	e9 f9 fe ff ff       	jmp    289b <init_driver+0xe8>
    29a2:	e8 b9 e8 ff ff       	call   1260 <_init+0x260>

00000000000029a7 <driver_post>:
    29a7:	f3 0f 1e fa          	endbr64 
    29ab:	53                   	push   %rbx
    29ac:	4c 89 c3             	mov    %r8,%rbx
    29af:	85 c9                	test   %ecx,%ecx
    29b1:	75 17                	jne    29ca <driver_post+0x23>
    29b3:	48 85 ff             	test   %rdi,%rdi
    29b6:	74 05                	je     29bd <driver_post+0x16>
    29b8:	80 3f 00             	cmpb   $0x0,(%rdi)
    29bb:	75 33                	jne    29f0 <driver_post+0x49>
    29bd:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
    29c2:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
    29c6:	89 c8                	mov    %ecx,%eax
    29c8:	5b                   	pop    %rbx
    29c9:	c3                   	ret    
    29ca:	48 8d 35 0b 08 00 00 	lea    0x80b(%rip),%rsi        # 31dc <_IO_stdin_used+0x1dc>
    29d1:	bf 02 00 00 00       	mov    $0x2,%edi
    29d6:	b8 00 00 00 00       	mov    $0x0,%eax
    29db:	e8 50 e9 ff ff       	call   1330 <_init+0x330>
    29e0:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
    29e5:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
    29e9:	b8 00 00 00 00       	mov    $0x0,%eax
    29ee:	eb d8                	jmp    29c8 <driver_post+0x21>
    29f0:	41 50                	push   %r8
    29f2:	52                   	push   %rdx
    29f3:	4c 8d 0d f9 07 00 00 	lea    0x7f9(%rip),%r9        # 31f3 <_IO_stdin_used+0x1f3>
    29fa:	49 89 f0             	mov    %rsi,%r8
    29fd:	48 89 f9             	mov    %rdi,%rcx
    2a00:	48 8d 15 f4 07 00 00 	lea    0x7f4(%rip),%rdx        # 31fb <_IO_stdin_used+0x1fb>
    2a07:	be 6e 3b 00 00       	mov    $0x3b6e,%esi
    2a0c:	48 8d 3d b1 07 00 00 	lea    0x7b1(%rip),%rdi        # 31c4 <_IO_stdin_used+0x1c4>
    2a13:	e8 90 f5 ff ff       	call   1fa8 <submitr>
    2a18:	48 83 c4 10          	add    $0x10,%rsp
    2a1c:	eb aa                	jmp    29c8 <driver_post+0x21>

Disassembly of section .fini:

0000000000002a20 <_fini>:
    2a20:	f3 0f 1e fa          	endbr64 
    2a24:	48 83 ec 08          	sub    $0x8,%rsp
    2a28:	48 83 c4 08          	add    $0x8,%rsp
    2a2c:	c3                   	ret    
