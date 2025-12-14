
rtarget：     文件格式 elf64-x86-64


Disassembly of section .text:

0000000000808000 <_start>:
  808000:	31 ed                	xor    %ebp,%ebp
  808002:	49 89 d1             	mov    %rdx,%r9
  808005:	5e                   	pop    %rsi
  808006:	48 89 e2             	mov    %rsp,%rdx
  808009:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  80800d:	50                   	push   %rax
  80800e:	54                   	push   %rsp
  80800f:	49 c7 c0 e0 a1 80 00 	mov    $0x80a1e0,%r8
  808016:	48 c7 c1 70 a1 80 00 	mov    $0x80a170,%rcx
  80801d:	48 c7 c7 81 82 80 00 	mov    $0x808281,%rdi
  808024:	ff 15 c6 3f 20 00    	call   *0x203fc6(%rip)        # a0bff0 <__libc_start_main@GLIBC_2.2.5>
  80802a:	f4                   	hlt
  80802b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000808030 <_dl_relocate_static_pie>:
  808030:	f3 c3                	repz ret
  808032:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  808039:	00 00 00 
  80803c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000808040 <deregister_tm_clones>:
  808040:	55                   	push   %rbp
  808041:	b8 98 c4 a0 00       	mov    $0xa0c498,%eax
  808046:	48 3d 98 c4 a0 00    	cmp    $0xa0c498,%rax
  80804c:	48 89 e5             	mov    %rsp,%rbp
  80804f:	74 17                	je     808068 <deregister_tm_clones+0x28>
  808051:	b8 00 00 00 00       	mov    $0x0,%eax
  808056:	48 85 c0             	test   %rax,%rax
  808059:	74 0d                	je     808068 <deregister_tm_clones+0x28>
  80805b:	5d                   	pop    %rbp
  80805c:	bf 98 c4 a0 00       	mov    $0xa0c498,%edi
  808061:	ff e0                	jmp    *%rax
  808063:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  808068:	5d                   	pop    %rbp
  808069:	c3                   	ret
  80806a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000808070 <register_tm_clones>:
  808070:	be 98 c4 a0 00       	mov    $0xa0c498,%esi
  808075:	55                   	push   %rbp
  808076:	48 81 ee 98 c4 a0 00 	sub    $0xa0c498,%rsi
  80807d:	48 89 e5             	mov    %rsp,%rbp
  808080:	48 c1 fe 03          	sar    $0x3,%rsi
  808084:	48 89 f0             	mov    %rsi,%rax
  808087:	48 c1 e8 3f          	shr    $0x3f,%rax
  80808b:	48 01 c6             	add    %rax,%rsi
  80808e:	48 d1 fe             	sar    $1,%rsi
  808091:	74 15                	je     8080a8 <register_tm_clones+0x38>
  808093:	b8 00 00 00 00       	mov    $0x0,%eax
  808098:	48 85 c0             	test   %rax,%rax
  80809b:	74 0b                	je     8080a8 <register_tm_clones+0x38>
  80809d:	5d                   	pop    %rbp
  80809e:	bf 98 c4 a0 00       	mov    $0xa0c498,%edi
  8080a3:	ff e0                	jmp    *%rax
  8080a5:	0f 1f 00             	nopl   (%rax)
  8080a8:	5d                   	pop    %rbp
  8080a9:	c3                   	ret
  8080aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000008080b0 <__do_global_dtors_aux>:
  8080b0:	80 3d 11 44 20 00 00 	cmpb   $0x0,0x204411(%rip)        # a0c4c8 <completed.7698>
  8080b7:	75 17                	jne    8080d0 <__do_global_dtors_aux+0x20>
  8080b9:	55                   	push   %rbp
  8080ba:	48 89 e5             	mov    %rsp,%rbp
  8080bd:	e8 7e ff ff ff       	call   808040 <deregister_tm_clones>
  8080c2:	c6 05 ff 43 20 00 01 	movb   $0x1,0x2043ff(%rip)        # a0c4c8 <completed.7698>
  8080c9:	5d                   	pop    %rbp
  8080ca:	c3                   	ret
  8080cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  8080d0:	f3 c3                	repz ret
  8080d2:	0f 1f 40 00          	nopl   0x0(%rax)
  8080d6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  8080dd:	00 00 00 

00000000008080e0 <frame_dummy>:
  8080e0:	55                   	push   %rbp
  8080e1:	48 89 e5             	mov    %rsp,%rbp
  8080e4:	5d                   	pop    %rbp
  8080e5:	eb 89                	jmp    808070 <register_tm_clones>

00000000008080e7 <usage>:
  8080e7:	48 83 ec 08          	sub    $0x8,%rsp
  8080eb:	48 89 fa             	mov    %rdi,%rdx
  8080ee:	83 3d 13 44 20 00 00 	cmpl   $0x0,0x204413(%rip)        # a0c508 <is_checker>
  8080f5:	74 50                	je     808147 <usage+0x60>
  8080f7:	48 8d 35 fa 20 00 00 	lea    0x20fa(%rip),%rsi        # 80a1f8 <_IO_stdin_used+0x8>
  8080fe:	bf 01 00 00 00       	mov    $0x1,%edi
  808103:	b8 00 00 00 00       	mov    $0x0,%eax
  808108:	e8 d3 8c bf ff       	call   400de0 <__printf_chk@plt>
  80810d:	48 8d 3d 1c 21 00 00 	lea    0x211c(%rip),%rdi        # 80a230 <_IO_stdin_used+0x40>
  808114:	e8 a7 8b bf ff       	call   400cc0 <puts@plt>
  808119:	48 8d 3d 10 22 00 00 	lea    0x2210(%rip),%rdi        # 80a330 <_IO_stdin_used+0x140>
  808120:	e8 9b 8b bf ff       	call   400cc0 <puts@plt>
  808125:	48 8d 3d 2c 21 00 00 	lea    0x212c(%rip),%rdi        # 80a258 <_IO_stdin_used+0x68>
  80812c:	e8 8f 8b bf ff       	call   400cc0 <puts@plt>
  808131:	48 8d 3d 12 22 00 00 	lea    0x2212(%rip),%rdi        # 80a34a <_IO_stdin_used+0x15a>
  808138:	e8 83 8b bf ff       	call   400cc0 <puts@plt>
  80813d:	bf 00 00 00 00       	mov    $0x0,%edi
  808142:	e8 d9 8c bf ff       	call   400e20 <exit@plt>
  808147:	48 8d 35 18 22 00 00 	lea    0x2218(%rip),%rsi        # 80a366 <_IO_stdin_used+0x176>
  80814e:	bf 01 00 00 00       	mov    $0x1,%edi
  808153:	b8 00 00 00 00       	mov    $0x0,%eax
  808158:	e8 83 8c bf ff       	call   400de0 <__printf_chk@plt>
  80815d:	48 8d 3d 1c 21 00 00 	lea    0x211c(%rip),%rdi        # 80a280 <_IO_stdin_used+0x90>
  808164:	e8 57 8b bf ff       	call   400cc0 <puts@plt>
  808169:	48 8d 3d 38 21 00 00 	lea    0x2138(%rip),%rdi        # 80a2a8 <_IO_stdin_used+0xb8>
  808170:	e8 4b 8b bf ff       	call   400cc0 <puts@plt>
  808175:	48 8d 3d 08 22 00 00 	lea    0x2208(%rip),%rdi        # 80a384 <_IO_stdin_used+0x194>
  80817c:	e8 3f 8b bf ff       	call   400cc0 <puts@plt>
  808181:	eb ba                	jmp    80813d <usage+0x56>

0000000000808183 <initialize_target>:
  808183:	55                   	push   %rbp
  808184:	53                   	push   %rbx
  808185:	48 81 ec 18 20 00 00 	sub    $0x2018,%rsp
  80818c:	89 f5                	mov    %esi,%ebp
  80818e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  808195:	00 00 
  808197:	48 89 84 24 08 20 00 	mov    %rax,0x2008(%rsp)
  80819e:	00 
  80819f:	31 c0                	xor    %eax,%eax
  8081a1:	89 3d 51 43 20 00    	mov    %edi,0x204351(%rip)        # a0c4f8 <check_level>
  8081a7:	8b 3d 83 3f 20 00    	mov    0x203f83(%rip),%edi        # a0c130 <target_id>
  8081ad:	e8 9b 1f 00 00       	call   80a14d <gencookie>
  8081b2:	89 05 4c 43 20 00    	mov    %eax,0x20434c(%rip)        # a0c504 <cookie>
  8081b8:	89 c7                	mov    %eax,%edi
  8081ba:	e8 8e 1f 00 00       	call   80a14d <gencookie>
  8081bf:	89 05 3b 43 20 00    	mov    %eax,0x20433b(%rip)        # a0c500 <authkey>
  8081c5:	8b 05 65 3f 20 00    	mov    0x203f65(%rip),%eax        # a0c130 <target_id>
  8081cb:	8d 78 01             	lea    0x1(%rax),%edi
  8081ce:	e8 bd 8a bf ff       	call   400c90 <srandom@plt>
  8081d3:	e8 c8 8b bf ff       	call   400da0 <random@plt>
  8081d8:	89 c7                	mov    %eax,%edi
  8081da:	e8 8d 02 00 00       	call   80846c <scramble>
  8081df:	89 c3                	mov    %eax,%ebx
  8081e1:	85 ed                	test   %ebp,%ebp
  8081e3:	75 50                	jne    808235 <initialize_target+0xb2>
  8081e5:	b8 00 00 00 00       	mov    $0x0,%eax
  8081ea:	01 d8                	add    %ebx,%eax
  8081ec:	0f b7 c0             	movzwl %ax,%eax
  8081ef:	8d 04 c5 00 01 00 00 	lea    0x100(,%rax,8),%eax
  8081f6:	89 c0                	mov    %eax,%eax
  8081f8:	48 89 05 91 42 20 00 	mov    %rax,0x204291(%rip)        # a0c490 <buf_offset>
  8081ff:	c6 05 2a 4f 20 00 72 	movb   $0x72,0x204f2a(%rip)        # a0d130 <target_prefix>
  808206:	83 3d 7b 42 20 00 00 	cmpl   $0x0,0x20427b(%rip)        # a0c488 <notify>
  80820d:	74 09                	je     808218 <initialize_target+0x95>
  80820f:	83 3d f2 42 20 00 00 	cmpl   $0x0,0x2042f2(%rip)        # a0c508 <is_checker>
  808216:	74 35                	je     80824d <initialize_target+0xca>
  808218:	48 8b 84 24 08 20 00 	mov    0x2008(%rsp),%rax
  80821f:	00 
  808220:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  808227:	00 00 
  808229:	75 51                	jne    80827c <initialize_target+0xf9>
  80822b:	48 81 c4 18 20 00 00 	add    $0x2018,%rsp
  808232:	5b                   	pop    %rbx
  808233:	5d                   	pop    %rbp
  808234:	c3                   	ret
  808235:	bf 00 00 00 00       	mov    $0x0,%edi
  80823a:	e8 51 8b bf ff       	call   400d90 <time@plt>
  80823f:	89 c7                	mov    %eax,%edi
  808241:	e8 4a 8a bf ff       	call   400c90 <srandom@plt>
  808246:	e8 55 8b bf ff       	call   400da0 <random@plt>
  80824b:	eb 9d                	jmp    8081ea <initialize_target+0x67>
  80824d:	48 89 e7             	mov    %rsp,%rdi
  808250:	e8 28 1c 00 00       	call   809e7d <init_driver>
  808255:	85 c0                	test   %eax,%eax
  808257:	79 bf                	jns    808218 <initialize_target+0x95>
  808259:	48 89 e2             	mov    %rsp,%rdx
  80825c:	48 8d 35 75 20 00 00 	lea    0x2075(%rip),%rsi        # 80a2d8 <_IO_stdin_used+0xe8>
  808263:	bf 01 00 00 00       	mov    $0x1,%edi
  808268:	b8 00 00 00 00       	mov    $0x0,%eax
  80826d:	e8 6e 8b bf ff       	call   400de0 <__printf_chk@plt>
  808272:	bf 08 00 00 00       	mov    $0x8,%edi
  808277:	e8 a4 8b bf ff       	call   400e20 <exit@plt>
  80827c:	e8 5f 8a bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000808281 <main>:
  808281:	41 56                	push   %r14
  808283:	41 55                	push   %r13
  808285:	41 54                	push   %r12
  808287:	55                   	push   %rbp
  808288:	53                   	push   %rbx
  808289:	41 89 fc             	mov    %edi,%r12d
  80828c:	48 89 f3             	mov    %rsi,%rbx
  80828f:	48 c7 c6 84 91 80 00 	mov    $0x809184,%rsi
  808296:	bf 0b 00 00 00       	mov    $0xb,%edi
  80829b:	e8 a0 8a bf ff       	call   400d40 <signal@plt>
  8082a0:	48 c7 c6 30 91 80 00 	mov    $0x809130,%rsi
  8082a7:	bf 07 00 00 00       	mov    $0x7,%edi
  8082ac:	e8 8f 8a bf ff       	call   400d40 <signal@plt>
  8082b1:	48 c7 c6 d8 91 80 00 	mov    $0x8091d8,%rsi
  8082b8:	bf 04 00 00 00       	mov    $0x4,%edi
  8082bd:	e8 7e 8a bf ff       	call   400d40 <signal@plt>
  8082c2:	83 3d 3f 42 20 00 00 	cmpl   $0x0,0x20423f(%rip)        # a0c508 <is_checker>
  8082c9:	75 26                	jne    8082f1 <main+0x70>
  8082cb:	48 8d 2d cb 20 00 00 	lea    0x20cb(%rip),%rbp        # 80a39d <_IO_stdin_used+0x1ad>
  8082d2:	48 8b 05 c7 41 20 00 	mov    0x2041c7(%rip),%rax        # a0c4a0 <stdin@GLIBC_2.2.5>
  8082d9:	48 89 05 10 42 20 00 	mov    %rax,0x204210(%rip)        # a0c4f0 <infile>
  8082e0:	41 bd 00 00 00 00    	mov    $0x0,%r13d
  8082e6:	41 be 00 00 00 00    	mov    $0x0,%r14d
  8082ec:	e9 8d 00 00 00       	jmp    80837e <main+0xfd>
  8082f1:	48 c7 c6 2c 92 80 00 	mov    $0x80922c,%rsi
  8082f8:	bf 0e 00 00 00       	mov    $0xe,%edi
  8082fd:	e8 3e 8a bf ff       	call   400d40 <signal@plt>
  808302:	bf 05 00 00 00       	mov    $0x5,%edi
  808307:	e8 04 8a bf ff       	call   400d10 <alarm@plt>
  80830c:	48 8d 2d 8f 20 00 00 	lea    0x208f(%rip),%rbp        # 80a3a2 <_IO_stdin_used+0x1b2>
  808313:	eb bd                	jmp    8082d2 <main+0x51>
  808315:	48 8b 3b             	mov    (%rbx),%rdi
  808318:	e8 ca fd ff ff       	call   8080e7 <usage>
  80831d:	48 8d 35 f1 22 00 00 	lea    0x22f1(%rip),%rsi        # 80a615 <_IO_stdin_used+0x425>
  808324:	48 8b 3d 7d 41 20 00 	mov    0x20417d(%rip),%rdi        # a0c4a8 <optarg@GLIBC_2.2.5>
  80832b:	e8 c0 8a bf ff       	call   400df0 <fopen@plt>
  808330:	48 89 05 b9 41 20 00 	mov    %rax,0x2041b9(%rip)        # a0c4f0 <infile>
  808337:	48 85 c0             	test   %rax,%rax
  80833a:	75 42                	jne    80837e <main+0xfd>
  80833c:	48 8b 0d 65 41 20 00 	mov    0x204165(%rip),%rcx        # a0c4a8 <optarg@GLIBC_2.2.5>
  808343:	48 8d 15 60 20 00 00 	lea    0x2060(%rip),%rdx        # 80a3aa <_IO_stdin_used+0x1ba>
  80834a:	be 01 00 00 00       	mov    $0x1,%esi
  80834f:	48 8b 3d 6a 41 20 00 	mov    0x20416a(%rip),%rdi        # a0c4c0 <stderr@GLIBC_2.2.5>
  808356:	e8 e5 8a bf ff       	call   400e40 <__fprintf_chk@plt>
  80835b:	b8 01 00 00 00       	mov    $0x1,%eax
  808360:	e9 d9 00 00 00       	jmp    80843e <main+0x1bd>
  808365:	ba 10 00 00 00       	mov    $0x10,%edx
  80836a:	be 00 00 00 00       	mov    $0x0,%esi
  80836f:	48 8b 3d 32 41 20 00 	mov    0x204132(%rip),%rdi        # a0c4a8 <optarg@GLIBC_2.2.5>
  808376:	e8 95 8a bf ff       	call   400e10 <strtoul@plt>
  80837b:	41 89 c6             	mov    %eax,%r14d
  80837e:	48 89 ea             	mov    %rbp,%rdx
  808381:	48 89 de             	mov    %rbx,%rsi
  808384:	44 89 e7             	mov    %r12d,%edi
  808387:	e8 74 8a bf ff       	call   400e00 <getopt@plt>
  80838c:	3c ff                	cmp    $0xff,%al
  80838e:	74 62                	je     8083f2 <main+0x171>
  808390:	0f be d0             	movsbl %al,%edx
  808393:	83 e8 61             	sub    $0x61,%eax
  808396:	3c 10                	cmp    $0x10,%al
  808398:	77 3a                	ja     8083d4 <main+0x153>
  80839a:	0f b6 c0             	movzbl %al,%eax
  80839d:	48 8d 0d 44 20 00 00 	lea    0x2044(%rip),%rcx        # 80a3e8 <_IO_stdin_used+0x1f8>
  8083a4:	48 63 04 81          	movslq (%rcx,%rax,4),%rax
  8083a8:	48 01 c8             	add    %rcx,%rax
  8083ab:	ff e0                	jmp    *%rax
  8083ad:	ba 0a 00 00 00       	mov    $0xa,%edx
  8083b2:	be 00 00 00 00       	mov    $0x0,%esi
  8083b7:	48 8b 3d ea 40 20 00 	mov    0x2040ea(%rip),%rdi        # a0c4a8 <optarg@GLIBC_2.2.5>
  8083be:	e8 ad 89 bf ff       	call   400d70 <strtol@plt>
  8083c3:	41 89 c5             	mov    %eax,%r13d
  8083c6:	eb b6                	jmp    80837e <main+0xfd>
  8083c8:	c7 05 b6 40 20 00 00 	movl   $0x0,0x2040b6(%rip)        # a0c488 <notify>
  8083cf:	00 00 00 
  8083d2:	eb aa                	jmp    80837e <main+0xfd>
  8083d4:	48 8d 35 ec 1f 00 00 	lea    0x1fec(%rip),%rsi        # 80a3c7 <_IO_stdin_used+0x1d7>
  8083db:	bf 01 00 00 00       	mov    $0x1,%edi
  8083e0:	b8 00 00 00 00       	mov    $0x0,%eax
  8083e5:	e8 f6 89 bf ff       	call   400de0 <__printf_chk@plt>
  8083ea:	48 8b 3b             	mov    (%rbx),%rdi
  8083ed:	e8 f5 fc ff ff       	call   8080e7 <usage>
  8083f2:	be 01 00 00 00       	mov    $0x1,%esi
  8083f7:	44 89 ef             	mov    %r13d,%edi
  8083fa:	e8 84 fd ff ff       	call   808183 <initialize_target>
  8083ff:	83 3d 02 41 20 00 00 	cmpl   $0x0,0x204102(%rip)        # a0c508 <is_checker>
  808406:	74 09                	je     808411 <main+0x190>
  808408:	44 39 35 f1 40 20 00 	cmp    %r14d,0x2040f1(%rip)        # a0c500 <authkey>
  80840f:	75 36                	jne    808447 <main+0x1c6>
  808411:	8b 15 ed 40 20 00    	mov    0x2040ed(%rip),%edx        # a0c504 <cookie>
  808417:	48 8d 35 bc 1f 00 00 	lea    0x1fbc(%rip),%rsi        # 80a3da <_IO_stdin_used+0x1ea>
  80841e:	bf 01 00 00 00       	mov    $0x1,%edi
  808423:	b8 00 00 00 00       	mov    $0x0,%eax
  808428:	e8 b3 89 bf ff       	call   400de0 <__printf_chk@plt>
  80842d:	48 8b 3d 5c 40 20 00 	mov    0x20405c(%rip),%rdi        # a0c490 <buf_offset>
  808434:	e8 4a 0e 00 00       	call   809283 <launch>
  808439:	b8 00 00 00 00       	mov    $0x0,%eax
  80843e:	5b                   	pop    %rbx
  80843f:	5d                   	pop    %rbp
  808440:	41 5c                	pop    %r12
  808442:	41 5d                	pop    %r13
  808444:	41 5e                	pop    %r14
  808446:	c3                   	ret
  808447:	44 89 f2             	mov    %r14d,%edx
  80844a:	48 8d 35 af 1e 00 00 	lea    0x1eaf(%rip),%rsi        # 80a300 <_IO_stdin_used+0x110>
  808451:	bf 01 00 00 00       	mov    $0x1,%edi
  808456:	b8 00 00 00 00       	mov    $0x0,%eax
  80845b:	e8 80 89 bf ff       	call   400de0 <__printf_chk@plt>
  808460:	b8 00 00 00 00       	mov    $0x0,%eax
  808465:	e8 1f 09 00 00       	call   808d89 <check_fail>
  80846a:	eb a5                	jmp    808411 <main+0x190>

000000000080846c <scramble>:
  80846c:	48 83 ec 38          	sub    $0x38,%rsp
  808470:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  808477:	00 00 
  808479:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
  80847e:	31 c0                	xor    %eax,%eax
  808480:	eb 10                	jmp    808492 <scramble+0x26>
  808482:	69 d0 76 85 00 00    	imul   $0x8576,%eax,%edx
  808488:	01 fa                	add    %edi,%edx
  80848a:	89 c1                	mov    %eax,%ecx
  80848c:	89 14 8c             	mov    %edx,(%rsp,%rcx,4)
  80848f:	83 c0 01             	add    $0x1,%eax
  808492:	83 f8 09             	cmp    $0x9,%eax
  808495:	76 eb                	jbe    808482 <scramble+0x16>
  808497:	8b 44 24 08          	mov    0x8(%rsp),%eax
  80849b:	69 c0 1a a2 00 00    	imul   $0xa21a,%eax,%eax
  8084a1:	89 44 24 08          	mov    %eax,0x8(%rsp)
  8084a5:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  8084a9:	69 c0 b7 a4 00 00    	imul   $0xa4b7,%eax,%eax
  8084af:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  8084b3:	8b 44 24 08          	mov    0x8(%rsp),%eax
  8084b7:	69 c0 fc a8 00 00    	imul   $0xa8fc,%eax,%eax
  8084bd:	89 44 24 08          	mov    %eax,0x8(%rsp)
  8084c1:	8b 04 24             	mov    (%rsp),%eax
  8084c4:	69 c0 36 f1 00 00    	imul   $0xf136,%eax,%eax
  8084ca:	89 04 24             	mov    %eax,(%rsp)
  8084cd:	8b 44 24 24          	mov    0x24(%rsp),%eax
  8084d1:	69 c0 27 c5 00 00    	imul   $0xc527,%eax,%eax
  8084d7:	89 44 24 24          	mov    %eax,0x24(%rsp)
  8084db:	8b 44 24 10          	mov    0x10(%rsp),%eax
  8084df:	69 c0 4c 35 00 00    	imul   $0x354c,%eax,%eax
  8084e5:	89 44 24 10          	mov    %eax,0x10(%rsp)
  8084e9:	8b 44 24 24          	mov    0x24(%rsp),%eax
  8084ed:	69 c0 d4 2f 00 00    	imul   $0x2fd4,%eax,%eax
  8084f3:	89 44 24 24          	mov    %eax,0x24(%rsp)
  8084f7:	8b 44 24 10          	mov    0x10(%rsp),%eax
  8084fb:	69 c0 f1 10 00 00    	imul   $0x10f1,%eax,%eax
  808501:	89 44 24 10          	mov    %eax,0x10(%rsp)
  808505:	8b 44 24 18          	mov    0x18(%rsp),%eax
  808509:	69 c0 95 9c 00 00    	imul   $0x9c95,%eax,%eax
  80850f:	89 44 24 18          	mov    %eax,0x18(%rsp)
  808513:	8b 04 24             	mov    (%rsp),%eax
  808516:	69 c0 c4 23 00 00    	imul   $0x23c4,%eax,%eax
  80851c:	89 04 24             	mov    %eax,(%rsp)
  80851f:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808523:	69 c0 7d 19 00 00    	imul   $0x197d,%eax,%eax
  808529:	89 44 24 20          	mov    %eax,0x20(%rsp)
  80852d:	8b 44 24 08          	mov    0x8(%rsp),%eax
  808531:	69 c0 62 4e 00 00    	imul   $0x4e62,%eax,%eax
  808537:	89 44 24 08          	mov    %eax,0x8(%rsp)
  80853b:	8b 44 24 18          	mov    0x18(%rsp),%eax
  80853f:	69 c0 46 13 00 00    	imul   $0x1346,%eax,%eax
  808545:	89 44 24 18          	mov    %eax,0x18(%rsp)
  808549:	8b 04 24             	mov    (%rsp),%eax
  80854c:	69 c0 17 65 00 00    	imul   $0x6517,%eax,%eax
  808552:	89 04 24             	mov    %eax,(%rsp)
  808555:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808559:	69 c0 a5 84 00 00    	imul   $0x84a5,%eax,%eax
  80855f:	89 44 24 20          	mov    %eax,0x20(%rsp)
  808563:	8b 44 24 04          	mov    0x4(%rsp),%eax
  808567:	69 c0 92 e9 00 00    	imul   $0xe992,%eax,%eax
  80856d:	89 44 24 04          	mov    %eax,0x4(%rsp)
  808571:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808575:	69 c0 9c 39 00 00    	imul   $0x399c,%eax,%eax
  80857b:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  80857f:	8b 44 24 10          	mov    0x10(%rsp),%eax
  808583:	69 c0 b3 50 00 00    	imul   $0x50b3,%eax,%eax
  808589:	89 44 24 10          	mov    %eax,0x10(%rsp)
  80858d:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  808591:	69 c0 ba ab 00 00    	imul   $0xabba,%eax,%eax
  808597:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  80859b:	8b 44 24 24          	mov    0x24(%rsp),%eax
  80859f:	69 c0 e2 d0 00 00    	imul   $0xd0e2,%eax,%eax
  8085a5:	89 44 24 24          	mov    %eax,0x24(%rsp)
  8085a9:	8b 44 24 08          	mov    0x8(%rsp),%eax
  8085ad:	69 c0 7f 66 00 00    	imul   $0x667f,%eax,%eax
  8085b3:	89 44 24 08          	mov    %eax,0x8(%rsp)
  8085b7:	8b 44 24 04          	mov    0x4(%rsp),%eax
  8085bb:	69 c0 8b 9b 00 00    	imul   $0x9b8b,%eax,%eax
  8085c1:	89 44 24 04          	mov    %eax,0x4(%rsp)
  8085c5:	8b 44 24 10          	mov    0x10(%rsp),%eax
  8085c9:	69 c0 dd 24 00 00    	imul   $0x24dd,%eax,%eax
  8085cf:	89 44 24 10          	mov    %eax,0x10(%rsp)
  8085d3:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8085d7:	69 c0 80 99 00 00    	imul   $0x9980,%eax,%eax
  8085dd:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8085e1:	8b 04 24             	mov    (%rsp),%eax
  8085e4:	69 c0 7f 77 00 00    	imul   $0x777f,%eax,%eax
  8085ea:	89 04 24             	mov    %eax,(%rsp)
  8085ed:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8085f1:	69 c0 8e a5 00 00    	imul   $0xa58e,%eax,%eax
  8085f7:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8085fb:	8b 44 24 10          	mov    0x10(%rsp),%eax
  8085ff:	69 c0 68 96 00 00    	imul   $0x9668,%eax,%eax
  808605:	89 44 24 10          	mov    %eax,0x10(%rsp)
  808609:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  80860d:	69 c0 b8 f8 00 00    	imul   $0xf8b8,%eax,%eax
  808613:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  808617:	8b 44 24 10          	mov    0x10(%rsp),%eax
  80861b:	69 c0 46 37 00 00    	imul   $0x3746,%eax,%eax
  808621:	89 44 24 10          	mov    %eax,0x10(%rsp)
  808625:	8b 44 24 24          	mov    0x24(%rsp),%eax
  808629:	69 c0 cb 0d 00 00    	imul   $0xdcb,%eax,%eax
  80862f:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808633:	8b 44 24 04          	mov    0x4(%rsp),%eax
  808637:	69 c0 aa 50 00 00    	imul   $0x50aa,%eax,%eax
  80863d:	89 44 24 04          	mov    %eax,0x4(%rsp)
  808641:	8b 44 24 18          	mov    0x18(%rsp),%eax
  808645:	69 c0 ab e2 00 00    	imul   $0xe2ab,%eax,%eax
  80864b:	89 44 24 18          	mov    %eax,0x18(%rsp)
  80864f:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808653:	69 c0 a6 85 00 00    	imul   $0x85a6,%eax,%eax
  808659:	89 44 24 20          	mov    %eax,0x20(%rsp)
  80865d:	8b 44 24 08          	mov    0x8(%rsp),%eax
  808661:	69 c0 de 6c 00 00    	imul   $0x6cde,%eax,%eax
  808667:	89 44 24 08          	mov    %eax,0x8(%rsp)
  80866b:	8b 44 24 24          	mov    0x24(%rsp),%eax
  80866f:	69 c0 47 75 00 00    	imul   $0x7547,%eax,%eax
  808675:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808679:	8b 44 24 20          	mov    0x20(%rsp),%eax
  80867d:	69 c0 41 a2 00 00    	imul   $0xa241,%eax,%eax
  808683:	89 44 24 20          	mov    %eax,0x20(%rsp)
  808687:	8b 44 24 18          	mov    0x18(%rsp),%eax
  80868b:	69 c0 ef 43 00 00    	imul   $0x43ef,%eax,%eax
  808691:	89 44 24 18          	mov    %eax,0x18(%rsp)
  808695:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808699:	69 c0 1a 72 00 00    	imul   $0x721a,%eax,%eax
  80869f:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  8086a3:	8b 44 24 20          	mov    0x20(%rsp),%eax
  8086a7:	69 c0 49 ea 00 00    	imul   $0xea49,%eax,%eax
  8086ad:	89 44 24 20          	mov    %eax,0x20(%rsp)
  8086b1:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8086b5:	69 c0 3f 2a 00 00    	imul   $0x2a3f,%eax,%eax
  8086bb:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8086bf:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8086c3:	69 c0 de c8 00 00    	imul   $0xc8de,%eax,%eax
  8086c9:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8086cd:	8b 44 24 04          	mov    0x4(%rsp),%eax
  8086d1:	69 c0 c4 f2 00 00    	imul   $0xf2c4,%eax,%eax
  8086d7:	89 44 24 04          	mov    %eax,0x4(%rsp)
  8086db:	8b 44 24 14          	mov    0x14(%rsp),%eax
  8086df:	69 c0 be c3 00 00    	imul   $0xc3be,%eax,%eax
  8086e5:	89 44 24 14          	mov    %eax,0x14(%rsp)
  8086e9:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  8086ed:	69 c0 f6 08 00 00    	imul   $0x8f6,%eax,%eax
  8086f3:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  8086f7:	8b 44 24 24          	mov    0x24(%rsp),%eax
  8086fb:	69 c0 4d 49 00 00    	imul   $0x494d,%eax,%eax
  808701:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808705:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  808709:	69 c0 f0 b6 00 00    	imul   $0xb6f0,%eax,%eax
  80870f:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  808713:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808717:	69 c0 1e 0e 00 00    	imul   $0xe1e,%eax,%eax
  80871d:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  808721:	8b 04 24             	mov    (%rsp),%eax
  808724:	69 c0 3d 24 00 00    	imul   $0x243d,%eax,%eax
  80872a:	89 04 24             	mov    %eax,(%rsp)
  80872d:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  808731:	69 c0 f9 cc 00 00    	imul   $0xccf9,%eax,%eax
  808737:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  80873b:	8b 44 24 24          	mov    0x24(%rsp),%eax
  80873f:	69 c0 25 c5 00 00    	imul   $0xc525,%eax,%eax
  808745:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808749:	8b 44 24 18          	mov    0x18(%rsp),%eax
  80874d:	69 c0 dc ce 00 00    	imul   $0xcedc,%eax,%eax
  808753:	89 44 24 18          	mov    %eax,0x18(%rsp)
  808757:	8b 04 24             	mov    (%rsp),%eax
  80875a:	69 c0 07 1e 00 00    	imul   $0x1e07,%eax,%eax
  808760:	89 04 24             	mov    %eax,(%rsp)
  808763:	8b 44 24 24          	mov    0x24(%rsp),%eax
  808767:	69 c0 33 a5 00 00    	imul   $0xa533,%eax,%eax
  80876d:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808771:	8b 44 24 18          	mov    0x18(%rsp),%eax
  808775:	69 c0 99 7b 00 00    	imul   $0x7b99,%eax,%eax
  80877b:	89 44 24 18          	mov    %eax,0x18(%rsp)
  80877f:	8b 44 24 10          	mov    0x10(%rsp),%eax
  808783:	69 c0 bb 9b 00 00    	imul   $0x9bbb,%eax,%eax
  808789:	89 44 24 10          	mov    %eax,0x10(%rsp)
  80878d:	8b 04 24             	mov    (%rsp),%eax
  808790:	69 c0 44 f1 00 00    	imul   $0xf144,%eax,%eax
  808796:	89 04 24             	mov    %eax,(%rsp)
  808799:	8b 44 24 18          	mov    0x18(%rsp),%eax
  80879d:	69 c0 a6 75 00 00    	imul   $0x75a6,%eax,%eax
  8087a3:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8087a7:	8b 44 24 04          	mov    0x4(%rsp),%eax
  8087ab:	69 c0 e1 c3 00 00    	imul   $0xc3e1,%eax,%eax
  8087b1:	89 44 24 04          	mov    %eax,0x4(%rsp)
  8087b5:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  8087b9:	69 c0 85 cf 00 00    	imul   $0xcf85,%eax,%eax
  8087bf:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  8087c3:	8b 04 24             	mov    (%rsp),%eax
  8087c6:	69 c0 6a 34 00 00    	imul   $0x346a,%eax,%eax
  8087cc:	89 04 24             	mov    %eax,(%rsp)
  8087cf:	8b 04 24             	mov    (%rsp),%eax
  8087d2:	69 c0 98 e3 00 00    	imul   $0xe398,%eax,%eax
  8087d8:	89 04 24             	mov    %eax,(%rsp)
  8087db:	8b 04 24             	mov    (%rsp),%eax
  8087de:	69 c0 c9 b2 00 00    	imul   $0xb2c9,%eax,%eax
  8087e4:	89 04 24             	mov    %eax,(%rsp)
  8087e7:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8087eb:	69 c0 f6 84 00 00    	imul   $0x84f6,%eax,%eax
  8087f1:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8087f5:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  8087f9:	69 c0 7a 85 00 00    	imul   $0x857a,%eax,%eax
  8087ff:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  808803:	8b 44 24 14          	mov    0x14(%rsp),%eax
  808807:	69 c0 22 68 00 00    	imul   $0x6822,%eax,%eax
  80880d:	89 44 24 14          	mov    %eax,0x14(%rsp)
  808811:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808815:	69 c0 30 94 00 00    	imul   $0x9430,%eax,%eax
  80881b:	89 44 24 20          	mov    %eax,0x20(%rsp)
  80881f:	8b 44 24 08          	mov    0x8(%rsp),%eax
  808823:	69 c0 06 b2 00 00    	imul   $0xb206,%eax,%eax
  808829:	89 44 24 08          	mov    %eax,0x8(%rsp)
  80882d:	8b 44 24 24          	mov    0x24(%rsp),%eax
  808831:	69 c0 ca 49 00 00    	imul   $0x49ca,%eax,%eax
  808837:	89 44 24 24          	mov    %eax,0x24(%rsp)
  80883b:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  80883f:	69 c0 59 42 00 00    	imul   $0x4259,%eax,%eax
  808845:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  808849:	8b 44 24 04          	mov    0x4(%rsp),%eax
  80884d:	69 c0 b5 e6 00 00    	imul   $0xe6b5,%eax,%eax
  808853:	89 44 24 04          	mov    %eax,0x4(%rsp)
  808857:	8b 44 24 24          	mov    0x24(%rsp),%eax
  80885b:	69 c0 3c 6b 00 00    	imul   $0x6b3c,%eax,%eax
  808861:	89 44 24 24          	mov    %eax,0x24(%rsp)
  808865:	8b 44 24 08          	mov    0x8(%rsp),%eax
  808869:	69 c0 af 42 00 00    	imul   $0x42af,%eax,%eax
  80886f:	89 44 24 08          	mov    %eax,0x8(%rsp)
  808873:	8b 44 24 10          	mov    0x10(%rsp),%eax
  808877:	69 c0 01 bc 00 00    	imul   $0xbc01,%eax,%eax
  80887d:	89 44 24 10          	mov    %eax,0x10(%rsp)
  808881:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808885:	69 c0 47 1a 00 00    	imul   $0x1a47,%eax,%eax
  80888b:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  80888f:	8b 44 24 04          	mov    0x4(%rsp),%eax
  808893:	69 c0 67 d3 00 00    	imul   $0xd367,%eax,%eax
  808899:	89 44 24 04          	mov    %eax,0x4(%rsp)
  80889d:	8b 44 24 24          	mov    0x24(%rsp),%eax
  8088a1:	69 c0 59 a4 00 00    	imul   $0xa459,%eax,%eax
  8088a7:	89 44 24 24          	mov    %eax,0x24(%rsp)
  8088ab:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  8088af:	69 c0 0c 3a 00 00    	imul   $0x3a0c,%eax,%eax
  8088b5:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  8088b9:	8b 44 24 08          	mov    0x8(%rsp),%eax
  8088bd:	69 c0 b5 a8 00 00    	imul   $0xa8b5,%eax,%eax
  8088c3:	89 44 24 08          	mov    %eax,0x8(%rsp)
  8088c7:	8b 44 24 04          	mov    0x4(%rsp),%eax
  8088cb:	69 c0 29 2e 00 00    	imul   $0x2e29,%eax,%eax
  8088d1:	89 44 24 04          	mov    %eax,0x4(%rsp)
  8088d5:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  8088d9:	69 c0 f1 10 00 00    	imul   $0x10f1,%eax,%eax
  8088df:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  8088e3:	8b 44 24 08          	mov    0x8(%rsp),%eax
  8088e7:	69 c0 cf 78 00 00    	imul   $0x78cf,%eax,%eax
  8088ed:	89 44 24 08          	mov    %eax,0x8(%rsp)
  8088f1:	8b 44 24 14          	mov    0x14(%rsp),%eax
  8088f5:	69 c0 4a cd 00 00    	imul   $0xcd4a,%eax,%eax
  8088fb:	89 44 24 14          	mov    %eax,0x14(%rsp)
  8088ff:	8b 44 24 18          	mov    0x18(%rsp),%eax
  808903:	69 c0 5a 57 00 00    	imul   $0x575a,%eax,%eax
  808909:	89 44 24 18          	mov    %eax,0x18(%rsp)
  80890d:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808911:	69 c0 0e 82 00 00    	imul   $0x820e,%eax,%eax
  808917:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  80891b:	8b 44 24 04          	mov    0x4(%rsp),%eax
  80891f:	69 c0 78 dc 00 00    	imul   $0xdc78,%eax,%eax
  808925:	89 44 24 04          	mov    %eax,0x4(%rsp)
  808929:	8b 44 24 20          	mov    0x20(%rsp),%eax
  80892d:	69 c0 c8 77 00 00    	imul   $0x77c8,%eax,%eax
  808933:	89 44 24 20          	mov    %eax,0x20(%rsp)
  808937:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  80893b:	69 c0 bc 40 00 00    	imul   $0x40bc,%eax,%eax
  808941:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  808945:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  808949:	69 c0 96 28 00 00    	imul   $0x2896,%eax,%eax
  80894f:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  808953:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808957:	69 c0 07 c1 00 00    	imul   $0xc107,%eax,%eax
  80895d:	89 44 24 20          	mov    %eax,0x20(%rsp)
  808961:	8b 04 24             	mov    (%rsp),%eax
  808964:	69 c0 44 88 00 00    	imul   $0x8844,%eax,%eax
  80896a:	89 04 24             	mov    %eax,(%rsp)
  80896d:	8b 44 24 20          	mov    0x20(%rsp),%eax
  808971:	69 c0 8f 91 00 00    	imul   $0x918f,%eax,%eax
  808977:	89 44 24 20          	mov    %eax,0x20(%rsp)
  80897b:	8b 44 24 0c          	mov    0xc(%rsp),%eax
  80897f:	69 c0 6d 4b 00 00    	imul   $0x4b6d,%eax,%eax
  808985:	89 44 24 0c          	mov    %eax,0xc(%rsp)
  808989:	8b 44 24 08          	mov    0x8(%rsp),%eax
  80898d:	69 c0 c1 83 00 00    	imul   $0x83c1,%eax,%eax
  808993:	89 44 24 08          	mov    %eax,0x8(%rsp)
  808997:	8b 04 24             	mov    (%rsp),%eax
  80899a:	69 c0 9d 8a 00 00    	imul   $0x8a9d,%eax,%eax
  8089a0:	89 04 24             	mov    %eax,(%rsp)
  8089a3:	8b 44 24 14          	mov    0x14(%rsp),%eax
  8089a7:	69 c0 52 22 00 00    	imul   $0x2252,%eax,%eax
  8089ad:	89 44 24 14          	mov    %eax,0x14(%rsp)
  8089b1:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
  8089b5:	69 c0 36 48 00 00    	imul   $0x4836,%eax,%eax
  8089bb:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
  8089bf:	8b 44 24 18          	mov    0x18(%rsp),%eax
  8089c3:	69 c0 b1 40 00 00    	imul   $0x40b1,%eax,%eax
  8089c9:	89 44 24 18          	mov    %eax,0x18(%rsp)
  8089cd:	ba 00 00 00 00       	mov    $0x0,%edx
  8089d2:	b8 00 00 00 00       	mov    $0x0,%eax
  8089d7:	eb 0a                	jmp    8089e3 <scramble+0x577>
  8089d9:	89 d1                	mov    %edx,%ecx
  8089db:	8b 0c 8c             	mov    (%rsp,%rcx,4),%ecx
  8089de:	01 c8                	add    %ecx,%eax
  8089e0:	83 c2 01             	add    $0x1,%edx
  8089e3:	83 fa 09             	cmp    $0x9,%edx
  8089e6:	76 f1                	jbe    8089d9 <scramble+0x56d>
  8089e8:	48 8b 74 24 28       	mov    0x28(%rsp),%rsi
  8089ed:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
  8089f4:	00 00 
  8089f6:	75 05                	jne    8089fd <scramble+0x591>
  8089f8:	48 83 c4 38          	add    $0x38,%rsp
  8089fc:	c3                   	ret
  8089fd:	e8 de 82 bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000808a02 <getbuf>:
  808a02:	48 83 ec 38          	sub    $0x38,%rsp
  808a06:	48 89 e7             	mov    %rsp,%rdi
  808a09:	e8 b3 03 00 00       	call   808dc1 <Gets>
  808a0e:	b8 01 00 00 00       	mov    $0x1,%eax
  808a13:	48 83 c4 38          	add    $0x38,%rsp
  808a17:	c3                   	ret

0000000000808a18 <touch1>:
  808a18:	48 83 ec 08          	sub    $0x8,%rsp
  808a1c:	c7 05 d6 3a 20 00 01 	movl   $0x1,0x203ad6(%rip)        # a0c4fc <vlevel>
  808a23:	00 00 00 
  808a26:	48 8d 3d 3e 1a 00 00 	lea    0x1a3e(%rip),%rdi        # 80a46b <_IO_stdin_used+0x27b>
  808a2d:	e8 8e 82 bf ff       	call   400cc0 <puts@plt>
  808a32:	bf 01 00 00 00       	mov    $0x1,%edi
  808a37:	e8 fc 05 00 00       	call   809038 <validate>
  808a3c:	bf 00 00 00 00       	mov    $0x0,%edi
  808a41:	e8 da 83 bf ff       	call   400e20 <exit@plt>

0000000000808a46 <touch2>:
  808a46:	48 83 ec 08          	sub    $0x8,%rsp
  808a4a:	89 fa                	mov    %edi,%edx
  808a4c:	c7 05 a6 3a 20 00 02 	movl   $0x2,0x203aa6(%rip)        # a0c4fc <vlevel>
  808a53:	00 00 00 
  808a56:	39 3d a8 3a 20 00    	cmp    %edi,0x203aa8(%rip)        # a0c504 <cookie>
  808a5c:	74 2a                	je     808a88 <touch2+0x42>
  808a5e:	48 8d 35 53 1a 00 00 	lea    0x1a53(%rip),%rsi        # 80a4b8 <_IO_stdin_used+0x2c8>
  808a65:	bf 01 00 00 00       	mov    $0x1,%edi
  808a6a:	b8 00 00 00 00       	mov    $0x0,%eax
  808a6f:	e8 6c 83 bf ff       	call   400de0 <__printf_chk@plt>
  808a74:	bf 02 00 00 00       	mov    $0x2,%edi
  808a79:	e8 8a 06 00 00       	call   809108 <fail>
  808a7e:	bf 00 00 00 00       	mov    $0x0,%edi
  808a83:	e8 98 83 bf ff       	call   400e20 <exit@plt>
  808a88:	48 8d 35 01 1a 00 00 	lea    0x1a01(%rip),%rsi        # 80a490 <_IO_stdin_used+0x2a0>
  808a8f:	bf 01 00 00 00       	mov    $0x1,%edi
  808a94:	b8 00 00 00 00       	mov    $0x0,%eax
  808a99:	e8 42 83 bf ff       	call   400de0 <__printf_chk@plt>
  808a9e:	bf 02 00 00 00       	mov    $0x2,%edi
  808aa3:	e8 90 05 00 00       	call   809038 <validate>
  808aa8:	eb d4                	jmp    808a7e <touch2+0x38>

0000000000808aaa <hexmatch>:
  808aaa:	41 54                	push   %r12
  808aac:	55                   	push   %rbp
  808aad:	53                   	push   %rbx
  808aae:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
  808ab2:	89 fd                	mov    %edi,%ebp
  808ab4:	48 89 f3             	mov    %rsi,%rbx
  808ab7:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  808abe:	00 00 
  808ac0:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
  808ac5:	31 c0                	xor    %eax,%eax
  808ac7:	e8 d4 82 bf ff       	call   400da0 <random@plt>
  808acc:	48 89 c1             	mov    %rax,%rcx
  808acf:	48 ba 0b d7 a3 70 3d 	movabs $0xa3d70a3d70a3d70b,%rdx
  808ad6:	0a d7 a3 
  808ad9:	48 f7 ea             	imul   %rdx
  808adc:	48 01 ca             	add    %rcx,%rdx
  808adf:	48 c1 fa 06          	sar    $0x6,%rdx
  808ae3:	48 89 c8             	mov    %rcx,%rax
  808ae6:	48 c1 f8 3f          	sar    $0x3f,%rax
  808aea:	48 29 c2             	sub    %rax,%rdx
  808aed:	48 8d 04 92          	lea    (%rdx,%rdx,4),%rax
  808af1:	48 8d 14 80          	lea    (%rax,%rax,4),%rdx
  808af5:	48 8d 04 95 00 00 00 	lea    0x0(,%rdx,4),%rax
  808afc:	00 
  808afd:	48 29 c1             	sub    %rax,%rcx
  808b00:	4c 8d 24 0c          	lea    (%rsp,%rcx,1),%r12
  808b04:	41 89 e8             	mov    %ebp,%r8d
  808b07:	48 8d 0d 7a 19 00 00 	lea    0x197a(%rip),%rcx        # 80a488 <_IO_stdin_used+0x298>
  808b0e:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
  808b15:	be 01 00 00 00       	mov    $0x1,%esi
  808b1a:	4c 89 e7             	mov    %r12,%rdi
  808b1d:	b8 00 00 00 00       	mov    $0x0,%eax
  808b22:	e8 29 83 bf ff       	call   400e50 <__sprintf_chk@plt>
  808b27:	ba 09 00 00 00       	mov    $0x9,%edx
  808b2c:	4c 89 e6             	mov    %r12,%rsi
  808b2f:	48 89 df             	mov    %rbx,%rdi
  808b32:	e8 69 81 bf ff       	call   400ca0 <strncmp@plt>
  808b37:	85 c0                	test   %eax,%eax
  808b39:	0f 94 c0             	sete   %al
  808b3c:	48 8b 5c 24 78       	mov    0x78(%rsp),%rbx
  808b41:	64 48 33 1c 25 28 00 	xor    %fs:0x28,%rbx
  808b48:	00 00 
  808b4a:	75 0c                	jne    808b58 <hexmatch+0xae>
  808b4c:	0f b6 c0             	movzbl %al,%eax
  808b4f:	48 83 ec 80          	sub    $0xffffffffffffff80,%rsp
  808b53:	5b                   	pop    %rbx
  808b54:	5d                   	pop    %rbp
  808b55:	41 5c                	pop    %r12
  808b57:	c3                   	ret
  808b58:	e8 83 81 bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000808b5d <touch3>:
  808b5d:	53                   	push   %rbx
  808b5e:	48 89 fb             	mov    %rdi,%rbx
  808b61:	c7 05 91 39 20 00 03 	movl   $0x3,0x203991(%rip)        # a0c4fc <vlevel>
  808b68:	00 00 00 
  808b6b:	48 89 fe             	mov    %rdi,%rsi
  808b6e:	8b 3d 90 39 20 00    	mov    0x203990(%rip),%edi        # a0c504 <cookie>
  808b74:	e8 31 ff ff ff       	call   808aaa <hexmatch>
  808b79:	85 c0                	test   %eax,%eax
  808b7b:	74 2d                	je     808baa <touch3+0x4d>
  808b7d:	48 89 da             	mov    %rbx,%rdx
  808b80:	48 8d 35 59 19 00 00 	lea    0x1959(%rip),%rsi        # 80a4e0 <_IO_stdin_used+0x2f0>
  808b87:	bf 01 00 00 00       	mov    $0x1,%edi
  808b8c:	b8 00 00 00 00       	mov    $0x0,%eax
  808b91:	e8 4a 82 bf ff       	call   400de0 <__printf_chk@plt>
  808b96:	bf 03 00 00 00       	mov    $0x3,%edi
  808b9b:	e8 98 04 00 00       	call   809038 <validate>
  808ba0:	bf 00 00 00 00       	mov    $0x0,%edi
  808ba5:	e8 76 82 bf ff       	call   400e20 <exit@plt>
  808baa:	48 89 da             	mov    %rbx,%rdx
  808bad:	48 8d 35 54 19 00 00 	lea    0x1954(%rip),%rsi        # 80a508 <_IO_stdin_used+0x318>
  808bb4:	bf 01 00 00 00       	mov    $0x1,%edi
  808bb9:	b8 00 00 00 00       	mov    $0x0,%eax
  808bbe:	e8 1d 82 bf ff       	call   400de0 <__printf_chk@plt>
  808bc3:	bf 03 00 00 00       	mov    $0x3,%edi
  808bc8:	e8 3b 05 00 00       	call   809108 <fail>
  808bcd:	eb d1                	jmp    808ba0 <touch3+0x43>

0000000000808bcf <test>:
  808bcf:	48 83 ec 08          	sub    $0x8,%rsp
  808bd3:	b8 00 00 00 00       	mov    $0x0,%eax
  808bd8:	e8 25 fe ff ff       	call   808a02 <getbuf>
  808bdd:	89 c2                	mov    %eax,%edx
  808bdf:	48 8d 35 4a 19 00 00 	lea    0x194a(%rip),%rsi        # 80a530 <_IO_stdin_used+0x340>
  808be6:	bf 01 00 00 00       	mov    $0x1,%edi
  808beb:	b8 00 00 00 00       	mov    $0x0,%eax
  808bf0:	e8 eb 81 bf ff       	call   400de0 <__printf_chk@plt>
  808bf5:	48 83 c4 08          	add    $0x8,%rsp
  808bf9:	c3                   	ret

0000000000808bfa <start_farm>:
  808bfa:	b8 01 00 00 00       	mov    $0x1,%eax
  808bff:	c3                   	ret

0000000000808c00 <getval_310>:
  808c00:	b8 48 c9 c7 c3       	mov    $0xc3c7c948,%eax
  808c05:	c3                   	ret

0000000000808c06 <getval_370>:
  808c06:	b8 48 89 c7 c3       	mov    $0xc3c78948,%eax
  808c0b:	c3                   	ret

0000000000808c0c <setval_212>:
  808c0c:	c7 07 2e 25 58 90    	movl   $0x9058252e,(%rdi)
  808c12:	c3                   	ret

0000000000808c13 <getval_340>:
  808c13:	b8 48 89 c7 c3       	mov    $0xc3c78948,%eax
  808c18:	c3                   	ret

0000000000808c19 <getval_356>:
  808c19:	b8 c8 89 c7 c3       	mov    $0xc3c789c8,%eax
  808c1e:	c3                   	ret

0000000000808c1f <addval_406>:
  808c1f:	8d 87 58 90 90 c3    	lea    -0x3c6f6fa8(%rdi),%eax
  808c25:	c3                   	ret

0000000000808c26 <setval_116>:
  808c26:	c7 07 48 90 90 c3    	movl   $0xc3909048,(%rdi)
  808c2c:	c3                   	ret

0000000000808c2d <setval_304>:
  808c2d:	c7 07 54 d8 90 90    	movl   $0x9090d854,(%rdi)
  808c33:	c3                   	ret

0000000000808c34 <mid_farm>:
  808c34:	b8 01 00 00 00       	mov    $0x1,%eax
  808c39:	c3                   	ret

0000000000808c3a <add_xy>:
  808c3a:	48 8d 04 37          	lea    (%rdi,%rsi,1),%rax
  808c3e:	c3                   	ret

0000000000808c3f <setval_457>:
  808c3f:	c7 07 48 89 e0 c3    	movl   $0xc3e08948,(%rdi)
  808c45:	c3                   	ret

0000000000808c46 <getval_305>:
  808c46:	b8 81 ca 90 c3       	mov    $0xc390ca81,%eax
  808c4b:	c3                   	ret

0000000000808c4c <setval_313>:
  808c4c:	c7 07 48 89 e0 92    	movl   $0x92e08948,(%rdi)
  808c52:	c3                   	ret

0000000000808c53 <getval_231>:
  808c53:	b8 89 d6 08 db       	mov    $0xdb08d689,%eax
  808c58:	c3                   	ret

0000000000808c59 <setval_337>:
  808c59:	c7 07 8d c1 84 c9    	movl   $0xc984c18d,(%rdi)
  808c5f:	c3                   	ret

0000000000808c60 <setval_322>:
  808c60:	c7 07 89 d6 c7 05    	movl   $0x5c7d689,(%rdi)
  808c66:	c3                   	ret

0000000000808c67 <setval_385>:
  808c67:	c7 07 48 89 e0 c1    	movl   $0xc1e08948,(%rdi)
  808c6d:	c3                   	ret

0000000000808c6e <getval_342>:
  808c6e:	b8 48 89 e0 c7       	mov    $0xc7e08948,%eax
  808c73:	c3                   	ret

0000000000808c74 <getval_157>:
  808c74:	b8 89 ca 94 c0       	mov    $0xc094ca89,%eax
  808c79:	c3                   	ret

0000000000808c7a <setval_191>:
  808c7a:	c7 07 89 c1 60 d2    	movl   $0xd260c189,(%rdi)
  808c80:	c3                   	ret

0000000000808c81 <addval_213>:
  808c81:	8d 87 48 89 e0 92    	lea    -0x6d1f76b8(%rdi),%eax
  808c87:	c3                   	ret

0000000000808c88 <addval_485>:
  808c88:	8d 87 48 89 e0 c2    	lea    -0x3d1f76b8(%rdi),%eax
  808c8e:	c3                   	ret

0000000000808c8f <setval_476>:
  808c8f:	c7 07 81 c1 20 c9    	movl   $0xc920c181,(%rdi)
  808c95:	c3                   	ret

0000000000808c96 <addval_371>:
  808c96:	8d 87 88 c1 08 db    	lea    -0x24f73e78(%rdi),%eax
  808c9c:	c3                   	ret

0000000000808c9d <setval_432>:
  808c9d:	c7 07 89 c1 94 d2    	movl   $0xd294c189,(%rdi)
  808ca3:	c3                   	ret

0000000000808ca4 <addval_334>:
  808ca4:	8d 87 25 2e 89 c1    	lea    -0x3e76d1db(%rdi),%eax
  808caa:	c3                   	ret

0000000000808cab <setval_388>:
  808cab:	c7 07 48 89 e0 90    	movl   $0x90e08948,(%rdi)
  808cb1:	c3                   	ret

0000000000808cb2 <getval_177>:
  808cb2:	b8 89 c1 84 d2       	mov    $0xd284c189,%eax
  808cb7:	c3                   	ret

0000000000808cb8 <addval_470>:
  808cb8:	8d 87 89 d6 20 c0    	lea    -0x3fdf2977(%rdi),%eax
  808cbe:	c3                   	ret

0000000000808cbf <addval_399>:
  808cbf:	8d 87 8d d6 38 d2    	lea    -0x2dc72973(%rdi),%eax
  808cc5:	c3                   	ret

0000000000808cc6 <getval_249>:
  808cc6:	b8 8d ca 20 d2       	mov    $0xd220ca8d,%eax
  808ccb:	c3                   	ret

0000000000808ccc <setval_151>:
  808ccc:	c7 07 89 ca 18 db    	movl   $0xdb18ca89,(%rdi)
  808cd2:	c3                   	ret

0000000000808cd3 <getval_179>:
  808cd3:	b8 b0 71 99 d6       	mov    $0xd69971b0,%eax
  808cd8:	c3                   	ret

0000000000808cd9 <getval_236>:
  808cd9:	b8 89 d6 48 d2       	mov    $0xd248d689,%eax
  808cde:	c3                   	ret

0000000000808cdf <getval_242>:
  808cdf:	b8 89 d6 92 90       	mov    $0x9092d689,%eax
  808ce4:	c3                   	ret

0000000000808ce5 <getval_421>:
  808ce5:	b8 c9 d6 08 d2       	mov    $0xd208d6c9,%eax
  808cea:	c3                   	ret

0000000000808ceb <setval_452>:
  808ceb:	c7 07 48 89 e0 91    	movl   $0x91e08948,(%rdi)
  808cf1:	c3                   	ret

0000000000808cf2 <setval_139>:
  808cf2:	c7 07 89 ca 20 c0    	movl   $0xc020ca89,(%rdi)
  808cf8:	c3                   	ret

0000000000808cf9 <getval_253>:
  808cf9:	b8 d0 89 ca 90       	mov    $0x90ca89d0,%eax
  808cfe:	c3                   	ret

0000000000808cff <setval_279>:
  808cff:	c7 07 09 c1 08 c9    	movl   $0xc908c109,(%rdi)
  808d05:	c3                   	ret

0000000000808d06 <getval_158>:
  808d06:	b8 89 ca 28 c9       	mov    $0xc928ca89,%eax
  808d0b:	c3                   	ret

0000000000808d0c <addval_403>:
  808d0c:	8d 87 89 ca c1 37    	lea    0x37c1ca89(%rdi),%eax
  808d12:	c3                   	ret

0000000000808d13 <end_farm>:
  808d13:	b8 01 00 00 00       	mov    $0x1,%eax
  808d18:	c3                   	ret

0000000000808d19 <save_char>:
  808d19:	8b 05 05 44 20 00    	mov    0x204405(%rip),%eax        # a0d124 <gets_cnt>
  808d1f:	3d ff 03 00 00       	cmp    $0x3ff,%eax
  808d24:	7f 4a                	jg     808d70 <save_char+0x57>
  808d26:	89 f9                	mov    %edi,%ecx
  808d28:	c0 e9 04             	shr    $0x4,%cl
  808d2b:	8d 14 40             	lea    (%rax,%rax,2),%edx
  808d2e:	4c 8d 05 1b 1b 00 00 	lea    0x1b1b(%rip),%r8        # 80a850 <trans_char>
  808d35:	83 e1 0f             	and    $0xf,%ecx
  808d38:	45 0f b6 0c 08       	movzbl (%r8,%rcx,1),%r9d
  808d3d:	48 8d 0d dc 37 20 00 	lea    0x2037dc(%rip),%rcx        # a0c520 <gets_buf>
  808d44:	48 63 f2             	movslq %edx,%rsi
  808d47:	44 88 0c 31          	mov    %r9b,(%rcx,%rsi,1)
  808d4b:	8d 72 01             	lea    0x1(%rdx),%esi
  808d4e:	83 e7 0f             	and    $0xf,%edi
  808d51:	41 0f b6 3c 38       	movzbl (%r8,%rdi,1),%edi
  808d56:	48 63 f6             	movslq %esi,%rsi
  808d59:	40 88 3c 31          	mov    %dil,(%rcx,%rsi,1)
  808d5d:	83 c2 02             	add    $0x2,%edx
  808d60:	48 63 d2             	movslq %edx,%rdx
  808d63:	c6 04 11 20          	movb   $0x20,(%rcx,%rdx,1)
  808d67:	83 c0 01             	add    $0x1,%eax
  808d6a:	89 05 b4 43 20 00    	mov    %eax,0x2043b4(%rip)        # a0d124 <gets_cnt>
  808d70:	f3 c3                	repz ret

0000000000808d72 <save_term>:
  808d72:	8b 05 ac 43 20 00    	mov    0x2043ac(%rip),%eax        # a0d124 <gets_cnt>
  808d78:	8d 04 40             	lea    (%rax,%rax,2),%eax
  808d7b:	48 98                	cltq
  808d7d:	48 8d 15 9c 37 20 00 	lea    0x20379c(%rip),%rdx        # a0c520 <gets_buf>
  808d84:	c6 04 02 00          	movb   $0x0,(%rdx,%rax,1)
  808d88:	c3                   	ret

0000000000808d89 <check_fail>:
  808d89:	48 83 ec 08          	sub    $0x8,%rsp
  808d8d:	0f be 15 9c 43 20 00 	movsbl 0x20439c(%rip),%edx        # a0d130 <target_prefix>
  808d94:	4c 8d 05 85 37 20 00 	lea    0x203785(%rip),%r8        # a0c520 <gets_buf>
  808d9b:	8b 0d 57 37 20 00    	mov    0x203757(%rip),%ecx        # a0c4f8 <check_level>
  808da1:	48 8d 35 ab 17 00 00 	lea    0x17ab(%rip),%rsi        # 80a553 <_IO_stdin_used+0x363>
  808da8:	bf 01 00 00 00       	mov    $0x1,%edi
  808dad:	b8 00 00 00 00       	mov    $0x0,%eax
  808db2:	e8 29 80 bf ff       	call   400de0 <__printf_chk@plt>
  808db7:	bf 01 00 00 00       	mov    $0x1,%edi
  808dbc:	e8 5f 80 bf ff       	call   400e20 <exit@plt>

0000000000808dc1 <Gets>:
  808dc1:	41 54                	push   %r12
  808dc3:	55                   	push   %rbp
  808dc4:	53                   	push   %rbx
  808dc5:	49 89 fc             	mov    %rdi,%r12
  808dc8:	c7 05 52 43 20 00 00 	movl   $0x0,0x204352(%rip)        # a0d124 <gets_cnt>
  808dcf:	00 00 00 
  808dd2:	48 89 fb             	mov    %rdi,%rbx
  808dd5:	eb 11                	jmp    808de8 <Gets+0x27>
  808dd7:	48 8d 6b 01          	lea    0x1(%rbx),%rbp
  808ddb:	88 03                	mov    %al,(%rbx)
  808ddd:	0f b6 f8             	movzbl %al,%edi
  808de0:	e8 34 ff ff ff       	call   808d19 <save_char>
  808de5:	48 89 eb             	mov    %rbp,%rbx
  808de8:	48 8b 3d 01 37 20 00 	mov    0x203701(%rip),%rdi        # a0c4f0 <infile>
  808def:	e8 bc 7f bf ff       	call   400db0 <_IO_getc@plt>
  808df4:	83 f8 ff             	cmp    $0xffffffff,%eax
  808df7:	74 05                	je     808dfe <Gets+0x3d>
  808df9:	83 f8 0a             	cmp    $0xa,%eax
  808dfc:	75 d9                	jne    808dd7 <Gets+0x16>
  808dfe:	c6 03 00             	movb   $0x0,(%rbx)
  808e01:	b8 00 00 00 00       	mov    $0x0,%eax
  808e06:	e8 67 ff ff ff       	call   808d72 <save_term>
  808e0b:	4c 89 e0             	mov    %r12,%rax
  808e0e:	5b                   	pop    %rbx
  808e0f:	5d                   	pop    %rbp
  808e10:	41 5c                	pop    %r12
  808e12:	c3                   	ret

0000000000808e13 <notify_server>:
  808e13:	55                   	push   %rbp
  808e14:	53                   	push   %rbx
  808e15:	48 81 ec 18 40 00 00 	sub    $0x4018,%rsp
  808e1c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  808e23:	00 00 
  808e25:	48 89 84 24 08 40 00 	mov    %rax,0x4008(%rsp)
  808e2c:	00 
  808e2d:	31 c0                	xor    %eax,%eax
  808e2f:	83 3d d2 36 20 00 00 	cmpl   $0x0,0x2036d2(%rip)        # a0c508 <is_checker>
  808e36:	0f 85 d9 00 00 00    	jne    808f15 <notify_server+0x102>
  808e3c:	89 fb                	mov    %edi,%ebx
  808e3e:	8b 05 e0 42 20 00    	mov    0x2042e0(%rip),%eax        # a0d124 <gets_cnt>
  808e44:	83 c0 64             	add    $0x64,%eax
  808e47:	3d 00 20 00 00       	cmp    $0x2000,%eax
  808e4c:	0f 8f e4 00 00 00    	jg     808f36 <notify_server+0x123>
  808e52:	0f be 05 d7 42 20 00 	movsbl 0x2042d7(%rip),%eax        # a0d130 <target_prefix>
  808e59:	83 3d 28 36 20 00 00 	cmpl   $0x0,0x203628(%rip)        # a0c488 <notify>
  808e60:	0f 84 f0 00 00 00    	je     808f56 <notify_server+0x143>
  808e66:	8b 15 94 36 20 00    	mov    0x203694(%rip),%edx        # a0c500 <authkey>
  808e6c:	85 db                	test   %ebx,%ebx
  808e6e:	0f 84 ec 00 00 00    	je     808f60 <notify_server+0x14d>
  808e74:	48 8d 2d ee 16 00 00 	lea    0x16ee(%rip),%rbp        # 80a569 <_IO_stdin_used+0x379>
  808e7b:	48 89 e7             	mov    %rsp,%rdi
  808e7e:	48 83 ec 08          	sub    $0x8,%rsp
  808e82:	48 8d 0d 97 36 20 00 	lea    0x203697(%rip),%rcx        # a0c520 <gets_buf>
  808e89:	51                   	push   %rcx
  808e8a:	56                   	push   %rsi
  808e8b:	50                   	push   %rax
  808e8c:	52                   	push   %rdx
  808e8d:	55                   	push   %rbp
  808e8e:	44 8b 0d 9b 32 20 00 	mov    0x20329b(%rip),%r9d        # a0c130 <target_id>
  808e95:	4c 8d 05 d7 16 00 00 	lea    0x16d7(%rip),%r8        # 80a573 <_IO_stdin_used+0x383>
  808e9c:	b9 00 20 00 00       	mov    $0x2000,%ecx
  808ea1:	ba 01 00 00 00       	mov    $0x1,%edx
  808ea6:	be 00 20 00 00       	mov    $0x2000,%esi
  808eab:	b8 00 00 00 00       	mov    $0x0,%eax
  808eb0:	e8 bb 7d bf ff       	call   400c70 <__snprintf_chk@plt>
  808eb5:	48 83 c4 30          	add    $0x30,%rsp
  808eb9:	83 3d c8 35 20 00 00 	cmpl   $0x0,0x2035c8(%rip)        # a0c488 <notify>
  808ec0:	0f 84 df 00 00 00    	je     808fa5 <notify_server+0x192>
  808ec6:	85 db                	test   %ebx,%ebx
  808ec8:	0f 84 c6 00 00 00    	je     808f94 <notify_server+0x181>
  808ece:	48 89 e1             	mov    %rsp,%rcx
  808ed1:	4c 8d 8c 24 00 20 00 	lea    0x2000(%rsp),%r9
  808ed8:	00 
  808ed9:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  808edf:	48 8b 15 62 32 20 00 	mov    0x203262(%rip),%rdx        # a0c148 <lab>
  808ee6:	48 8b 35 93 35 20 00 	mov    0x203593(%rip),%rsi        # a0c480 <course>
  808eed:	48 8b 3d 4c 32 20 00 	mov    0x20324c(%rip),%rdi        # a0c140 <user_id>
  808ef4:	e8 af 11 00 00       	call   80a0a8 <driver_post>
  808ef9:	85 c0                	test   %eax,%eax
  808efb:	78 6f                	js     808f6c <notify_server+0x159>
  808efd:	48 8d 3d b4 17 00 00 	lea    0x17b4(%rip),%rdi        # 80a6b8 <_IO_stdin_used+0x4c8>
  808f04:	e8 b7 7d bf ff       	call   400cc0 <puts@plt>
  808f09:	48 8d 3d 8b 16 00 00 	lea    0x168b(%rip),%rdi        # 80a59b <_IO_stdin_used+0x3ab>
  808f10:	e8 ab 7d bf ff       	call   400cc0 <puts@plt>
  808f15:	48 8b 84 24 08 40 00 	mov    0x4008(%rsp),%rax
  808f1c:	00 
  808f1d:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  808f24:	00 00 
  808f26:	0f 85 07 01 00 00    	jne    809033 <notify_server+0x220>
  808f2c:	48 81 c4 18 40 00 00 	add    $0x4018,%rsp
  808f33:	5b                   	pop    %rbx
  808f34:	5d                   	pop    %rbp
  808f35:	c3                   	ret
  808f36:	48 8d 35 4b 17 00 00 	lea    0x174b(%rip),%rsi        # 80a688 <_IO_stdin_used+0x498>
  808f3d:	bf 01 00 00 00       	mov    $0x1,%edi
  808f42:	b8 00 00 00 00       	mov    $0x0,%eax
  808f47:	e8 94 7e bf ff       	call   400de0 <__printf_chk@plt>
  808f4c:	bf 01 00 00 00       	mov    $0x1,%edi
  808f51:	e8 ca 7e bf ff       	call   400e20 <exit@plt>
  808f56:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  808f5b:	e9 0c ff ff ff       	jmp    808e6c <notify_server+0x59>
  808f60:	48 8d 2d 07 16 00 00 	lea    0x1607(%rip),%rbp        # 80a56e <_IO_stdin_used+0x37e>
  808f67:	e9 0f ff ff ff       	jmp    808e7b <notify_server+0x68>
  808f6c:	48 8d 94 24 00 20 00 	lea    0x2000(%rsp),%rdx
  808f73:	00 
  808f74:	48 8d 35 14 16 00 00 	lea    0x1614(%rip),%rsi        # 80a58f <_IO_stdin_used+0x39f>
  808f7b:	bf 01 00 00 00       	mov    $0x1,%edi
  808f80:	b8 00 00 00 00       	mov    $0x0,%eax
  808f85:	e8 56 7e bf ff       	call   400de0 <__printf_chk@plt>
  808f8a:	bf 01 00 00 00       	mov    $0x1,%edi
  808f8f:	e8 8c 7e bf ff       	call   400e20 <exit@plt>
  808f94:	48 8d 3d 0a 16 00 00 	lea    0x160a(%rip),%rdi        # 80a5a5 <_IO_stdin_used+0x3b5>
  808f9b:	e8 20 7d bf ff       	call   400cc0 <puts@plt>
  808fa0:	e9 70 ff ff ff       	jmp    808f15 <notify_server+0x102>
  808fa5:	48 89 ea             	mov    %rbp,%rdx
  808fa8:	48 8d 35 41 17 00 00 	lea    0x1741(%rip),%rsi        # 80a6f0 <_IO_stdin_used+0x500>
  808faf:	bf 01 00 00 00       	mov    $0x1,%edi
  808fb4:	b8 00 00 00 00       	mov    $0x0,%eax
  808fb9:	e8 22 7e bf ff       	call   400de0 <__printf_chk@plt>
  808fbe:	48 8b 15 7b 31 20 00 	mov    0x20317b(%rip),%rdx        # a0c140 <user_id>
  808fc5:	48 8d 35 e0 15 00 00 	lea    0x15e0(%rip),%rsi        # 80a5ac <_IO_stdin_used+0x3bc>
  808fcc:	bf 01 00 00 00       	mov    $0x1,%edi
  808fd1:	b8 00 00 00 00       	mov    $0x0,%eax
  808fd6:	e8 05 7e bf ff       	call   400de0 <__printf_chk@plt>
  808fdb:	48 8b 15 9e 34 20 00 	mov    0x20349e(%rip),%rdx        # a0c480 <course>
  808fe2:	48 8d 35 d0 15 00 00 	lea    0x15d0(%rip),%rsi        # 80a5b9 <_IO_stdin_used+0x3c9>
  808fe9:	bf 01 00 00 00       	mov    $0x1,%edi
  808fee:	b8 00 00 00 00       	mov    $0x0,%eax
  808ff3:	e8 e8 7d bf ff       	call   400de0 <__printf_chk@plt>
  808ff8:	48 8b 15 49 31 20 00 	mov    0x203149(%rip),%rdx        # a0c148 <lab>
  808fff:	48 8d 35 bf 15 00 00 	lea    0x15bf(%rip),%rsi        # 80a5c5 <_IO_stdin_used+0x3d5>
  809006:	bf 01 00 00 00       	mov    $0x1,%edi
  80900b:	b8 00 00 00 00       	mov    $0x0,%eax
  809010:	e8 cb 7d bf ff       	call   400de0 <__printf_chk@plt>
  809015:	48 89 e2             	mov    %rsp,%rdx
  809018:	48 8d 35 af 15 00 00 	lea    0x15af(%rip),%rsi        # 80a5ce <_IO_stdin_used+0x3de>
  80901f:	bf 01 00 00 00       	mov    $0x1,%edi
  809024:	b8 00 00 00 00       	mov    $0x0,%eax
  809029:	e8 b2 7d bf ff       	call   400de0 <__printf_chk@plt>
  80902e:	e9 e2 fe ff ff       	jmp    808f15 <notify_server+0x102>
  809033:	e8 a8 7c bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809038 <validate>:
  809038:	53                   	push   %rbx
  809039:	89 fb                	mov    %edi,%ebx
  80903b:	83 3d c6 34 20 00 00 	cmpl   $0x0,0x2034c6(%rip)        # a0c508 <is_checker>
  809042:	74 72                	je     8090b6 <validate+0x7e>
  809044:	39 3d b2 34 20 00    	cmp    %edi,0x2034b2(%rip)        # a0c4fc <vlevel>
  80904a:	75 32                	jne    80907e <validate+0x46>
  80904c:	8b 15 a6 34 20 00    	mov    0x2034a6(%rip),%edx        # a0c4f8 <check_level>
  809052:	39 fa                	cmp    %edi,%edx
  809054:	75 3e                	jne    809094 <validate+0x5c>
  809056:	0f be 15 d3 40 20 00 	movsbl 0x2040d3(%rip),%edx        # a0d130 <target_prefix>
  80905d:	4c 8d 05 bc 34 20 00 	lea    0x2034bc(%rip),%r8        # a0c520 <gets_buf>
  809064:	89 f9                	mov    %edi,%ecx
  809066:	48 8d 35 8b 15 00 00 	lea    0x158b(%rip),%rsi        # 80a5f8 <_IO_stdin_used+0x408>
  80906d:	bf 01 00 00 00       	mov    $0x1,%edi
  809072:	b8 00 00 00 00       	mov    $0x0,%eax
  809077:	e8 64 7d bf ff       	call   400de0 <__printf_chk@plt>
  80907c:	5b                   	pop    %rbx
  80907d:	c3                   	ret
  80907e:	48 8d 3d 55 15 00 00 	lea    0x1555(%rip),%rdi        # 80a5da <_IO_stdin_used+0x3ea>
  809085:	e8 36 7c bf ff       	call   400cc0 <puts@plt>
  80908a:	b8 00 00 00 00       	mov    $0x0,%eax
  80908f:	e8 f5 fc ff ff       	call   808d89 <check_fail>
  809094:	89 f9                	mov    %edi,%ecx
  809096:	48 8d 35 7b 16 00 00 	lea    0x167b(%rip),%rsi        # 80a718 <_IO_stdin_used+0x528>
  80909d:	bf 01 00 00 00       	mov    $0x1,%edi
  8090a2:	b8 00 00 00 00       	mov    $0x0,%eax
  8090a7:	e8 34 7d bf ff       	call   400de0 <__printf_chk@plt>
  8090ac:	b8 00 00 00 00       	mov    $0x0,%eax
  8090b1:	e8 d3 fc ff ff       	call   808d89 <check_fail>
  8090b6:	39 3d 40 34 20 00    	cmp    %edi,0x203440(%rip)        # a0c4fc <vlevel>
  8090bc:	74 1a                	je     8090d8 <validate+0xa0>
  8090be:	48 8d 3d 15 15 00 00 	lea    0x1515(%rip),%rdi        # 80a5da <_IO_stdin_used+0x3ea>
  8090c5:	e8 f6 7b bf ff       	call   400cc0 <puts@plt>
  8090ca:	89 de                	mov    %ebx,%esi
  8090cc:	bf 00 00 00 00       	mov    $0x0,%edi
  8090d1:	e8 3d fd ff ff       	call   808e13 <notify_server>
  8090d6:	eb a4                	jmp    80907c <validate+0x44>
  8090d8:	0f be 0d 51 40 20 00 	movsbl 0x204051(%rip),%ecx        # a0d130 <target_prefix>
  8090df:	89 fa                	mov    %edi,%edx
  8090e1:	48 8d 35 58 16 00 00 	lea    0x1658(%rip),%rsi        # 80a740 <_IO_stdin_used+0x550>
  8090e8:	bf 01 00 00 00       	mov    $0x1,%edi
  8090ed:	b8 00 00 00 00       	mov    $0x0,%eax
  8090f2:	e8 e9 7c bf ff       	call   400de0 <__printf_chk@plt>
  8090f7:	89 de                	mov    %ebx,%esi
  8090f9:	bf 01 00 00 00       	mov    $0x1,%edi
  8090fe:	e8 10 fd ff ff       	call   808e13 <notify_server>
  809103:	e9 74 ff ff ff       	jmp    80907c <validate+0x44>

0000000000809108 <fail>:
  809108:	48 83 ec 08          	sub    $0x8,%rsp
  80910c:	83 3d f5 33 20 00 00 	cmpl   $0x0,0x2033f5(%rip)        # a0c508 <is_checker>
  809113:	75 11                	jne    809126 <fail+0x1e>
  809115:	89 fe                	mov    %edi,%esi
  809117:	bf 00 00 00 00       	mov    $0x0,%edi
  80911c:	e8 f2 fc ff ff       	call   808e13 <notify_server>
  809121:	48 83 c4 08          	add    $0x8,%rsp
  809125:	c3                   	ret
  809126:	b8 00 00 00 00       	mov    $0x0,%eax
  80912b:	e8 59 fc ff ff       	call   808d89 <check_fail>

0000000000809130 <bushandler>:
  809130:	48 83 ec 08          	sub    $0x8,%rsp
  809134:	83 3d cd 33 20 00 00 	cmpl   $0x0,0x2033cd(%rip)        # a0c508 <is_checker>
  80913b:	74 16                	je     809153 <bushandler+0x23>
  80913d:	48 8d 3d c9 14 00 00 	lea    0x14c9(%rip),%rdi        # 80a60d <_IO_stdin_used+0x41d>
  809144:	e8 77 7b bf ff       	call   400cc0 <puts@plt>
  809149:	b8 00 00 00 00       	mov    $0x0,%eax
  80914e:	e8 36 fc ff ff       	call   808d89 <check_fail>
  809153:	48 8d 3d 1e 16 00 00 	lea    0x161e(%rip),%rdi        # 80a778 <_IO_stdin_used+0x588>
  80915a:	e8 61 7b bf ff       	call   400cc0 <puts@plt>
  80915f:	48 8d 3d b1 14 00 00 	lea    0x14b1(%rip),%rdi        # 80a617 <_IO_stdin_used+0x427>
  809166:	e8 55 7b bf ff       	call   400cc0 <puts@plt>
  80916b:	be 00 00 00 00       	mov    $0x0,%esi
  809170:	bf 00 00 00 00       	mov    $0x0,%edi
  809175:	e8 99 fc ff ff       	call   808e13 <notify_server>
  80917a:	bf 01 00 00 00       	mov    $0x1,%edi
  80917f:	e8 9c 7c bf ff       	call   400e20 <exit@plt>

0000000000809184 <seghandler>:
  809184:	48 83 ec 08          	sub    $0x8,%rsp
  809188:	83 3d 79 33 20 00 00 	cmpl   $0x0,0x203379(%rip)        # a0c508 <is_checker>
  80918f:	74 16                	je     8091a7 <seghandler+0x23>
  809191:	48 8d 3d 95 14 00 00 	lea    0x1495(%rip),%rdi        # 80a62d <_IO_stdin_used+0x43d>
  809198:	e8 23 7b bf ff       	call   400cc0 <puts@plt>
  80919d:	b8 00 00 00 00       	mov    $0x0,%eax
  8091a2:	e8 e2 fb ff ff       	call   808d89 <check_fail>
  8091a7:	48 8d 3d ea 15 00 00 	lea    0x15ea(%rip),%rdi        # 80a798 <_IO_stdin_used+0x5a8>
  8091ae:	e8 0d 7b bf ff       	call   400cc0 <puts@plt>
  8091b3:	48 8d 3d 5d 14 00 00 	lea    0x145d(%rip),%rdi        # 80a617 <_IO_stdin_used+0x427>
  8091ba:	e8 01 7b bf ff       	call   400cc0 <puts@plt>
  8091bf:	be 00 00 00 00       	mov    $0x0,%esi
  8091c4:	bf 00 00 00 00       	mov    $0x0,%edi
  8091c9:	e8 45 fc ff ff       	call   808e13 <notify_server>
  8091ce:	bf 01 00 00 00       	mov    $0x1,%edi
  8091d3:	e8 48 7c bf ff       	call   400e20 <exit@plt>

00000000008091d8 <illegalhandler>:
  8091d8:	48 83 ec 08          	sub    $0x8,%rsp
  8091dc:	83 3d 25 33 20 00 00 	cmpl   $0x0,0x203325(%rip)        # a0c508 <is_checker>
  8091e3:	74 16                	je     8091fb <illegalhandler+0x23>
  8091e5:	48 8d 3d 54 14 00 00 	lea    0x1454(%rip),%rdi        # 80a640 <_IO_stdin_used+0x450>
  8091ec:	e8 cf 7a bf ff       	call   400cc0 <puts@plt>
  8091f1:	b8 00 00 00 00       	mov    $0x0,%eax
  8091f6:	e8 8e fb ff ff       	call   808d89 <check_fail>
  8091fb:	48 8d 3d be 15 00 00 	lea    0x15be(%rip),%rdi        # 80a7c0 <_IO_stdin_used+0x5d0>
  809202:	e8 b9 7a bf ff       	call   400cc0 <puts@plt>
  809207:	48 8d 3d 09 14 00 00 	lea    0x1409(%rip),%rdi        # 80a617 <_IO_stdin_used+0x427>
  80920e:	e8 ad 7a bf ff       	call   400cc0 <puts@plt>
  809213:	be 00 00 00 00       	mov    $0x0,%esi
  809218:	bf 00 00 00 00       	mov    $0x0,%edi
  80921d:	e8 f1 fb ff ff       	call   808e13 <notify_server>
  809222:	bf 01 00 00 00       	mov    $0x1,%edi
  809227:	e8 f4 7b bf ff       	call   400e20 <exit@plt>

000000000080922c <sigalrmhandler>:
  80922c:	48 83 ec 08          	sub    $0x8,%rsp
  809230:	83 3d d1 32 20 00 00 	cmpl   $0x0,0x2032d1(%rip)        # a0c508 <is_checker>
  809237:	74 16                	je     80924f <sigalrmhandler+0x23>
  809239:	48 8d 3d 14 14 00 00 	lea    0x1414(%rip),%rdi        # 80a654 <_IO_stdin_used+0x464>
  809240:	e8 7b 7a bf ff       	call   400cc0 <puts@plt>
  809245:	b8 00 00 00 00       	mov    $0x0,%eax
  80924a:	e8 3a fb ff ff       	call   808d89 <check_fail>
  80924f:	ba 05 00 00 00       	mov    $0x5,%edx
  809254:	48 8d 35 95 15 00 00 	lea    0x1595(%rip),%rsi        # 80a7f0 <_IO_stdin_used+0x600>
  80925b:	bf 01 00 00 00       	mov    $0x1,%edi
  809260:	b8 00 00 00 00       	mov    $0x0,%eax
  809265:	e8 76 7b bf ff       	call   400de0 <__printf_chk@plt>
  80926a:	be 00 00 00 00       	mov    $0x0,%esi
  80926f:	bf 00 00 00 00       	mov    $0x0,%edi
  809274:	e8 9a fb ff ff       	call   808e13 <notify_server>
  809279:	bf 01 00 00 00       	mov    $0x1,%edi
  80927e:	e8 9d 7b bf ff       	call   400e20 <exit@plt>

0000000000809283 <launch>:
  809283:	55                   	push   %rbp
  809284:	48 89 e5             	mov    %rsp,%rbp
  809287:	48 83 ec 10          	sub    $0x10,%rsp
  80928b:	48 89 fa             	mov    %rdi,%rdx
  80928e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809295:	00 00 
  809297:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  80929b:	31 c0                	xor    %eax,%eax
  80929d:	48 8d 47 1e          	lea    0x1e(%rdi),%rax
  8092a1:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
  8092a5:	48 29 c4             	sub    %rax,%rsp
  8092a8:	48 8d 7c 24 0f       	lea    0xf(%rsp),%rdi
  8092ad:	48 83 e7 f0          	and    $0xfffffffffffffff0,%rdi
  8092b1:	be f4 00 00 00       	mov    $0xf4,%esi
  8092b6:	e8 45 7a bf ff       	call   400d00 <memset@plt>
  8092bb:	48 8b 05 de 31 20 00 	mov    0x2031de(%rip),%rax        # a0c4a0 <stdin@GLIBC_2.2.5>
  8092c2:	48 39 05 27 32 20 00 	cmp    %rax,0x203227(%rip)        # a0c4f0 <infile>
  8092c9:	74 3a                	je     809305 <launch+0x82>
  8092cb:	c7 05 27 32 20 00 00 	movl   $0x0,0x203227(%rip)        # a0c4fc <vlevel>
  8092d2:	00 00 00 
  8092d5:	b8 00 00 00 00       	mov    $0x0,%eax
  8092da:	e8 f0 f8 ff ff       	call   808bcf <test>
  8092df:	83 3d 22 32 20 00 00 	cmpl   $0x0,0x203222(%rip)        # a0c508 <is_checker>
  8092e6:	75 35                	jne    80931d <launch+0x9a>
  8092e8:	48 8d 3d 85 13 00 00 	lea    0x1385(%rip),%rdi        # 80a674 <_IO_stdin_used+0x484>
  8092ef:	e8 cc 79 bf ff       	call   400cc0 <puts@plt>
  8092f4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  8092f8:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  8092ff:	00 00 
  809301:	75 30                	jne    809333 <launch+0xb0>
  809303:	c9                   	leave
  809304:	c3                   	ret
  809305:	48 8d 35 50 13 00 00 	lea    0x1350(%rip),%rsi        # 80a65c <_IO_stdin_used+0x46c>
  80930c:	bf 01 00 00 00       	mov    $0x1,%edi
  809311:	b8 00 00 00 00       	mov    $0x0,%eax
  809316:	e8 c5 7a bf ff       	call   400de0 <__printf_chk@plt>
  80931b:	eb ae                	jmp    8092cb <launch+0x48>
  80931d:	48 8d 3d 45 13 00 00 	lea    0x1345(%rip),%rdi        # 80a669 <_IO_stdin_used+0x479>
  809324:	e8 97 79 bf ff       	call   400cc0 <puts@plt>
  809329:	b8 00 00 00 00       	mov    $0x0,%eax
  80932e:	e8 56 fa ff ff       	call   808d89 <check_fail>
  809333:	e8 a8 79 bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809338 <stable_launch>:
  809338:	53                   	push   %rbx
  809339:	48 89 3d a8 31 20 00 	mov    %rdi,0x2031a8(%rip)        # a0c4e8 <global_offset>
  809340:	41 b9 00 00 00 00    	mov    $0x0,%r9d
  809346:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  80934c:	b9 32 01 00 00       	mov    $0x132,%ecx
  809351:	ba 07 00 00 00       	mov    $0x7,%edx
  809356:	be 00 00 10 00       	mov    $0x100000,%esi
  80935b:	bf 00 60 58 55       	mov    $0x55586000,%edi
  809360:	e8 8b 79 bf ff       	call   400cf0 <mmap@plt>
  809365:	48 89 c3             	mov    %rax,%rbx
  809368:	48 3d 00 60 58 55    	cmp    $0x55586000,%rax
  80936e:	75 43                	jne    8093b3 <stable_launch+0x7b>
  809370:	48 8d 90 f8 ff 0f 00 	lea    0xffff8(%rax),%rdx
  809377:	48 89 15 aa 3d 20 00 	mov    %rdx,0x203daa(%rip)        # a0d128 <stack_top>
  80937e:	48 89 e0             	mov    %rsp,%rax
  809381:	48 89 d4             	mov    %rdx,%rsp
  809384:	48 89 c2             	mov    %rax,%rdx
  809387:	48 89 15 52 31 20 00 	mov    %rdx,0x203152(%rip)        # a0c4e0 <global_save_stack>
  80938e:	48 8b 3d 53 31 20 00 	mov    0x203153(%rip),%rdi        # a0c4e8 <global_offset>
  809395:	e8 e9 fe ff ff       	call   809283 <launch>
  80939a:	48 8b 05 3f 31 20 00 	mov    0x20313f(%rip),%rax        # a0c4e0 <global_save_stack>
  8093a1:	48 89 c4             	mov    %rax,%rsp
  8093a4:	be 00 00 10 00       	mov    $0x100000,%esi
  8093a9:	48 89 df             	mov    %rbx,%rdi
  8093ac:	e8 1f 7a bf ff       	call   400dd0 <munmap@plt>
  8093b1:	5b                   	pop    %rbx
  8093b2:	c3                   	ret
  8093b3:	be 00 00 10 00       	mov    $0x100000,%esi
  8093b8:	48 89 c7             	mov    %rax,%rdi
  8093bb:	e8 10 7a bf ff       	call   400dd0 <munmap@plt>
  8093c0:	b9 00 60 58 55       	mov    $0x55586000,%ecx
  8093c5:	48 8d 15 5c 14 00 00 	lea    0x145c(%rip),%rdx        # 80a828 <_IO_stdin_used+0x638>
  8093cc:	be 01 00 00 00       	mov    $0x1,%esi
  8093d1:	48 8b 3d e8 30 20 00 	mov    0x2030e8(%rip),%rdi        # a0c4c0 <stderr@GLIBC_2.2.5>
  8093d8:	b8 00 00 00 00       	mov    $0x0,%eax
  8093dd:	e8 5e 7a bf ff       	call   400e40 <__fprintf_chk@plt>
  8093e2:	bf 01 00 00 00       	mov    $0x1,%edi
  8093e7:	e8 34 7a bf ff       	call   400e20 <exit@plt>

00000000008093ec <rio_readinitb>:
  8093ec:	89 37                	mov    %esi,(%rdi)
  8093ee:	c7 47 04 00 00 00 00 	movl   $0x0,0x4(%rdi)
  8093f5:	48 8d 47 10          	lea    0x10(%rdi),%rax
  8093f9:	48 89 47 08          	mov    %rax,0x8(%rdi)
  8093fd:	c3                   	ret

00000000008093fe <sigalrm_handler>:
  8093fe:	48 83 ec 08          	sub    $0x8,%rsp
  809402:	b9 00 00 00 00       	mov    $0x0,%ecx
  809407:	48 8d 15 52 14 00 00 	lea    0x1452(%rip),%rdx        # 80a860 <trans_char+0x10>
  80940e:	be 01 00 00 00       	mov    $0x1,%esi
  809413:	48 8b 3d a6 30 20 00 	mov    0x2030a6(%rip),%rdi        # a0c4c0 <stderr@GLIBC_2.2.5>
  80941a:	b8 00 00 00 00       	mov    $0x0,%eax
  80941f:	e8 1c 7a bf ff       	call   400e40 <__fprintf_chk@plt>
  809424:	bf 01 00 00 00       	mov    $0x1,%edi
  809429:	e8 f2 79 bf ff       	call   400e20 <exit@plt>

000000000080942e <rio_writen>:
  80942e:	41 55                	push   %r13
  809430:	41 54                	push   %r12
  809432:	55                   	push   %rbp
  809433:	53                   	push   %rbx
  809434:	48 83 ec 08          	sub    $0x8,%rsp
  809438:	41 89 fc             	mov    %edi,%r12d
  80943b:	48 89 f5             	mov    %rsi,%rbp
  80943e:	49 89 d5             	mov    %rdx,%r13
  809441:	48 89 d3             	mov    %rdx,%rbx
  809444:	eb 06                	jmp    80944c <rio_writen+0x1e>
  809446:	48 29 c3             	sub    %rax,%rbx
  809449:	48 01 c5             	add    %rax,%rbp
  80944c:	48 85 db             	test   %rbx,%rbx
  80944f:	74 24                	je     809475 <rio_writen+0x47>
  809451:	48 89 da             	mov    %rbx,%rdx
  809454:	48 89 ee             	mov    %rbp,%rsi
  809457:	44 89 e7             	mov    %r12d,%edi
  80945a:	e8 71 78 bf ff       	call   400cd0 <write@plt>
  80945f:	48 85 c0             	test   %rax,%rax
  809462:	7f e2                	jg     809446 <rio_writen+0x18>
  809464:	e8 17 78 bf ff       	call   400c80 <__errno_location@plt>
  809469:	83 38 04             	cmpl   $0x4,(%rax)
  80946c:	75 15                	jne    809483 <rio_writen+0x55>
  80946e:	b8 00 00 00 00       	mov    $0x0,%eax
  809473:	eb d1                	jmp    809446 <rio_writen+0x18>
  809475:	4c 89 e8             	mov    %r13,%rax
  809478:	48 83 c4 08          	add    $0x8,%rsp
  80947c:	5b                   	pop    %rbx
  80947d:	5d                   	pop    %rbp
  80947e:	41 5c                	pop    %r12
  809480:	41 5d                	pop    %r13
  809482:	c3                   	ret
  809483:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  80948a:	eb ec                	jmp    809478 <rio_writen+0x4a>

000000000080948c <rio_read>:
  80948c:	41 55                	push   %r13
  80948e:	41 54                	push   %r12
  809490:	55                   	push   %rbp
  809491:	53                   	push   %rbx
  809492:	48 83 ec 08          	sub    $0x8,%rsp
  809496:	48 89 fb             	mov    %rdi,%rbx
  809499:	49 89 f5             	mov    %rsi,%r13
  80949c:	49 89 d4             	mov    %rdx,%r12
  80949f:	eb 0a                	jmp    8094ab <rio_read+0x1f>
  8094a1:	e8 da 77 bf ff       	call   400c80 <__errno_location@plt>
  8094a6:	83 38 04             	cmpl   $0x4,(%rax)
  8094a9:	75 5c                	jne    809507 <rio_read+0x7b>
  8094ab:	8b 6b 04             	mov    0x4(%rbx),%ebp
  8094ae:	85 ed                	test   %ebp,%ebp
  8094b0:	7f 24                	jg     8094d6 <rio_read+0x4a>
  8094b2:	48 8d 6b 10          	lea    0x10(%rbx),%rbp
  8094b6:	8b 3b                	mov    (%rbx),%edi
  8094b8:	ba 00 20 00 00       	mov    $0x2000,%edx
  8094bd:	48 89 ee             	mov    %rbp,%rsi
  8094c0:	e8 6b 78 bf ff       	call   400d30 <read@plt>
  8094c5:	89 43 04             	mov    %eax,0x4(%rbx)
  8094c8:	85 c0                	test   %eax,%eax
  8094ca:	78 d5                	js     8094a1 <rio_read+0x15>
  8094cc:	85 c0                	test   %eax,%eax
  8094ce:	74 40                	je     809510 <rio_read+0x84>
  8094d0:	48 89 6b 08          	mov    %rbp,0x8(%rbx)
  8094d4:	eb d5                	jmp    8094ab <rio_read+0x1f>
  8094d6:	89 e8                	mov    %ebp,%eax
  8094d8:	4c 39 e0             	cmp    %r12,%rax
  8094db:	72 03                	jb     8094e0 <rio_read+0x54>
  8094dd:	44 89 e5             	mov    %r12d,%ebp
  8094e0:	4c 63 e5             	movslq %ebp,%r12
  8094e3:	48 8b 73 08          	mov    0x8(%rbx),%rsi
  8094e7:	4c 89 e2             	mov    %r12,%rdx
  8094ea:	4c 89 ef             	mov    %r13,%rdi
  8094ed:	e8 8e 78 bf ff       	call   400d80 <memcpy@plt>
  8094f2:	4c 01 63 08          	add    %r12,0x8(%rbx)
  8094f6:	29 6b 04             	sub    %ebp,0x4(%rbx)
  8094f9:	4c 89 e0             	mov    %r12,%rax
  8094fc:	48 83 c4 08          	add    $0x8,%rsp
  809500:	5b                   	pop    %rbx
  809501:	5d                   	pop    %rbp
  809502:	41 5c                	pop    %r12
  809504:	41 5d                	pop    %r13
  809506:	c3                   	ret
  809507:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  80950e:	eb ec                	jmp    8094fc <rio_read+0x70>
  809510:	b8 00 00 00 00       	mov    $0x0,%eax
  809515:	eb e5                	jmp    8094fc <rio_read+0x70>

0000000000809517 <rio_readlineb>:
  809517:	41 55                	push   %r13
  809519:	41 54                	push   %r12
  80951b:	55                   	push   %rbp
  80951c:	53                   	push   %rbx
  80951d:	48 83 ec 18          	sub    $0x18,%rsp
  809521:	49 89 fd             	mov    %rdi,%r13
  809524:	48 89 f5             	mov    %rsi,%rbp
  809527:	49 89 d4             	mov    %rdx,%r12
  80952a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809531:	00 00 
  809533:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  809538:	31 c0                	xor    %eax,%eax
  80953a:	bb 01 00 00 00       	mov    $0x1,%ebx
  80953f:	4c 39 e3             	cmp    %r12,%rbx
  809542:	73 47                	jae    80958b <rio_readlineb+0x74>
  809544:	48 8d 74 24 07       	lea    0x7(%rsp),%rsi
  809549:	ba 01 00 00 00       	mov    $0x1,%edx
  80954e:	4c 89 ef             	mov    %r13,%rdi
  809551:	e8 36 ff ff ff       	call   80948c <rio_read>
  809556:	83 f8 01             	cmp    $0x1,%eax
  809559:	75 1c                	jne    809577 <rio_readlineb+0x60>
  80955b:	48 8d 45 01          	lea    0x1(%rbp),%rax
  80955f:	0f b6 54 24 07       	movzbl 0x7(%rsp),%edx
  809564:	88 55 00             	mov    %dl,0x0(%rbp)
  809567:	80 7c 24 07 0a       	cmpb   $0xa,0x7(%rsp)
  80956c:	74 1a                	je     809588 <rio_readlineb+0x71>
  80956e:	48 83 c3 01          	add    $0x1,%rbx
  809572:	48 89 c5             	mov    %rax,%rbp
  809575:	eb c8                	jmp    80953f <rio_readlineb+0x28>
  809577:	85 c0                	test   %eax,%eax
  809579:	75 32                	jne    8095ad <rio_readlineb+0x96>
  80957b:	48 83 fb 01          	cmp    $0x1,%rbx
  80957f:	75 0a                	jne    80958b <rio_readlineb+0x74>
  809581:	b8 00 00 00 00       	mov    $0x0,%eax
  809586:	eb 0a                	jmp    809592 <rio_readlineb+0x7b>
  809588:	48 89 c5             	mov    %rax,%rbp
  80958b:	c6 45 00 00          	movb   $0x0,0x0(%rbp)
  80958f:	48 89 d8             	mov    %rbx,%rax
  809592:	48 8b 4c 24 08       	mov    0x8(%rsp),%rcx
  809597:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  80959e:	00 00 
  8095a0:	75 14                	jne    8095b6 <rio_readlineb+0x9f>
  8095a2:	48 83 c4 18          	add    $0x18,%rsp
  8095a6:	5b                   	pop    %rbx
  8095a7:	5d                   	pop    %rbp
  8095a8:	41 5c                	pop    %r12
  8095aa:	41 5d                	pop    %r13
  8095ac:	c3                   	ret
  8095ad:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  8095b4:	eb dc                	jmp    809592 <rio_readlineb+0x7b>
  8095b6:	e8 25 77 bf ff       	call   400ce0 <__stack_chk_fail@plt>

00000000008095bb <urlencode>:
  8095bb:	41 54                	push   %r12
  8095bd:	55                   	push   %rbp
  8095be:	53                   	push   %rbx
  8095bf:	48 83 ec 10          	sub    $0x10,%rsp
  8095c3:	48 89 fb             	mov    %rdi,%rbx
  8095c6:	48 89 f5             	mov    %rsi,%rbp
  8095c9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  8095d0:	00 00 
  8095d2:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  8095d7:	31 c0                	xor    %eax,%eax
  8095d9:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  8095e0:	f2 ae                	repnz scas %es:(%rdi),%al
  8095e2:	48 89 ce             	mov    %rcx,%rsi
  8095e5:	48 f7 d6             	not    %rsi
  8095e8:	8d 46 ff             	lea    -0x1(%rsi),%eax
  8095eb:	eb 0f                	jmp    8095fc <urlencode+0x41>
  8095ed:	44 88 45 00          	mov    %r8b,0x0(%rbp)
  8095f1:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
  8095f5:	48 83 c3 01          	add    $0x1,%rbx
  8095f9:	44 89 e0             	mov    %r12d,%eax
  8095fc:	44 8d 60 ff          	lea    -0x1(%rax),%r12d
  809600:	85 c0                	test   %eax,%eax
  809602:	0f 84 a8 00 00 00    	je     8096b0 <urlencode+0xf5>
  809608:	44 0f b6 03          	movzbl (%rbx),%r8d
  80960c:	41 80 f8 2a          	cmp    $0x2a,%r8b
  809610:	0f 94 c2             	sete   %dl
  809613:	41 80 f8 2d          	cmp    $0x2d,%r8b
  809617:	0f 94 c0             	sete   %al
  80961a:	08 c2                	or     %al,%dl
  80961c:	75 cf                	jne    8095ed <urlencode+0x32>
  80961e:	41 80 f8 2e          	cmp    $0x2e,%r8b
  809622:	74 c9                	je     8095ed <urlencode+0x32>
  809624:	41 80 f8 5f          	cmp    $0x5f,%r8b
  809628:	74 c3                	je     8095ed <urlencode+0x32>
  80962a:	41 8d 40 d0          	lea    -0x30(%r8),%eax
  80962e:	3c 09                	cmp    $0x9,%al
  809630:	76 bb                	jbe    8095ed <urlencode+0x32>
  809632:	41 8d 40 bf          	lea    -0x41(%r8),%eax
  809636:	3c 19                	cmp    $0x19,%al
  809638:	76 b3                	jbe    8095ed <urlencode+0x32>
  80963a:	41 8d 40 9f          	lea    -0x61(%r8),%eax
  80963e:	3c 19                	cmp    $0x19,%al
  809640:	76 ab                	jbe    8095ed <urlencode+0x32>
  809642:	41 80 f8 20          	cmp    $0x20,%r8b
  809646:	74 56                	je     80969e <urlencode+0xe3>
  809648:	41 8d 40 e0          	lea    -0x20(%r8),%eax
  80964c:	3c 5f                	cmp    $0x5f,%al
  80964e:	0f 96 c2             	setbe  %dl
  809651:	41 80 f8 09          	cmp    $0x9,%r8b
  809655:	0f 94 c0             	sete   %al
  809658:	08 c2                	or     %al,%dl
  80965a:	74 4f                	je     8096ab <urlencode+0xf0>
  80965c:	48 89 e7             	mov    %rsp,%rdi
  80965f:	45 0f b6 c0          	movzbl %r8b,%r8d
  809663:	48 8d 0d 8e 12 00 00 	lea    0x128e(%rip),%rcx        # 80a8f8 <trans_char+0xa8>
  80966a:	ba 08 00 00 00       	mov    $0x8,%edx
  80966f:	be 01 00 00 00       	mov    $0x1,%esi
  809674:	b8 00 00 00 00       	mov    $0x0,%eax
  809679:	e8 d2 77 bf ff       	call   400e50 <__sprintf_chk@plt>
  80967e:	0f b6 04 24          	movzbl (%rsp),%eax
  809682:	88 45 00             	mov    %al,0x0(%rbp)
  809685:	0f b6 44 24 01       	movzbl 0x1(%rsp),%eax
  80968a:	88 45 01             	mov    %al,0x1(%rbp)
  80968d:	0f b6 44 24 02       	movzbl 0x2(%rsp),%eax
  809692:	88 45 02             	mov    %al,0x2(%rbp)
  809695:	48 8d 6d 03          	lea    0x3(%rbp),%rbp
  809699:	e9 57 ff ff ff       	jmp    8095f5 <urlencode+0x3a>
  80969e:	c6 45 00 2b          	movb   $0x2b,0x0(%rbp)
  8096a2:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
  8096a6:	e9 4a ff ff ff       	jmp    8095f5 <urlencode+0x3a>
  8096ab:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  8096b0:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  8096b5:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
  8096bc:	00 00 
  8096be:	75 09                	jne    8096c9 <urlencode+0x10e>
  8096c0:	48 83 c4 10          	add    $0x10,%rsp
  8096c4:	5b                   	pop    %rbx
  8096c5:	5d                   	pop    %rbp
  8096c6:	41 5c                	pop    %r12
  8096c8:	c3                   	ret
  8096c9:	e8 12 76 bf ff       	call   400ce0 <__stack_chk_fail@plt>

00000000008096ce <submitr>:
  8096ce:	41 57                	push   %r15
  8096d0:	41 56                	push   %r14
  8096d2:	41 55                	push   %r13
  8096d4:	41 54                	push   %r12
  8096d6:	55                   	push   %rbp
  8096d7:	53                   	push   %rbx
  8096d8:	48 81 ec 68 a0 00 00 	sub    $0xa068,%rsp
  8096df:	49 89 fd             	mov    %rdi,%r13
  8096e2:	89 74 24 14          	mov    %esi,0x14(%rsp)
  8096e6:	49 89 d7             	mov    %rdx,%r15
  8096e9:	48 89 4c 24 08       	mov    %rcx,0x8(%rsp)
  8096ee:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
  8096f3:	4d 89 ce             	mov    %r9,%r14
  8096f6:	48 8b ac 24 a0 a0 00 	mov    0xa0a0(%rsp),%rbp
  8096fd:	00 
  8096fe:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809705:	00 00 
  809707:	48 89 84 24 58 a0 00 	mov    %rax,0xa058(%rsp)
  80970e:	00 
  80970f:	31 c0                	xor    %eax,%eax
  809711:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%rsp)
  809718:	00 
  809719:	ba 00 00 00 00       	mov    $0x0,%edx
  80971e:	be 01 00 00 00       	mov    $0x1,%esi
  809723:	bf 02 00 00 00       	mov    $0x2,%edi
  809728:	e8 33 77 bf ff       	call   400e60 <socket@plt>
  80972d:	85 c0                	test   %eax,%eax
  80972f:	0f 88 a9 02 00 00    	js     8099de <submitr+0x310>
  809735:	89 c3                	mov    %eax,%ebx
  809737:	4c 89 ef             	mov    %r13,%rdi
  80973a:	e8 11 76 bf ff       	call   400d50 <gethostbyname@plt>
  80973f:	48 85 c0             	test   %rax,%rax
  809742:	0f 84 e2 02 00 00    	je     809a2a <submitr+0x35c>
  809748:	4c 8d 64 24 30       	lea    0x30(%rsp),%r12
  80974d:	48 c7 44 24 32 00 00 	movq   $0x0,0x32(%rsp)
  809754:	00 00 
  809756:	c7 44 24 3a 00 00 00 	movl   $0x0,0x3a(%rsp)
  80975d:	00 
  80975e:	66 c7 44 24 3e 00 00 	movw   $0x0,0x3e(%rsp)
  809765:	66 c7 44 24 30 02 00 	movw   $0x2,0x30(%rsp)
  80976c:	48 63 50 14          	movslq 0x14(%rax),%rdx
  809770:	48 8b 40 18          	mov    0x18(%rax),%rax
  809774:	48 8b 30             	mov    (%rax),%rsi
  809777:	48 8d 7c 24 34       	lea    0x34(%rsp),%rdi
  80977c:	b9 0c 00 00 00       	mov    $0xc,%ecx
  809781:	e8 da 75 bf ff       	call   400d60 <__memmove_chk@plt>
  809786:	0f b7 44 24 14       	movzwl 0x14(%rsp),%eax
  80978b:	66 c1 c8 08          	ror    $0x8,%ax
  80978f:	66 89 44 24 32       	mov    %ax,0x32(%rsp)
  809794:	ba 10 00 00 00       	mov    $0x10,%edx
  809799:	4c 89 e6             	mov    %r12,%rsi
  80979c:	89 df                	mov    %ebx,%edi
  80979e:	e8 8d 76 bf ff       	call   400e30 <connect@plt>
  8097a3:	85 c0                	test   %eax,%eax
  8097a5:	0f 88 e7 02 00 00    	js     809a92 <submitr+0x3c4>
  8097ab:	48 c7 c6 ff ff ff ff 	mov    $0xffffffffffffffff,%rsi
  8097b2:	b8 00 00 00 00       	mov    $0x0,%eax
  8097b7:	48 89 f1             	mov    %rsi,%rcx
  8097ba:	4c 89 f7             	mov    %r14,%rdi
  8097bd:	f2 ae                	repnz scas %es:(%rdi),%al
  8097bf:	48 89 ca             	mov    %rcx,%rdx
  8097c2:	48 f7 d2             	not    %rdx
  8097c5:	48 89 f1             	mov    %rsi,%rcx
  8097c8:	4c 89 ff             	mov    %r15,%rdi
  8097cb:	f2 ae                	repnz scas %es:(%rdi),%al
  8097cd:	48 f7 d1             	not    %rcx
  8097d0:	49 89 c8             	mov    %rcx,%r8
  8097d3:	48 89 f1             	mov    %rsi,%rcx
  8097d6:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
  8097db:	f2 ae                	repnz scas %es:(%rdi),%al
  8097dd:	48 f7 d1             	not    %rcx
  8097e0:	4d 8d 44 08 fe       	lea    -0x2(%r8,%rcx,1),%r8
  8097e5:	48 89 f1             	mov    %rsi,%rcx
  8097e8:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
  8097ed:	f2 ae                	repnz scas %es:(%rdi),%al
  8097ef:	48 89 c8             	mov    %rcx,%rax
  8097f2:	48 f7 d0             	not    %rax
  8097f5:	49 8d 4c 00 ff       	lea    -0x1(%r8,%rax,1),%rcx
  8097fa:	48 8d 44 52 fd       	lea    -0x3(%rdx,%rdx,2),%rax
  8097ff:	48 8d 84 01 80 00 00 	lea    0x80(%rcx,%rax,1),%rax
  809806:	00 
  809807:	48 3d 00 20 00 00    	cmp    $0x2000,%rax
  80980d:	0f 87 d9 02 00 00    	ja     809aec <submitr+0x41e>
  809813:	48 8d b4 24 50 40 00 	lea    0x4050(%rsp),%rsi
  80981a:	00 
  80981b:	b9 00 04 00 00       	mov    $0x400,%ecx
  809820:	b8 00 00 00 00       	mov    $0x0,%eax
  809825:	48 89 f7             	mov    %rsi,%rdi
  809828:	f3 48 ab             	rep stos %rax,%es:(%rdi)
  80982b:	4c 89 f7             	mov    %r14,%rdi
  80982e:	e8 88 fd ff ff       	call   8095bb <urlencode>
  809833:	85 c0                	test   %eax,%eax
  809835:	0f 88 24 03 00 00    	js     809b5f <submitr+0x491>
  80983b:	4c 8d a4 24 50 20 00 	lea    0x2050(%rsp),%r12
  809842:	00 
  809843:	41 55                	push   %r13
  809845:	48 8d 84 24 58 40 00 	lea    0x4058(%rsp),%rax
  80984c:	00 
  80984d:	50                   	push   %rax
  80984e:	4d 89 f9             	mov    %r15,%r9
  809851:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
  809856:	48 8d 0d 2b 10 00 00 	lea    0x102b(%rip),%rcx        # 80a888 <trans_char+0x38>
  80985d:	ba 00 20 00 00       	mov    $0x2000,%edx
  809862:	be 01 00 00 00       	mov    $0x1,%esi
  809867:	4c 89 e7             	mov    %r12,%rdi
  80986a:	b8 00 00 00 00       	mov    $0x0,%eax
  80986f:	e8 dc 75 bf ff       	call   400e50 <__sprintf_chk@plt>
  809874:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  80987b:	b8 00 00 00 00       	mov    $0x0,%eax
  809880:	4c 89 e7             	mov    %r12,%rdi
  809883:	f2 ae                	repnz scas %es:(%rdi),%al
  809885:	48 89 ca             	mov    %rcx,%rdx
  809888:	48 f7 d2             	not    %rdx
  80988b:	48 8d 52 ff          	lea    -0x1(%rdx),%rdx
  80988f:	4c 89 e6             	mov    %r12,%rsi
  809892:	89 df                	mov    %ebx,%edi
  809894:	e8 95 fb ff ff       	call   80942e <rio_writen>
  809899:	48 83 c4 10          	add    $0x10,%rsp
  80989d:	48 85 c0             	test   %rax,%rax
  8098a0:	0f 88 44 03 00 00    	js     809bea <submitr+0x51c>
  8098a6:	4c 8d 64 24 40       	lea    0x40(%rsp),%r12
  8098ab:	89 de                	mov    %ebx,%esi
  8098ad:	4c 89 e7             	mov    %r12,%rdi
  8098b0:	e8 37 fb ff ff       	call   8093ec <rio_readinitb>
  8098b5:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  8098bc:	00 
  8098bd:	ba 00 20 00 00       	mov    $0x2000,%edx
  8098c2:	4c 89 e7             	mov    %r12,%rdi
  8098c5:	e8 4d fc ff ff       	call   809517 <rio_readlineb>
  8098ca:	48 85 c0             	test   %rax,%rax
  8098cd:	0f 8e 86 03 00 00    	jle    809c59 <submitr+0x58b>
  8098d3:	48 8d 4c 24 2c       	lea    0x2c(%rsp),%rcx
  8098d8:	48 8d 94 24 50 60 00 	lea    0x6050(%rsp),%rdx
  8098df:	00 
  8098e0:	48 8d bc 24 50 20 00 	lea    0x2050(%rsp),%rdi
  8098e7:	00 
  8098e8:	4c 8d 84 24 50 80 00 	lea    0x8050(%rsp),%r8
  8098ef:	00 
  8098f0:	48 8d 35 08 10 00 00 	lea    0x1008(%rip),%rsi        # 80a8ff <trans_char+0xaf>
  8098f7:	b8 00 00 00 00       	mov    $0x0,%eax
  8098fc:	e8 bf 74 bf ff       	call   400dc0 <__isoc99_sscanf@plt>
  809901:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  809908:	00 
  809909:	b9 03 00 00 00       	mov    $0x3,%ecx
  80990e:	48 8d 3d 01 10 00 00 	lea    0x1001(%rip),%rdi        # 80a916 <trans_char+0xc6>
  809915:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809917:	0f 97 c0             	seta   %al
  80991a:	1c 00                	sbb    $0x0,%al
  80991c:	84 c0                	test   %al,%al
  80991e:	0f 84 b3 03 00 00    	je     809cd7 <submitr+0x609>
  809924:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  80992b:	00 
  80992c:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
  809931:	ba 00 20 00 00       	mov    $0x2000,%edx
  809936:	e8 dc fb ff ff       	call   809517 <rio_readlineb>
  80993b:	48 85 c0             	test   %rax,%rax
  80993e:	7f c1                	jg     809901 <submitr+0x233>
  809940:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809947:	3a 20 43 
  80994a:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809951:	20 75 6e 
  809954:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809958:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  80995c:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809963:	74 6f 20 
  809966:	48 ba 72 65 61 64 20 	movabs $0x6165682064616572,%rdx
  80996d:	68 65 61 
  809970:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809974:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809978:	48 b8 64 65 72 73 20 	movabs $0x6f72662073726564,%rax
  80997f:	66 72 6f 
  809982:	48 ba 6d 20 74 68 65 	movabs $0x657220656874206d,%rdx
  809989:	20 72 65 
  80998c:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809990:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809994:	48 b8 73 75 6c 74 20 	movabs $0x72657320746c7573,%rax
  80999b:	73 65 72 
  80999e:	48 89 45 30          	mov    %rax,0x30(%rbp)
  8099a2:	c7 45 38 76 65 72 00 	movl   $0x726576,0x38(%rbp)
  8099a9:	89 df                	mov    %ebx,%edi
  8099ab:	e8 70 73 bf ff       	call   400d20 <close@plt>
  8099b0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  8099b5:	48 8b 9c 24 58 a0 00 	mov    0xa058(%rsp),%rbx
  8099bc:	00 
  8099bd:	64 48 33 1c 25 28 00 	xor    %fs:0x28,%rbx
  8099c4:	00 00 
  8099c6:	0f 85 7e 04 00 00    	jne    809e4a <submitr+0x77c>
  8099cc:	48 81 c4 68 a0 00 00 	add    $0xa068,%rsp
  8099d3:	5b                   	pop    %rbx
  8099d4:	5d                   	pop    %rbp
  8099d5:	41 5c                	pop    %r12
  8099d7:	41 5d                	pop    %r13
  8099d9:	41 5e                	pop    %r14
  8099db:	41 5f                	pop    %r15
  8099dd:	c3                   	ret
  8099de:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  8099e5:	3a 20 43 
  8099e8:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  8099ef:	20 75 6e 
  8099f2:	48 89 45 00          	mov    %rax,0x0(%rbp)
  8099f6:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  8099fa:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809a01:	74 6f 20 
  809a04:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
  809a0b:	65 20 73 
  809a0e:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809a12:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809a16:	c7 45 20 6f 63 6b 65 	movl   $0x656b636f,0x20(%rbp)
  809a1d:	66 c7 45 24 74 00    	movw   $0x74,0x24(%rbp)
  809a23:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809a28:	eb 8b                	jmp    8099b5 <submitr+0x2e7>
  809a2a:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
  809a31:	3a 20 44 
  809a34:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
  809a3b:	20 75 6e 
  809a3e:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809a42:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809a46:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809a4d:	74 6f 20 
  809a50:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
  809a57:	76 65 20 
  809a5a:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809a5e:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809a62:	48 b8 73 65 72 76 65 	movabs $0x6120726576726573,%rax
  809a69:	72 20 61 
  809a6c:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809a70:	c7 45 28 64 64 72 65 	movl   $0x65726464,0x28(%rbp)
  809a77:	66 c7 45 2c 73 73    	movw   $0x7373,0x2c(%rbp)
  809a7d:	c6 45 2e 00          	movb   $0x0,0x2e(%rbp)
  809a81:	89 df                	mov    %ebx,%edi
  809a83:	e8 98 72 bf ff       	call   400d20 <close@plt>
  809a88:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809a8d:	e9 23 ff ff ff       	jmp    8099b5 <submitr+0x2e7>
  809a92:	48 b8 45 72 72 6f 72 	movabs $0x55203a726f727245,%rax
  809a99:	3a 20 55 
  809a9c:	48 ba 6e 61 62 6c 65 	movabs $0x6f7420656c62616e,%rdx
  809aa3:	20 74 6f 
  809aa6:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809aaa:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809aae:	48 b8 20 63 6f 6e 6e 	movabs $0x7463656e6e6f6320,%rax
  809ab5:	65 63 74 
  809ab8:	48 ba 20 74 6f 20 74 	movabs $0x20656874206f7420,%rdx
  809abf:	68 65 20 
  809ac2:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809ac6:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809aca:	c7 45 20 73 65 72 76 	movl   $0x76726573,0x20(%rbp)
  809ad1:	66 c7 45 24 65 72    	movw   $0x7265,0x24(%rbp)
  809ad7:	c6 45 26 00          	movb   $0x0,0x26(%rbp)
  809adb:	89 df                	mov    %ebx,%edi
  809add:	e8 3e 72 bf ff       	call   400d20 <close@plt>
  809ae2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809ae7:	e9 c9 fe ff ff       	jmp    8099b5 <submitr+0x2e7>
  809aec:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
  809af3:	3a 20 52 
  809af6:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
  809afd:	20 73 74 
  809b00:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809b04:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809b08:	48 b8 72 69 6e 67 20 	movabs $0x6f6f7420676e6972,%rax
  809b0f:	74 6f 6f 
  809b12:	48 ba 20 6c 61 72 67 	movabs $0x202e656772616c20,%rdx
  809b19:	65 2e 20 
  809b1c:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809b20:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809b24:	48 b8 49 6e 63 72 65 	movabs $0x6573616572636e49,%rax
  809b2b:	61 73 65 
  809b2e:	48 ba 20 53 55 42 4d 	movabs $0x5254494d42555320,%rdx
  809b35:	49 54 52 
  809b38:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809b3c:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809b40:	48 b8 5f 4d 41 58 42 	movabs $0x46554258414d5f,%rax
  809b47:	55 46 00 
  809b4a:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809b4e:	89 df                	mov    %ebx,%edi
  809b50:	e8 cb 71 bf ff       	call   400d20 <close@plt>
  809b55:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809b5a:	e9 56 fe ff ff       	jmp    8099b5 <submitr+0x2e7>
  809b5f:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
  809b66:	3a 20 52 
  809b69:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
  809b70:	20 73 74 
  809b73:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809b77:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809b7b:	48 b8 72 69 6e 67 20 	movabs $0x6e6f6320676e6972,%rax
  809b82:	63 6f 6e 
  809b85:	48 ba 74 61 69 6e 73 	movabs $0x6e6120736e696174,%rdx
  809b8c:	20 61 6e 
  809b8f:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809b93:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809b97:	48 b8 20 69 6c 6c 65 	movabs $0x6c6167656c6c6920,%rax
  809b9e:	67 61 6c 
  809ba1:	48 ba 20 6f 72 20 75 	movabs $0x72706e7520726f20,%rdx
  809ba8:	6e 70 72 
  809bab:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809baf:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809bb3:	48 b8 69 6e 74 61 62 	movabs $0x20656c6261746e69,%rax
  809bba:	6c 65 20 
  809bbd:	48 ba 63 68 61 72 61 	movabs $0x6574636172616863,%rdx
  809bc4:	63 74 65 
  809bc7:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809bcb:	48 89 55 38          	mov    %rdx,0x38(%rbp)
  809bcf:	66 c7 45 40 72 2e    	movw   $0x2e72,0x40(%rbp)
  809bd5:	c6 45 42 00          	movb   $0x0,0x42(%rbp)
  809bd9:	89 df                	mov    %ebx,%edi
  809bdb:	e8 40 71 bf ff       	call   400d20 <close@plt>
  809be0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809be5:	e9 cb fd ff ff       	jmp    8099b5 <submitr+0x2e7>
  809bea:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809bf1:	3a 20 43 
  809bf4:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809bfb:	20 75 6e 
  809bfe:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809c02:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809c06:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809c0d:	74 6f 20 
  809c10:	48 ba 77 72 69 74 65 	movabs $0x6f74206574697277,%rdx
  809c17:	20 74 6f 
  809c1a:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809c1e:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809c22:	48 b8 20 74 68 65 20 	movabs $0x7365722065687420,%rax
  809c29:	72 65 73 
  809c2c:	48 ba 75 6c 74 20 73 	movabs $0x7672657320746c75,%rdx
  809c33:	65 72 76 
  809c36:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809c3a:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809c3e:	66 c7 45 30 65 72    	movw   $0x7265,0x30(%rbp)
  809c44:	c6 45 32 00          	movb   $0x0,0x32(%rbp)
  809c48:	89 df                	mov    %ebx,%edi
  809c4a:	e8 d1 70 bf ff       	call   400d20 <close@plt>
  809c4f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809c54:	e9 5c fd ff ff       	jmp    8099b5 <submitr+0x2e7>
  809c59:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809c60:	3a 20 43 
  809c63:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809c6a:	20 75 6e 
  809c6d:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809c71:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809c75:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809c7c:	74 6f 20 
  809c7f:	48 ba 72 65 61 64 20 	movabs $0x7269662064616572,%rdx
  809c86:	66 69 72 
  809c89:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809c8d:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809c91:	48 b8 73 74 20 68 65 	movabs $0x6564616568207473,%rax
  809c98:	61 64 65 
  809c9b:	48 ba 72 20 66 72 6f 	movabs $0x72206d6f72662072,%rdx
  809ca2:	6d 20 72 
  809ca5:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809ca9:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809cad:	48 b8 65 73 75 6c 74 	movabs $0x657320746c757365,%rax
  809cb4:	20 73 65 
  809cb7:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809cbb:	c7 45 38 72 76 65 72 	movl   $0x72657672,0x38(%rbp)
  809cc2:	c6 45 3c 00          	movb   $0x0,0x3c(%rbp)
  809cc6:	89 df                	mov    %ebx,%edi
  809cc8:	e8 53 70 bf ff       	call   400d20 <close@plt>
  809ccd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809cd2:	e9 de fc ff ff       	jmp    8099b5 <submitr+0x2e7>
  809cd7:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  809cde:	00 
  809cdf:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
  809ce4:	ba 00 20 00 00       	mov    $0x2000,%edx
  809ce9:	e8 29 f8 ff ff       	call   809517 <rio_readlineb>
  809cee:	48 85 c0             	test   %rax,%rax
  809cf1:	0f 8e 96 00 00 00    	jle    809d8d <submitr+0x6bf>
  809cf7:	44 8b 44 24 2c       	mov    0x2c(%rsp),%r8d
  809cfc:	41 81 f8 c8 00 00 00 	cmp    $0xc8,%r8d
  809d03:	0f 85 08 01 00 00    	jne    809e11 <submitr+0x743>
  809d09:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  809d10:	00 
  809d11:	48 89 ef             	mov    %rbp,%rdi
  809d14:	e8 97 6f bf ff       	call   400cb0 <strcpy@plt>
  809d19:	89 df                	mov    %ebx,%edi
  809d1b:	e8 00 70 bf ff       	call   400d20 <close@plt>
  809d20:	b9 04 00 00 00       	mov    $0x4,%ecx
  809d25:	48 8d 3d e4 0b 00 00 	lea    0xbe4(%rip),%rdi        # 80a910 <trans_char+0xc0>
  809d2c:	48 89 ee             	mov    %rbp,%rsi
  809d2f:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809d31:	0f 97 c0             	seta   %al
  809d34:	1c 00                	sbb    $0x0,%al
  809d36:	0f be c0             	movsbl %al,%eax
  809d39:	85 c0                	test   %eax,%eax
  809d3b:	0f 84 74 fc ff ff    	je     8099b5 <submitr+0x2e7>
  809d41:	b9 05 00 00 00       	mov    $0x5,%ecx
  809d46:	48 8d 3d c7 0b 00 00 	lea    0xbc7(%rip),%rdi        # 80a914 <trans_char+0xc4>
  809d4d:	48 89 ee             	mov    %rbp,%rsi
  809d50:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809d52:	0f 97 c0             	seta   %al
  809d55:	1c 00                	sbb    $0x0,%al
  809d57:	0f be c0             	movsbl %al,%eax
  809d5a:	85 c0                	test   %eax,%eax
  809d5c:	0f 84 53 fc ff ff    	je     8099b5 <submitr+0x2e7>
  809d62:	b9 03 00 00 00       	mov    $0x3,%ecx
  809d67:	48 8d 3d ab 0b 00 00 	lea    0xbab(%rip),%rdi        # 80a919 <trans_char+0xc9>
  809d6e:	48 89 ee             	mov    %rbp,%rsi
  809d71:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809d73:	0f 97 c0             	seta   %al
  809d76:	1c 00                	sbb    $0x0,%al
  809d78:	0f be c0             	movsbl %al,%eax
  809d7b:	85 c0                	test   %eax,%eax
  809d7d:	0f 84 32 fc ff ff    	je     8099b5 <submitr+0x2e7>
  809d83:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809d88:	e9 28 fc ff ff       	jmp    8099b5 <submitr+0x2e7>
  809d8d:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809d94:	3a 20 43 
  809d97:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809d9e:	20 75 6e 
  809da1:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809da5:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809da9:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809db0:	74 6f 20 
  809db3:	48 ba 72 65 61 64 20 	movabs $0x6174732064616572,%rdx
  809dba:	73 74 61 
  809dbd:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809dc1:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809dc5:	48 b8 74 75 73 20 6d 	movabs $0x7373656d20737574,%rax
  809dcc:	65 73 73 
  809dcf:	48 ba 61 67 65 20 66 	movabs $0x6d6f726620656761,%rdx
  809dd6:	72 6f 6d 
  809dd9:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809ddd:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809de1:	48 b8 20 72 65 73 75 	movabs $0x20746c7573657220,%rax
  809de8:	6c 74 20 
  809deb:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809def:	c7 45 38 73 65 72 76 	movl   $0x76726573,0x38(%rbp)
  809df6:	66 c7 45 3c 65 72    	movw   $0x7265,0x3c(%rbp)
  809dfc:	c6 45 3e 00          	movb   $0x0,0x3e(%rbp)
  809e00:	89 df                	mov    %ebx,%edi
  809e02:	e8 19 6f bf ff       	call   400d20 <close@plt>
  809e07:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809e0c:	e9 a4 fb ff ff       	jmp    8099b5 <submitr+0x2e7>
  809e11:	4c 8d 8c 24 50 80 00 	lea    0x8050(%rsp),%r9
  809e18:	00 
  809e19:	48 8d 0d a8 0a 00 00 	lea    0xaa8(%rip),%rcx        # 80a8c8 <trans_char+0x78>
  809e20:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
  809e27:	be 01 00 00 00       	mov    $0x1,%esi
  809e2c:	48 89 ef             	mov    %rbp,%rdi
  809e2f:	b8 00 00 00 00       	mov    $0x0,%eax
  809e34:	e8 17 70 bf ff       	call   400e50 <__sprintf_chk@plt>
  809e39:	89 df                	mov    %ebx,%edi
  809e3b:	e8 e0 6e bf ff       	call   400d20 <close@plt>
  809e40:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809e45:	e9 6b fb ff ff       	jmp    8099b5 <submitr+0x2e7>
  809e4a:	e8 91 6e bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809e4f <init_timeout>:
  809e4f:	85 ff                	test   %edi,%edi
  809e51:	74 28                	je     809e7b <init_timeout+0x2c>
  809e53:	53                   	push   %rbx
  809e54:	89 fb                	mov    %edi,%ebx
  809e56:	85 ff                	test   %edi,%edi
  809e58:	78 1a                	js     809e74 <init_timeout+0x25>
  809e5a:	48 8d 35 9d f5 ff ff 	lea    -0xa63(%rip),%rsi        # 8093fe <sigalrm_handler>
  809e61:	bf 0e 00 00 00       	mov    $0xe,%edi
  809e66:	e8 d5 6e bf ff       	call   400d40 <signal@plt>
  809e6b:	89 df                	mov    %ebx,%edi
  809e6d:	e8 9e 6e bf ff       	call   400d10 <alarm@plt>
  809e72:	5b                   	pop    %rbx
  809e73:	c3                   	ret
  809e74:	bb 00 00 00 00       	mov    $0x0,%ebx
  809e79:	eb df                	jmp    809e5a <init_timeout+0xb>
  809e7b:	f3 c3                	repz ret

0000000000809e7d <init_driver>:
  809e7d:	41 54                	push   %r12
  809e7f:	55                   	push   %rbp
  809e80:	53                   	push   %rbx
  809e81:	48 83 ec 20          	sub    $0x20,%rsp
  809e85:	49 89 fc             	mov    %rdi,%r12
  809e88:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809e8f:	00 00 
  809e91:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  809e96:	31 c0                	xor    %eax,%eax
  809e98:	be 01 00 00 00       	mov    $0x1,%esi
  809e9d:	bf 0d 00 00 00       	mov    $0xd,%edi
  809ea2:	e8 99 6e bf ff       	call   400d40 <signal@plt>
  809ea7:	be 01 00 00 00       	mov    $0x1,%esi
  809eac:	bf 1d 00 00 00       	mov    $0x1d,%edi
  809eb1:	e8 8a 6e bf ff       	call   400d40 <signal@plt>
  809eb6:	be 01 00 00 00       	mov    $0x1,%esi
  809ebb:	bf 1d 00 00 00       	mov    $0x1d,%edi
  809ec0:	e8 7b 6e bf ff       	call   400d40 <signal@plt>
  809ec5:	ba 00 00 00 00       	mov    $0x0,%edx
  809eca:	be 01 00 00 00       	mov    $0x1,%esi
  809ecf:	bf 02 00 00 00       	mov    $0x2,%edi
  809ed4:	e8 87 6f bf ff       	call   400e60 <socket@plt>
  809ed9:	85 c0                	test   %eax,%eax
  809edb:	0f 88 a3 00 00 00    	js     809f84 <init_driver+0x107>
  809ee1:	89 c3                	mov    %eax,%ebx
  809ee3:	48 8d 3d 57 05 00 00 	lea    0x557(%rip),%rdi        # 80a441 <_IO_stdin_used+0x251>
  809eea:	e8 61 6e bf ff       	call   400d50 <gethostbyname@plt>
  809eef:	48 85 c0             	test   %rax,%rax
  809ef2:	0f 84 df 00 00 00    	je     809fd7 <init_driver+0x15a>
  809ef8:	48 89 e5             	mov    %rsp,%rbp
  809efb:	48 c7 44 24 02 00 00 	movq   $0x0,0x2(%rsp)
  809f02:	00 00 
  809f04:	c7 45 0a 00 00 00 00 	movl   $0x0,0xa(%rbp)
  809f0b:	66 c7 45 0e 00 00    	movw   $0x0,0xe(%rbp)
  809f11:	66 c7 04 24 02 00    	movw   $0x2,(%rsp)
  809f17:	48 63 50 14          	movslq 0x14(%rax),%rdx
  809f1b:	48 8b 40 18          	mov    0x18(%rax),%rax
  809f1f:	48 8b 30             	mov    (%rax),%rsi
  809f22:	48 8d 7d 04          	lea    0x4(%rbp),%rdi
  809f26:	b9 0c 00 00 00       	mov    $0xc,%ecx
  809f2b:	e8 30 6e bf ff       	call   400d60 <__memmove_chk@plt>
  809f30:	66 c7 44 24 02 3c 9a 	movw   $0x9a3c,0x2(%rsp)
  809f37:	ba 10 00 00 00       	mov    $0x10,%edx
  809f3c:	48 89 ee             	mov    %rbp,%rsi
  809f3f:	89 df                	mov    %ebx,%edi
  809f41:	e8 ea 6e bf ff       	call   400e30 <connect@plt>
  809f46:	85 c0                	test   %eax,%eax
  809f48:	0f 88 fb 00 00 00    	js     80a049 <init_driver+0x1cc>
  809f4e:	89 df                	mov    %ebx,%edi
  809f50:	e8 cb 6d bf ff       	call   400d20 <close@plt>
  809f55:	66 41 c7 04 24 4f 4b 	movw   $0x4b4f,(%r12)
  809f5c:	41 c6 44 24 02 00    	movb   $0x0,0x2(%r12)
  809f62:	b8 00 00 00 00       	mov    $0x0,%eax
  809f67:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
  809f6c:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  809f73:	00 00 
  809f75:	0f 85 28 01 00 00    	jne    80a0a3 <init_driver+0x226>
  809f7b:	48 83 c4 20          	add    $0x20,%rsp
  809f7f:	5b                   	pop    %rbx
  809f80:	5d                   	pop    %rbp
  809f81:	41 5c                	pop    %r12
  809f83:	c3                   	ret
  809f84:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809f8b:	3a 20 43 
  809f8e:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809f95:	20 75 6e 
  809f98:	49 89 04 24          	mov    %rax,(%r12)
  809f9c:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  809fa1:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809fa8:	74 6f 20 
  809fab:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
  809fb2:	65 20 73 
  809fb5:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  809fba:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  809fbf:	41 c7 44 24 20 6f 63 	movl   $0x656b636f,0x20(%r12)
  809fc6:	6b 65 
  809fc8:	66 41 c7 44 24 24 74 	movw   $0x74,0x24(%r12)
  809fcf:	00 
  809fd0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809fd5:	eb 90                	jmp    809f67 <init_driver+0xea>
  809fd7:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
  809fde:	3a 20 44 
  809fe1:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
  809fe8:	20 75 6e 
  809feb:	49 89 04 24          	mov    %rax,(%r12)
  809fef:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  809ff4:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809ffb:	74 6f 20 
  809ffe:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
  80a005:	76 65 20 
  80a008:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  80a00d:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  80a012:	48 b8 73 65 72 76 65 	movabs $0x6120726576726573,%rax
  80a019:	72 20 61 
  80a01c:	49 89 44 24 20       	mov    %rax,0x20(%r12)
  80a021:	41 c7 44 24 28 64 64 	movl   $0x65726464,0x28(%r12)
  80a028:	72 65 
  80a02a:	66 41 c7 44 24 2c 73 	movw   $0x7373,0x2c(%r12)
  80a031:	73 
  80a032:	41 c6 44 24 2e 00    	movb   $0x0,0x2e(%r12)
  80a038:	89 df                	mov    %ebx,%edi
  80a03a:	e8 e1 6c bf ff       	call   400d20 <close@plt>
  80a03f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  80a044:	e9 1e ff ff ff       	jmp    809f67 <init_driver+0xea>
  80a049:	48 b8 45 72 72 6f 72 	movabs $0x55203a726f727245,%rax
  80a050:	3a 20 55 
  80a053:	48 ba 6e 61 62 6c 65 	movabs $0x6f7420656c62616e,%rdx
  80a05a:	20 74 6f 
  80a05d:	49 89 04 24          	mov    %rax,(%r12)
  80a061:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  80a066:	48 b8 20 63 6f 6e 6e 	movabs $0x7463656e6e6f6320,%rax
  80a06d:	65 63 74 
  80a070:	48 ba 20 74 6f 20 73 	movabs $0x76726573206f7420,%rdx
  80a077:	65 72 76 
  80a07a:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  80a07f:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  80a084:	66 41 c7 44 24 20 65 	movw   $0x7265,0x20(%r12)
  80a08b:	72 
  80a08c:	41 c6 44 24 22 00    	movb   $0x0,0x22(%r12)
  80a092:	89 df                	mov    %ebx,%edi
  80a094:	e8 87 6c bf ff       	call   400d20 <close@plt>
  80a099:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  80a09e:	e9 c4 fe ff ff       	jmp    809f67 <init_driver+0xea>
  80a0a3:	e8 38 6c bf ff       	call   400ce0 <__stack_chk_fail@plt>

000000000080a0a8 <driver_post>:
  80a0a8:	53                   	push   %rbx
  80a0a9:	4c 89 cb             	mov    %r9,%rbx
  80a0ac:	45 85 c0             	test   %r8d,%r8d
  80a0af:	75 18                	jne    80a0c9 <driver_post+0x21>
  80a0b1:	48 85 ff             	test   %rdi,%rdi
  80a0b4:	74 05                	je     80a0bb <driver_post+0x13>
  80a0b6:	80 3f 00             	cmpb   $0x0,(%rdi)
  80a0b9:	75 37                	jne    80a0f2 <driver_post+0x4a>
  80a0bb:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
  80a0c0:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
  80a0c4:	44 89 c0             	mov    %r8d,%eax
  80a0c7:	5b                   	pop    %rbx
  80a0c8:	c3                   	ret
  80a0c9:	48 89 ca             	mov    %rcx,%rdx
  80a0cc:	48 8d 35 49 08 00 00 	lea    0x849(%rip),%rsi        # 80a91c <trans_char+0xcc>
  80a0d3:	bf 01 00 00 00       	mov    $0x1,%edi
  80a0d8:	b8 00 00 00 00       	mov    $0x0,%eax
  80a0dd:	e8 fe 6c bf ff       	call   400de0 <__printf_chk@plt>
  80a0e2:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
  80a0e7:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
  80a0eb:	b8 00 00 00 00       	mov    $0x0,%eax
  80a0f0:	eb d5                	jmp    80a0c7 <driver_post+0x1f>
  80a0f2:	48 83 ec 08          	sub    $0x8,%rsp
  80a0f6:	41 51                	push   %r9
  80a0f8:	49 89 c9             	mov    %rcx,%r9
  80a0fb:	49 89 d0             	mov    %rdx,%r8
  80a0fe:	48 89 f9             	mov    %rdi,%rcx
  80a101:	48 89 f2             	mov    %rsi,%rdx
  80a104:	be 9a 3c 00 00       	mov    $0x3c9a,%esi
  80a109:	48 8d 3d 31 03 00 00 	lea    0x331(%rip),%rdi        # 80a441 <_IO_stdin_used+0x251>
  80a110:	e8 b9 f5 ff ff       	call   8096ce <submitr>
  80a115:	48 83 c4 10          	add    $0x10,%rsp
  80a119:	eb ac                	jmp    80a0c7 <driver_post+0x1f>

000000000080a11b <check>:
  80a11b:	89 f8                	mov    %edi,%eax
  80a11d:	c1 e8 1c             	shr    $0x1c,%eax
  80a120:	85 c0                	test   %eax,%eax
  80a122:	74 1d                	je     80a141 <check+0x26>
  80a124:	b9 00 00 00 00       	mov    $0x0,%ecx
  80a129:	83 f9 1f             	cmp    $0x1f,%ecx
  80a12c:	7f 0d                	jg     80a13b <check+0x20>
  80a12e:	89 f8                	mov    %edi,%eax
  80a130:	d3 e8                	shr    %cl,%eax
  80a132:	3c 0a                	cmp    $0xa,%al
  80a134:	74 11                	je     80a147 <check+0x2c>
  80a136:	83 c1 08             	add    $0x8,%ecx
  80a139:	eb ee                	jmp    80a129 <check+0xe>
  80a13b:	b8 01 00 00 00       	mov    $0x1,%eax
  80a140:	c3                   	ret
  80a141:	b8 00 00 00 00       	mov    $0x0,%eax
  80a146:	c3                   	ret
  80a147:	b8 00 00 00 00       	mov    $0x0,%eax
  80a14c:	c3                   	ret

000000000080a14d <gencookie>:
  80a14d:	53                   	push   %rbx
  80a14e:	83 c7 01             	add    $0x1,%edi
  80a151:	e8 3a 6b bf ff       	call   400c90 <srandom@plt>
  80a156:	e8 45 6c bf ff       	call   400da0 <random@plt>
  80a15b:	89 c3                	mov    %eax,%ebx
  80a15d:	89 c7                	mov    %eax,%edi
  80a15f:	e8 b7 ff ff ff       	call   80a11b <check>
  80a164:	85 c0                	test   %eax,%eax
  80a166:	74 ee                	je     80a156 <gencookie+0x9>
  80a168:	89 d8                	mov    %ebx,%eax
  80a16a:	5b                   	pop    %rbx
  80a16b:	c3                   	ret
  80a16c:	0f 1f 40 00          	nopl   0x0(%rax)

000000000080a170 <__libc_csu_init>:
  80a170:	41 57                	push   %r15
  80a172:	41 56                	push   %r14
  80a174:	49 89 d7             	mov    %rdx,%r15
  80a177:	41 55                	push   %r13
  80a179:	41 54                	push   %r12
  80a17b:	4c 8d 25 8e 1c 20 00 	lea    0x201c8e(%rip),%r12        # a0be10 <__frame_dummy_init_array_entry>
  80a182:	55                   	push   %rbp
  80a183:	48 8d 2d 8e 1c 20 00 	lea    0x201c8e(%rip),%rbp        # a0be18 <__do_global_dtors_aux_fini_array_entry>
  80a18a:	53                   	push   %rbx
  80a18b:	41 89 fd             	mov    %edi,%r13d
  80a18e:	49 89 f6             	mov    %rsi,%r14
  80a191:	4c 29 e5             	sub    %r12,%rbp
  80a194:	48 83 ec 08          	sub    $0x8,%rsp
  80a198:	48 c1 fd 03          	sar    $0x3,%rbp
  80a19c:	e8 a7 6a bf ff       	call   400c48 <_init>
  80a1a1:	48 85 ed             	test   %rbp,%rbp
  80a1a4:	74 20                	je     80a1c6 <__libc_csu_init+0x56>
  80a1a6:	31 db                	xor    %ebx,%ebx
  80a1a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  80a1af:	00 
  80a1b0:	4c 89 fa             	mov    %r15,%rdx
  80a1b3:	4c 89 f6             	mov    %r14,%rsi
  80a1b6:	44 89 ef             	mov    %r13d,%edi
  80a1b9:	41 ff 14 dc          	call   *(%r12,%rbx,8)
  80a1bd:	48 83 c3 01          	add    $0x1,%rbx
  80a1c1:	48 39 dd             	cmp    %rbx,%rbp
  80a1c4:	75 ea                	jne    80a1b0 <__libc_csu_init+0x40>
  80a1c6:	48 83 c4 08          	add    $0x8,%rsp
  80a1ca:	5b                   	pop    %rbx
  80a1cb:	5d                   	pop    %rbp
  80a1cc:	41 5c                	pop    %r12
  80a1ce:	41 5d                	pop    %r13
  80a1d0:	41 5e                	pop    %r14
  80a1d2:	41 5f                	pop    %r15
  80a1d4:	c3                   	ret
  80a1d5:	90                   	nop
  80a1d6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  80a1dd:	00 00 00 

000000000080a1e0 <__libc_csu_fini>:
  80a1e0:	f3 c3                	repz ret

Disassembly of section .init:

0000000000400c48 <_init>:
  400c48:	48 83 ec 08          	sub    $0x8,%rsp
  400c4c:	48 8b 05 a5 b3 60 00 	mov    0x60b3a5(%rip),%rax        # a0bff8 <__gmon_start__>
  400c53:	48 85 c0             	test   %rax,%rax
  400c56:	74 02                	je     400c5a <_init+0x12>
  400c58:	ff d0                	call   *%rax
  400c5a:	48 83 c4 08          	add    $0x8,%rsp
  400c5e:	c3                   	ret

Disassembly of section .plt:

0000000000400c60 <.plt>:
  400c60:	ff 35 a2 b3 60 00    	push   0x60b3a2(%rip)        # a0c008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400c66:	ff 25 a4 b3 60 00    	jmp    *0x60b3a4(%rip)        # a0c010 <_GLOBAL_OFFSET_TABLE_+0x10>
  400c6c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400c70 <__snprintf_chk@plt>:
  400c70:	ff 25 a2 b3 60 00    	jmp    *0x60b3a2(%rip)        # a0c018 <__snprintf_chk@GLIBC_2.3.4>
  400c76:	68 00 00 00 00       	push   $0x0
  400c7b:	e9 e0 ff ff ff       	jmp    400c60 <.plt>

0000000000400c80 <__errno_location@plt>:
  400c80:	ff 25 9a b3 60 00    	jmp    *0x60b39a(%rip)        # a0c020 <__errno_location@GLIBC_2.2.5>
  400c86:	68 01 00 00 00       	push   $0x1
  400c8b:	e9 d0 ff ff ff       	jmp    400c60 <.plt>

0000000000400c90 <srandom@plt>:
  400c90:	ff 25 92 b3 60 00    	jmp    *0x60b392(%rip)        # a0c028 <srandom@GLIBC_2.2.5>
  400c96:	68 02 00 00 00       	push   $0x2
  400c9b:	e9 c0 ff ff ff       	jmp    400c60 <.plt>

0000000000400ca0 <strncmp@plt>:
  400ca0:	ff 25 8a b3 60 00    	jmp    *0x60b38a(%rip)        # a0c030 <strncmp@GLIBC_2.2.5>
  400ca6:	68 03 00 00 00       	push   $0x3
  400cab:	e9 b0 ff ff ff       	jmp    400c60 <.plt>

0000000000400cb0 <strcpy@plt>:
  400cb0:	ff 25 82 b3 60 00    	jmp    *0x60b382(%rip)        # a0c038 <strcpy@GLIBC_2.2.5>
  400cb6:	68 04 00 00 00       	push   $0x4
  400cbb:	e9 a0 ff ff ff       	jmp    400c60 <.plt>

0000000000400cc0 <puts@plt>:
  400cc0:	ff 25 7a b3 60 00    	jmp    *0x60b37a(%rip)        # a0c040 <puts@GLIBC_2.2.5>
  400cc6:	68 05 00 00 00       	push   $0x5
  400ccb:	e9 90 ff ff ff       	jmp    400c60 <.plt>

0000000000400cd0 <write@plt>:
  400cd0:	ff 25 72 b3 60 00    	jmp    *0x60b372(%rip)        # a0c048 <write@GLIBC_2.2.5>
  400cd6:	68 06 00 00 00       	push   $0x6
  400cdb:	e9 80 ff ff ff       	jmp    400c60 <.plt>

0000000000400ce0 <__stack_chk_fail@plt>:
  400ce0:	ff 25 6a b3 60 00    	jmp    *0x60b36a(%rip)        # a0c050 <__stack_chk_fail@GLIBC_2.4>
  400ce6:	68 07 00 00 00       	push   $0x7
  400ceb:	e9 70 ff ff ff       	jmp    400c60 <.plt>

0000000000400cf0 <mmap@plt>:
  400cf0:	ff 25 62 b3 60 00    	jmp    *0x60b362(%rip)        # a0c058 <mmap@GLIBC_2.2.5>
  400cf6:	68 08 00 00 00       	push   $0x8
  400cfb:	e9 60 ff ff ff       	jmp    400c60 <.plt>

0000000000400d00 <memset@plt>:
  400d00:	ff 25 5a b3 60 00    	jmp    *0x60b35a(%rip)        # a0c060 <memset@GLIBC_2.2.5>
  400d06:	68 09 00 00 00       	push   $0x9
  400d0b:	e9 50 ff ff ff       	jmp    400c60 <.plt>

0000000000400d10 <alarm@plt>:
  400d10:	ff 25 52 b3 60 00    	jmp    *0x60b352(%rip)        # a0c068 <alarm@GLIBC_2.2.5>
  400d16:	68 0a 00 00 00       	push   $0xa
  400d1b:	e9 40 ff ff ff       	jmp    400c60 <.plt>

0000000000400d20 <close@plt>:
  400d20:	ff 25 4a b3 60 00    	jmp    *0x60b34a(%rip)        # a0c070 <close@GLIBC_2.2.5>
  400d26:	68 0b 00 00 00       	push   $0xb
  400d2b:	e9 30 ff ff ff       	jmp    400c60 <.plt>

0000000000400d30 <read@plt>:
  400d30:	ff 25 42 b3 60 00    	jmp    *0x60b342(%rip)        # a0c078 <read@GLIBC_2.2.5>
  400d36:	68 0c 00 00 00       	push   $0xc
  400d3b:	e9 20 ff ff ff       	jmp    400c60 <.plt>

0000000000400d40 <signal@plt>:
  400d40:	ff 25 3a b3 60 00    	jmp    *0x60b33a(%rip)        # a0c080 <signal@GLIBC_2.2.5>
  400d46:	68 0d 00 00 00       	push   $0xd
  400d4b:	e9 10 ff ff ff       	jmp    400c60 <.plt>

0000000000400d50 <gethostbyname@plt>:
  400d50:	ff 25 32 b3 60 00    	jmp    *0x60b332(%rip)        # a0c088 <gethostbyname@GLIBC_2.2.5>
  400d56:	68 0e 00 00 00       	push   $0xe
  400d5b:	e9 00 ff ff ff       	jmp    400c60 <.plt>

0000000000400d60 <__memmove_chk@plt>:
  400d60:	ff 25 2a b3 60 00    	jmp    *0x60b32a(%rip)        # a0c090 <__memmove_chk@GLIBC_2.3.4>
  400d66:	68 0f 00 00 00       	push   $0xf
  400d6b:	e9 f0 fe ff ff       	jmp    400c60 <.plt>

0000000000400d70 <strtol@plt>:
  400d70:	ff 25 22 b3 60 00    	jmp    *0x60b322(%rip)        # a0c098 <strtol@GLIBC_2.2.5>
  400d76:	68 10 00 00 00       	push   $0x10
  400d7b:	e9 e0 fe ff ff       	jmp    400c60 <.plt>

0000000000400d80 <memcpy@plt>:
  400d80:	ff 25 1a b3 60 00    	jmp    *0x60b31a(%rip)        # a0c0a0 <memcpy@GLIBC_2.14>
  400d86:	68 11 00 00 00       	push   $0x11
  400d8b:	e9 d0 fe ff ff       	jmp    400c60 <.plt>

0000000000400d90 <time@plt>:
  400d90:	ff 25 12 b3 60 00    	jmp    *0x60b312(%rip)        # a0c0a8 <time@GLIBC_2.2.5>
  400d96:	68 12 00 00 00       	push   $0x12
  400d9b:	e9 c0 fe ff ff       	jmp    400c60 <.plt>

0000000000400da0 <random@plt>:
  400da0:	ff 25 0a b3 60 00    	jmp    *0x60b30a(%rip)        # a0c0b0 <random@GLIBC_2.2.5>
  400da6:	68 13 00 00 00       	push   $0x13
  400dab:	e9 b0 fe ff ff       	jmp    400c60 <.plt>

0000000000400db0 <_IO_getc@plt>:
  400db0:	ff 25 02 b3 60 00    	jmp    *0x60b302(%rip)        # a0c0b8 <_IO_getc@GLIBC_2.2.5>
  400db6:	68 14 00 00 00       	push   $0x14
  400dbb:	e9 a0 fe ff ff       	jmp    400c60 <.plt>

0000000000400dc0 <__isoc99_sscanf@plt>:
  400dc0:	ff 25 fa b2 60 00    	jmp    *0x60b2fa(%rip)        # a0c0c0 <__isoc99_sscanf@GLIBC_2.7>
  400dc6:	68 15 00 00 00       	push   $0x15
  400dcb:	e9 90 fe ff ff       	jmp    400c60 <.plt>

0000000000400dd0 <munmap@plt>:
  400dd0:	ff 25 f2 b2 60 00    	jmp    *0x60b2f2(%rip)        # a0c0c8 <munmap@GLIBC_2.2.5>
  400dd6:	68 16 00 00 00       	push   $0x16
  400ddb:	e9 80 fe ff ff       	jmp    400c60 <.plt>

0000000000400de0 <__printf_chk@plt>:
  400de0:	ff 25 ea b2 60 00    	jmp    *0x60b2ea(%rip)        # a0c0d0 <__printf_chk@GLIBC_2.3.4>
  400de6:	68 17 00 00 00       	push   $0x17
  400deb:	e9 70 fe ff ff       	jmp    400c60 <.plt>

0000000000400df0 <fopen@plt>:
  400df0:	ff 25 e2 b2 60 00    	jmp    *0x60b2e2(%rip)        # a0c0d8 <fopen@GLIBC_2.2.5>
  400df6:	68 18 00 00 00       	push   $0x18
  400dfb:	e9 60 fe ff ff       	jmp    400c60 <.plt>

0000000000400e00 <getopt@plt>:
  400e00:	ff 25 da b2 60 00    	jmp    *0x60b2da(%rip)        # a0c0e0 <getopt@GLIBC_2.2.5>
  400e06:	68 19 00 00 00       	push   $0x19
  400e0b:	e9 50 fe ff ff       	jmp    400c60 <.plt>

0000000000400e10 <strtoul@plt>:
  400e10:	ff 25 d2 b2 60 00    	jmp    *0x60b2d2(%rip)        # a0c0e8 <strtoul@GLIBC_2.2.5>
  400e16:	68 1a 00 00 00       	push   $0x1a
  400e1b:	e9 40 fe ff ff       	jmp    400c60 <.plt>

0000000000400e20 <exit@plt>:
  400e20:	ff 25 ca b2 60 00    	jmp    *0x60b2ca(%rip)        # a0c0f0 <exit@GLIBC_2.2.5>
  400e26:	68 1b 00 00 00       	push   $0x1b
  400e2b:	e9 30 fe ff ff       	jmp    400c60 <.plt>

0000000000400e30 <connect@plt>:
  400e30:	ff 25 c2 b2 60 00    	jmp    *0x60b2c2(%rip)        # a0c0f8 <connect@GLIBC_2.2.5>
  400e36:	68 1c 00 00 00       	push   $0x1c
  400e3b:	e9 20 fe ff ff       	jmp    400c60 <.plt>

0000000000400e40 <__fprintf_chk@plt>:
  400e40:	ff 25 ba b2 60 00    	jmp    *0x60b2ba(%rip)        # a0c100 <__fprintf_chk@GLIBC_2.3.4>
  400e46:	68 1d 00 00 00       	push   $0x1d
  400e4b:	e9 10 fe ff ff       	jmp    400c60 <.plt>

0000000000400e50 <__sprintf_chk@plt>:
  400e50:	ff 25 b2 b2 60 00    	jmp    *0x60b2b2(%rip)        # a0c108 <__sprintf_chk@GLIBC_2.3.4>
  400e56:	68 1e 00 00 00       	push   $0x1e
  400e5b:	e9 00 fe ff ff       	jmp    400c60 <.plt>

0000000000400e60 <socket@plt>:
  400e60:	ff 25 aa b2 60 00    	jmp    *0x60b2aa(%rip)        # a0c110 <socket@GLIBC_2.2.5>
  400e66:	68 1f 00 00 00       	push   $0x1f
  400e6b:	e9 f0 fd ff ff       	jmp    400c60 <.plt>

Disassembly of section .fini:

000000000080a1e4 <_fini>:
  80a1e4:	48 83 ec 08          	sub    $0x8,%rsp
  80a1e8:	48 83 c4 08          	add    $0x8,%rsp
  80a1ec:	c3                   	ret
