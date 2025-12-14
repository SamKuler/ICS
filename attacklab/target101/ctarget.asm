
ctarget：     文件格式 elf64-x86-64


Disassembly of section .text:

0000000000808000 <_start>:
  808000:	31 ed                	xor    %ebp,%ebp
  808002:	49 89 d1             	mov    %rdx,%r9
  808005:	5e                   	pop    %rsi
  808006:	48 89 e2             	mov    %rsp,%rdx
  808009:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  80800d:	50                   	push   %rax
  80800e:	54                   	push   %rsp
  80800f:	49 c7 c0 c0 a0 80 00 	mov    $0x80a0c0,%r8
  808016:	48 c7 c1 50 a0 80 00 	mov    $0x80a050,%rcx
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
  8080f7:	48 8d 35 da 1f 00 00 	lea    0x1fda(%rip),%rsi        # 80a0d8 <_IO_stdin_used+0x8>
  8080fe:	bf 01 00 00 00       	mov    $0x1,%edi
  808103:	b8 00 00 00 00       	mov    $0x0,%eax
  808108:	e8 d3 8c bf ff       	call   400de0 <__printf_chk@plt>
  80810d:	48 8d 3d fc 1f 00 00 	lea    0x1ffc(%rip),%rdi        # 80a110 <_IO_stdin_used+0x40>
  808114:	e8 a7 8b bf ff       	call   400cc0 <puts@plt>
  808119:	48 8d 3d f0 20 00 00 	lea    0x20f0(%rip),%rdi        # 80a210 <_IO_stdin_used+0x140>
  808120:	e8 9b 8b bf ff       	call   400cc0 <puts@plt>
  808125:	48 8d 3d 0c 20 00 00 	lea    0x200c(%rip),%rdi        # 80a138 <_IO_stdin_used+0x68>
  80812c:	e8 8f 8b bf ff       	call   400cc0 <puts@plt>
  808131:	48 8d 3d f2 20 00 00 	lea    0x20f2(%rip),%rdi        # 80a22a <_IO_stdin_used+0x15a>
  808138:	e8 83 8b bf ff       	call   400cc0 <puts@plt>
  80813d:	bf 00 00 00 00       	mov    $0x0,%edi
  808142:	e8 d9 8c bf ff       	call   400e20 <exit@plt>
  808147:	48 8d 35 f8 20 00 00 	lea    0x20f8(%rip),%rsi        # 80a246 <_IO_stdin_used+0x176>
  80814e:	bf 01 00 00 00       	mov    $0x1,%edi
  808153:	b8 00 00 00 00       	mov    $0x0,%eax
  808158:	e8 83 8c bf ff       	call   400de0 <__printf_chk@plt>
  80815d:	48 8d 3d fc 1f 00 00 	lea    0x1ffc(%rip),%rdi        # 80a160 <_IO_stdin_used+0x90>
  808164:	e8 57 8b bf ff       	call   400cc0 <puts@plt>
  808169:	48 8d 3d 18 20 00 00 	lea    0x2018(%rip),%rdi        # 80a188 <_IO_stdin_used+0xb8>
  808170:	e8 4b 8b bf ff       	call   400cc0 <puts@plt>
  808175:	48 8d 3d e8 20 00 00 	lea    0x20e8(%rip),%rdi        # 80a264 <_IO_stdin_used+0x194>
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
  8081ad:	e8 7c 1e 00 00       	call   80a02e <gencookie>
  8081b2:	89 05 4c 43 20 00    	mov    %eax,0x20434c(%rip)        # a0c504 <cookie>
  8081b8:	89 c7                	mov    %eax,%edi
  8081ba:	e8 6f 1e 00 00       	call   80a02e <gencookie>
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
  8081ff:	c6 05 2a 4f 20 00 63 	movb   $0x63,0x204f2a(%rip)        # a0d130 <target_prefix>
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
  808250:	e8 09 1b 00 00       	call   809d5e <init_driver>
  808255:	85 c0                	test   %eax,%eax
  808257:	79 bf                	jns    808218 <initialize_target+0x95>
  808259:	48 89 e2             	mov    %rsp,%rdx
  80825c:	48 8d 35 55 1f 00 00 	lea    0x1f55(%rip),%rsi        # 80a1b8 <_IO_stdin_used+0xe8>
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
  80828f:	48 c7 c6 65 90 80 00 	mov    $0x809065,%rsi
  808296:	bf 0b 00 00 00       	mov    $0xb,%edi
  80829b:	e8 a0 8a bf ff       	call   400d40 <signal@plt>
  8082a0:	48 c7 c6 11 90 80 00 	mov    $0x809011,%rsi
  8082a7:	bf 07 00 00 00       	mov    $0x7,%edi
  8082ac:	e8 8f 8a bf ff       	call   400d40 <signal@plt>
  8082b1:	48 c7 c6 b9 90 80 00 	mov    $0x8090b9,%rsi
  8082b8:	bf 04 00 00 00       	mov    $0x4,%edi
  8082bd:	e8 7e 8a bf ff       	call   400d40 <signal@plt>
  8082c2:	83 3d 3f 42 20 00 00 	cmpl   $0x0,0x20423f(%rip)        # a0c508 <is_checker>
  8082c9:	75 26                	jne    8082f1 <main+0x70>
  8082cb:	48 8d 2d ab 1f 00 00 	lea    0x1fab(%rip),%rbp        # 80a27d <_IO_stdin_used+0x1ad>
  8082d2:	48 8b 05 c7 41 20 00 	mov    0x2041c7(%rip),%rax        # a0c4a0 <stdin@GLIBC_2.2.5>
  8082d9:	48 89 05 10 42 20 00 	mov    %rax,0x204210(%rip)        # a0c4f0 <infile>
  8082e0:	41 bd 00 00 00 00    	mov    $0x0,%r13d
  8082e6:	41 be 00 00 00 00    	mov    $0x0,%r14d
  8082ec:	e9 8d 00 00 00       	jmp    80837e <main+0xfd>
  8082f1:	48 c7 c6 0d 91 80 00 	mov    $0x80910d,%rsi
  8082f8:	bf 0e 00 00 00       	mov    $0xe,%edi
  8082fd:	e8 3e 8a bf ff       	call   400d40 <signal@plt>
  808302:	bf 05 00 00 00       	mov    $0x5,%edi
  808307:	e8 04 8a bf ff       	call   400d10 <alarm@plt>
  80830c:	48 8d 2d 6f 1f 00 00 	lea    0x1f6f(%rip),%rbp        # 80a282 <_IO_stdin_used+0x1b2>
  808313:	eb bd                	jmp    8082d2 <main+0x51>
  808315:	48 8b 3b             	mov    (%rbx),%rdi
  808318:	e8 ca fd ff ff       	call   8080e7 <usage>
  80831d:	48 8d 35 d1 21 00 00 	lea    0x21d1(%rip),%rsi        # 80a4f5 <_IO_stdin_used+0x425>
  808324:	48 8b 3d 7d 41 20 00 	mov    0x20417d(%rip),%rdi        # a0c4a8 <optarg@GLIBC_2.2.5>
  80832b:	e8 c0 8a bf ff       	call   400df0 <fopen@plt>
  808330:	48 89 05 b9 41 20 00 	mov    %rax,0x2041b9(%rip)        # a0c4f0 <infile>
  808337:	48 85 c0             	test   %rax,%rax
  80833a:	75 42                	jne    80837e <main+0xfd>
  80833c:	48 8b 0d 65 41 20 00 	mov    0x204165(%rip),%rcx        # a0c4a8 <optarg@GLIBC_2.2.5>
  808343:	48 8d 15 40 1f 00 00 	lea    0x1f40(%rip),%rdx        # 80a28a <_IO_stdin_used+0x1ba>
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
  80839d:	48 8d 0d 24 1f 00 00 	lea    0x1f24(%rip),%rcx        # 80a2c8 <_IO_stdin_used+0x1f8>
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
  8083d4:	48 8d 35 cc 1e 00 00 	lea    0x1ecc(%rip),%rsi        # 80a2a7 <_IO_stdin_used+0x1d7>
  8083db:	bf 01 00 00 00       	mov    $0x1,%edi
  8083e0:	b8 00 00 00 00       	mov    $0x0,%eax
  8083e5:	e8 f6 89 bf ff       	call   400de0 <__printf_chk@plt>
  8083ea:	48 8b 3b             	mov    (%rbx),%rdi
  8083ed:	e8 f5 fc ff ff       	call   8080e7 <usage>
  8083f2:	be 00 00 00 00       	mov    $0x0,%esi
  8083f7:	44 89 ef             	mov    %r13d,%edi
  8083fa:	e8 84 fd ff ff       	call   808183 <initialize_target>
  8083ff:	83 3d 02 41 20 00 00 	cmpl   $0x0,0x204102(%rip)        # a0c508 <is_checker>
  808406:	74 09                	je     808411 <main+0x190>
  808408:	44 39 35 f1 40 20 00 	cmp    %r14d,0x2040f1(%rip)        # a0c500 <authkey>
  80840f:	75 36                	jne    808447 <main+0x1c6>
  808411:	8b 15 ed 40 20 00    	mov    0x2040ed(%rip),%edx        # a0c504 <cookie>
  808417:	48 8d 35 9c 1e 00 00 	lea    0x1e9c(%rip),%rsi        # 80a2ba <_IO_stdin_used+0x1ea>
  80841e:	bf 01 00 00 00       	mov    $0x1,%edi
  808423:	b8 00 00 00 00       	mov    $0x0,%eax
  808428:	e8 b3 89 bf ff       	call   400de0 <__printf_chk@plt>
  80842d:	48 8b 3d 5c 40 20 00 	mov    0x20405c(%rip),%rdi        # a0c490 <buf_offset>
  808434:	e8 e0 0d 00 00       	call   809219 <stable_launch>
  808439:	b8 00 00 00 00       	mov    $0x0,%eax
  80843e:	5b                   	pop    %rbx
  80843f:	5d                   	pop    %rbp
  808440:	41 5c                	pop    %r12
  808442:	41 5d                	pop    %r13
  808444:	41 5e                	pop    %r14
  808446:	c3                   	ret
  808447:	44 89 f2             	mov    %r14d,%edx
  80844a:	48 8d 35 8f 1d 00 00 	lea    0x1d8f(%rip),%rsi        # 80a1e0 <_IO_stdin_used+0x110>
  808451:	bf 01 00 00 00       	mov    $0x1,%edi
  808456:	b8 00 00 00 00       	mov    $0x0,%eax
  80845b:	e8 80 89 bf ff       	call   400de0 <__printf_chk@plt>
  808460:	b8 00 00 00 00       	mov    $0x0,%eax
  808465:	e8 00 08 00 00       	call   808c6a <check_fail>
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
  808a09:	e8 94 02 00 00       	call   808ca2 <Gets>
  808a0e:	b8 01 00 00 00       	mov    $0x1,%eax
  808a13:	48 83 c4 38          	add    $0x38,%rsp
  808a17:	c3                   	ret

0000000000808a18 <touch1>:
  808a18:	48 83 ec 08          	sub    $0x8,%rsp
  808a1c:	c7 05 d6 3a 20 00 01 	movl   $0x1,0x203ad6(%rip)        # a0c4fc <vlevel>
  808a23:	00 00 00 
  808a26:	48 8d 3d 1e 19 00 00 	lea    0x191e(%rip),%rdi        # 80a34b <_IO_stdin_used+0x27b>
  808a2d:	e8 8e 82 bf ff       	call   400cc0 <puts@plt>
  808a32:	bf 01 00 00 00       	mov    $0x1,%edi
  808a37:	e8 dd 04 00 00       	call   808f19 <validate>
  808a3c:	bf 00 00 00 00       	mov    $0x0,%edi
  808a41:	e8 da 83 bf ff       	call   400e20 <exit@plt>

0000000000808a46 <touch2>:
  808a46:	48 83 ec 08          	sub    $0x8,%rsp
  808a4a:	89 fa                	mov    %edi,%edx
  808a4c:	c7 05 a6 3a 20 00 02 	movl   $0x2,0x203aa6(%rip)        # a0c4fc <vlevel>
  808a53:	00 00 00 
  808a56:	39 3d a8 3a 20 00    	cmp    %edi,0x203aa8(%rip)        # a0c504 <cookie>
  808a5c:	74 2a                	je     808a88 <touch2+0x42>
  808a5e:	48 8d 35 33 19 00 00 	lea    0x1933(%rip),%rsi        # 80a398 <_IO_stdin_used+0x2c8>
  808a65:	bf 01 00 00 00       	mov    $0x1,%edi
  808a6a:	b8 00 00 00 00       	mov    $0x0,%eax
  808a6f:	e8 6c 83 bf ff       	call   400de0 <__printf_chk@plt>
  808a74:	bf 02 00 00 00       	mov    $0x2,%edi
  808a79:	e8 6b 05 00 00       	call   808fe9 <fail>
  808a7e:	bf 00 00 00 00       	mov    $0x0,%edi
  808a83:	e8 98 83 bf ff       	call   400e20 <exit@plt>
  808a88:	48 8d 35 e1 18 00 00 	lea    0x18e1(%rip),%rsi        # 80a370 <_IO_stdin_used+0x2a0>
  808a8f:	bf 01 00 00 00       	mov    $0x1,%edi
  808a94:	b8 00 00 00 00       	mov    $0x0,%eax
  808a99:	e8 42 83 bf ff       	call   400de0 <__printf_chk@plt>
  808a9e:	bf 02 00 00 00       	mov    $0x2,%edi
  808aa3:	e8 71 04 00 00       	call   808f19 <validate>
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
  808b07:	48 8d 0d 5a 18 00 00 	lea    0x185a(%rip),%rcx        # 80a368 <_IO_stdin_used+0x298>
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
  808b80:	48 8d 35 39 18 00 00 	lea    0x1839(%rip),%rsi        # 80a3c0 <_IO_stdin_used+0x2f0>
  808b87:	bf 01 00 00 00       	mov    $0x1,%edi
  808b8c:	b8 00 00 00 00       	mov    $0x0,%eax
  808b91:	e8 4a 82 bf ff       	call   400de0 <__printf_chk@plt>
  808b96:	bf 03 00 00 00       	mov    $0x3,%edi
  808b9b:	e8 79 03 00 00       	call   808f19 <validate>
  808ba0:	bf 00 00 00 00       	mov    $0x0,%edi
  808ba5:	e8 76 82 bf ff       	call   400e20 <exit@plt>
  808baa:	48 89 da             	mov    %rbx,%rdx
  808bad:	48 8d 35 34 18 00 00 	lea    0x1834(%rip),%rsi        # 80a3e8 <_IO_stdin_used+0x318>
  808bb4:	bf 01 00 00 00       	mov    $0x1,%edi
  808bb9:	b8 00 00 00 00       	mov    $0x0,%eax
  808bbe:	e8 1d 82 bf ff       	call   400de0 <__printf_chk@plt>
  808bc3:	bf 03 00 00 00       	mov    $0x3,%edi
  808bc8:	e8 1c 04 00 00       	call   808fe9 <fail>
  808bcd:	eb d1                	jmp    808ba0 <touch3+0x43>

0000000000808bcf <test>:
  808bcf:	48 83 ec 08          	sub    $0x8,%rsp
  808bd3:	b8 00 00 00 00       	mov    $0x0,%eax
  808bd8:	e8 25 fe ff ff       	call   808a02 <getbuf>
  808bdd:	89 c2                	mov    %eax,%edx
  808bdf:	48 8d 35 2a 18 00 00 	lea    0x182a(%rip),%rsi        # 80a410 <_IO_stdin_used+0x340>
  808be6:	bf 01 00 00 00       	mov    $0x1,%edi
  808beb:	b8 00 00 00 00       	mov    $0x0,%eax
  808bf0:	e8 eb 81 bf ff       	call   400de0 <__printf_chk@plt>
  808bf5:	48 83 c4 08          	add    $0x8,%rsp
  808bf9:	c3                   	ret

0000000000808bfa <save_char>:
  808bfa:	8b 05 24 45 20 00    	mov    0x204524(%rip),%eax        # a0d124 <gets_cnt>
  808c00:	3d ff 03 00 00       	cmp    $0x3ff,%eax
  808c05:	7f 4a                	jg     808c51 <save_char+0x57>
  808c07:	89 f9                	mov    %edi,%ecx
  808c09:	c0 e9 04             	shr    $0x4,%cl
  808c0c:	8d 14 40             	lea    (%rax,%rax,2),%edx
  808c0f:	4c 8d 05 1a 1b 00 00 	lea    0x1b1a(%rip),%r8        # 80a730 <trans_char>
  808c16:	83 e1 0f             	and    $0xf,%ecx
  808c19:	45 0f b6 0c 08       	movzbl (%r8,%rcx,1),%r9d
  808c1e:	48 8d 0d fb 38 20 00 	lea    0x2038fb(%rip),%rcx        # a0c520 <gets_buf>
  808c25:	48 63 f2             	movslq %edx,%rsi
  808c28:	44 88 0c 31          	mov    %r9b,(%rcx,%rsi,1)
  808c2c:	8d 72 01             	lea    0x1(%rdx),%esi
  808c2f:	83 e7 0f             	and    $0xf,%edi
  808c32:	41 0f b6 3c 38       	movzbl (%r8,%rdi,1),%edi
  808c37:	48 63 f6             	movslq %esi,%rsi
  808c3a:	40 88 3c 31          	mov    %dil,(%rcx,%rsi,1)
  808c3e:	83 c2 02             	add    $0x2,%edx
  808c41:	48 63 d2             	movslq %edx,%rdx
  808c44:	c6 04 11 20          	movb   $0x20,(%rcx,%rdx,1)
  808c48:	83 c0 01             	add    $0x1,%eax
  808c4b:	89 05 d3 44 20 00    	mov    %eax,0x2044d3(%rip)        # a0d124 <gets_cnt>
  808c51:	f3 c3                	repz ret

0000000000808c53 <save_term>:
  808c53:	8b 05 cb 44 20 00    	mov    0x2044cb(%rip),%eax        # a0d124 <gets_cnt>
  808c59:	8d 04 40             	lea    (%rax,%rax,2),%eax
  808c5c:	48 98                	cltq
  808c5e:	48 8d 15 bb 38 20 00 	lea    0x2038bb(%rip),%rdx        # a0c520 <gets_buf>
  808c65:	c6 04 02 00          	movb   $0x0,(%rdx,%rax,1)
  808c69:	c3                   	ret

0000000000808c6a <check_fail>:
  808c6a:	48 83 ec 08          	sub    $0x8,%rsp
  808c6e:	0f be 15 bb 44 20 00 	movsbl 0x2044bb(%rip),%edx        # a0d130 <target_prefix>
  808c75:	4c 8d 05 a4 38 20 00 	lea    0x2038a4(%rip),%r8        # a0c520 <gets_buf>
  808c7c:	8b 0d 76 38 20 00    	mov    0x203876(%rip),%ecx        # a0c4f8 <check_level>
  808c82:	48 8d 35 aa 17 00 00 	lea    0x17aa(%rip),%rsi        # 80a433 <_IO_stdin_used+0x363>
  808c89:	bf 01 00 00 00       	mov    $0x1,%edi
  808c8e:	b8 00 00 00 00       	mov    $0x0,%eax
  808c93:	e8 48 81 bf ff       	call   400de0 <__printf_chk@plt>
  808c98:	bf 01 00 00 00       	mov    $0x1,%edi
  808c9d:	e8 7e 81 bf ff       	call   400e20 <exit@plt>

0000000000808ca2 <Gets>:
  808ca2:	41 54                	push   %r12
  808ca4:	55                   	push   %rbp
  808ca5:	53                   	push   %rbx
  808ca6:	49 89 fc             	mov    %rdi,%r12
  808ca9:	c7 05 71 44 20 00 00 	movl   $0x0,0x204471(%rip)        # a0d124 <gets_cnt>
  808cb0:	00 00 00 
  808cb3:	48 89 fb             	mov    %rdi,%rbx
  808cb6:	eb 11                	jmp    808cc9 <Gets+0x27>
  808cb8:	48 8d 6b 01          	lea    0x1(%rbx),%rbp
  808cbc:	88 03                	mov    %al,(%rbx)
  808cbe:	0f b6 f8             	movzbl %al,%edi
  808cc1:	e8 34 ff ff ff       	call   808bfa <save_char>
  808cc6:	48 89 eb             	mov    %rbp,%rbx
  808cc9:	48 8b 3d 20 38 20 00 	mov    0x203820(%rip),%rdi        # a0c4f0 <infile>
  808cd0:	e8 db 80 bf ff       	call   400db0 <_IO_getc@plt>
  808cd5:	83 f8 ff             	cmp    $0xffffffff,%eax
  808cd8:	74 05                	je     808cdf <Gets+0x3d>
  808cda:	83 f8 0a             	cmp    $0xa,%eax
  808cdd:	75 d9                	jne    808cb8 <Gets+0x16>
  808cdf:	c6 03 00             	movb   $0x0,(%rbx)
  808ce2:	b8 00 00 00 00       	mov    $0x0,%eax
  808ce7:	e8 67 ff ff ff       	call   808c53 <save_term>
  808cec:	4c 89 e0             	mov    %r12,%rax
  808cef:	5b                   	pop    %rbx
  808cf0:	5d                   	pop    %rbp
  808cf1:	41 5c                	pop    %r12
  808cf3:	c3                   	ret

0000000000808cf4 <notify_server>:
  808cf4:	55                   	push   %rbp
  808cf5:	53                   	push   %rbx
  808cf6:	48 81 ec 18 40 00 00 	sub    $0x4018,%rsp
  808cfd:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  808d04:	00 00 
  808d06:	48 89 84 24 08 40 00 	mov    %rax,0x4008(%rsp)
  808d0d:	00 
  808d0e:	31 c0                	xor    %eax,%eax
  808d10:	83 3d f1 37 20 00 00 	cmpl   $0x0,0x2037f1(%rip)        # a0c508 <is_checker>
  808d17:	0f 85 d9 00 00 00    	jne    808df6 <notify_server+0x102>
  808d1d:	89 fb                	mov    %edi,%ebx
  808d1f:	8b 05 ff 43 20 00    	mov    0x2043ff(%rip),%eax        # a0d124 <gets_cnt>
  808d25:	83 c0 64             	add    $0x64,%eax
  808d28:	3d 00 20 00 00       	cmp    $0x2000,%eax
  808d2d:	0f 8f e4 00 00 00    	jg     808e17 <notify_server+0x123>
  808d33:	0f be 05 f6 43 20 00 	movsbl 0x2043f6(%rip),%eax        # a0d130 <target_prefix>
  808d3a:	83 3d 47 37 20 00 00 	cmpl   $0x0,0x203747(%rip)        # a0c488 <notify>
  808d41:	0f 84 f0 00 00 00    	je     808e37 <notify_server+0x143>
  808d47:	8b 15 b3 37 20 00    	mov    0x2037b3(%rip),%edx        # a0c500 <authkey>
  808d4d:	85 db                	test   %ebx,%ebx
  808d4f:	0f 84 ec 00 00 00    	je     808e41 <notify_server+0x14d>
  808d55:	48 8d 2d ed 16 00 00 	lea    0x16ed(%rip),%rbp        # 80a449 <_IO_stdin_used+0x379>
  808d5c:	48 89 e7             	mov    %rsp,%rdi
  808d5f:	48 83 ec 08          	sub    $0x8,%rsp
  808d63:	48 8d 0d b6 37 20 00 	lea    0x2037b6(%rip),%rcx        # a0c520 <gets_buf>
  808d6a:	51                   	push   %rcx
  808d6b:	56                   	push   %rsi
  808d6c:	50                   	push   %rax
  808d6d:	52                   	push   %rdx
  808d6e:	55                   	push   %rbp
  808d6f:	44 8b 0d ba 33 20 00 	mov    0x2033ba(%rip),%r9d        # a0c130 <target_id>
  808d76:	4c 8d 05 d6 16 00 00 	lea    0x16d6(%rip),%r8        # 80a453 <_IO_stdin_used+0x383>
  808d7d:	b9 00 20 00 00       	mov    $0x2000,%ecx
  808d82:	ba 01 00 00 00       	mov    $0x1,%edx
  808d87:	be 00 20 00 00       	mov    $0x2000,%esi
  808d8c:	b8 00 00 00 00       	mov    $0x0,%eax
  808d91:	e8 da 7e bf ff       	call   400c70 <__snprintf_chk@plt>
  808d96:	48 83 c4 30          	add    $0x30,%rsp
  808d9a:	83 3d e7 36 20 00 00 	cmpl   $0x0,0x2036e7(%rip)        # a0c488 <notify>
  808da1:	0f 84 df 00 00 00    	je     808e86 <notify_server+0x192>
  808da7:	85 db                	test   %ebx,%ebx
  808da9:	0f 84 c6 00 00 00    	je     808e75 <notify_server+0x181>
  808daf:	48 89 e1             	mov    %rsp,%rcx
  808db2:	4c 8d 8c 24 00 20 00 	lea    0x2000(%rsp),%r9
  808db9:	00 
  808dba:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  808dc0:	48 8b 15 81 33 20 00 	mov    0x203381(%rip),%rdx        # a0c148 <lab>
  808dc7:	48 8b 35 b2 36 20 00 	mov    0x2036b2(%rip),%rsi        # a0c480 <course>
  808dce:	48 8b 3d 6b 33 20 00 	mov    0x20336b(%rip),%rdi        # a0c140 <user_id>
  808dd5:	e8 af 11 00 00       	call   809f89 <driver_post>
  808dda:	85 c0                	test   %eax,%eax
  808ddc:	78 6f                	js     808e4d <notify_server+0x159>
  808dde:	48 8d 3d b3 17 00 00 	lea    0x17b3(%rip),%rdi        # 80a598 <_IO_stdin_used+0x4c8>
  808de5:	e8 d6 7e bf ff       	call   400cc0 <puts@plt>
  808dea:	48 8d 3d 8a 16 00 00 	lea    0x168a(%rip),%rdi        # 80a47b <_IO_stdin_used+0x3ab>
  808df1:	e8 ca 7e bf ff       	call   400cc0 <puts@plt>
  808df6:	48 8b 84 24 08 40 00 	mov    0x4008(%rsp),%rax
  808dfd:	00 
  808dfe:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  808e05:	00 00 
  808e07:	0f 85 07 01 00 00    	jne    808f14 <notify_server+0x220>
  808e0d:	48 81 c4 18 40 00 00 	add    $0x4018,%rsp
  808e14:	5b                   	pop    %rbx
  808e15:	5d                   	pop    %rbp
  808e16:	c3                   	ret
  808e17:	48 8d 35 4a 17 00 00 	lea    0x174a(%rip),%rsi        # 80a568 <_IO_stdin_used+0x498>
  808e1e:	bf 01 00 00 00       	mov    $0x1,%edi
  808e23:	b8 00 00 00 00       	mov    $0x0,%eax
  808e28:	e8 b3 7f bf ff       	call   400de0 <__printf_chk@plt>
  808e2d:	bf 01 00 00 00       	mov    $0x1,%edi
  808e32:	e8 e9 7f bf ff       	call   400e20 <exit@plt>
  808e37:	ba ff ff ff ff       	mov    $0xffffffff,%edx
  808e3c:	e9 0c ff ff ff       	jmp    808d4d <notify_server+0x59>
  808e41:	48 8d 2d 06 16 00 00 	lea    0x1606(%rip),%rbp        # 80a44e <_IO_stdin_used+0x37e>
  808e48:	e9 0f ff ff ff       	jmp    808d5c <notify_server+0x68>
  808e4d:	48 8d 94 24 00 20 00 	lea    0x2000(%rsp),%rdx
  808e54:	00 
  808e55:	48 8d 35 13 16 00 00 	lea    0x1613(%rip),%rsi        # 80a46f <_IO_stdin_used+0x39f>
  808e5c:	bf 01 00 00 00       	mov    $0x1,%edi
  808e61:	b8 00 00 00 00       	mov    $0x0,%eax
  808e66:	e8 75 7f bf ff       	call   400de0 <__printf_chk@plt>
  808e6b:	bf 01 00 00 00       	mov    $0x1,%edi
  808e70:	e8 ab 7f bf ff       	call   400e20 <exit@plt>
  808e75:	48 8d 3d 09 16 00 00 	lea    0x1609(%rip),%rdi        # 80a485 <_IO_stdin_used+0x3b5>
  808e7c:	e8 3f 7e bf ff       	call   400cc0 <puts@plt>
  808e81:	e9 70 ff ff ff       	jmp    808df6 <notify_server+0x102>
  808e86:	48 89 ea             	mov    %rbp,%rdx
  808e89:	48 8d 35 40 17 00 00 	lea    0x1740(%rip),%rsi        # 80a5d0 <_IO_stdin_used+0x500>
  808e90:	bf 01 00 00 00       	mov    $0x1,%edi
  808e95:	b8 00 00 00 00       	mov    $0x0,%eax
  808e9a:	e8 41 7f bf ff       	call   400de0 <__printf_chk@plt>
  808e9f:	48 8b 15 9a 32 20 00 	mov    0x20329a(%rip),%rdx        # a0c140 <user_id>
  808ea6:	48 8d 35 df 15 00 00 	lea    0x15df(%rip),%rsi        # 80a48c <_IO_stdin_used+0x3bc>
  808ead:	bf 01 00 00 00       	mov    $0x1,%edi
  808eb2:	b8 00 00 00 00       	mov    $0x0,%eax
  808eb7:	e8 24 7f bf ff       	call   400de0 <__printf_chk@plt>
  808ebc:	48 8b 15 bd 35 20 00 	mov    0x2035bd(%rip),%rdx        # a0c480 <course>
  808ec3:	48 8d 35 cf 15 00 00 	lea    0x15cf(%rip),%rsi        # 80a499 <_IO_stdin_used+0x3c9>
  808eca:	bf 01 00 00 00       	mov    $0x1,%edi
  808ecf:	b8 00 00 00 00       	mov    $0x0,%eax
  808ed4:	e8 07 7f bf ff       	call   400de0 <__printf_chk@plt>
  808ed9:	48 8b 15 68 32 20 00 	mov    0x203268(%rip),%rdx        # a0c148 <lab>
  808ee0:	48 8d 35 be 15 00 00 	lea    0x15be(%rip),%rsi        # 80a4a5 <_IO_stdin_used+0x3d5>
  808ee7:	bf 01 00 00 00       	mov    $0x1,%edi
  808eec:	b8 00 00 00 00       	mov    $0x0,%eax
  808ef1:	e8 ea 7e bf ff       	call   400de0 <__printf_chk@plt>
  808ef6:	48 89 e2             	mov    %rsp,%rdx
  808ef9:	48 8d 35 ae 15 00 00 	lea    0x15ae(%rip),%rsi        # 80a4ae <_IO_stdin_used+0x3de>
  808f00:	bf 01 00 00 00       	mov    $0x1,%edi
  808f05:	b8 00 00 00 00       	mov    $0x0,%eax
  808f0a:	e8 d1 7e bf ff       	call   400de0 <__printf_chk@plt>
  808f0f:	e9 e2 fe ff ff       	jmp    808df6 <notify_server+0x102>
  808f14:	e8 c7 7d bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000808f19 <validate>:
  808f19:	53                   	push   %rbx
  808f1a:	89 fb                	mov    %edi,%ebx
  808f1c:	83 3d e5 35 20 00 00 	cmpl   $0x0,0x2035e5(%rip)        # a0c508 <is_checker>
  808f23:	74 72                	je     808f97 <validate+0x7e>
  808f25:	39 3d d1 35 20 00    	cmp    %edi,0x2035d1(%rip)        # a0c4fc <vlevel>
  808f2b:	75 32                	jne    808f5f <validate+0x46>
  808f2d:	8b 15 c5 35 20 00    	mov    0x2035c5(%rip),%edx        # a0c4f8 <check_level>
  808f33:	39 fa                	cmp    %edi,%edx
  808f35:	75 3e                	jne    808f75 <validate+0x5c>
  808f37:	0f be 15 f2 41 20 00 	movsbl 0x2041f2(%rip),%edx        # a0d130 <target_prefix>
  808f3e:	4c 8d 05 db 35 20 00 	lea    0x2035db(%rip),%r8        # a0c520 <gets_buf>
  808f45:	89 f9                	mov    %edi,%ecx
  808f47:	48 8d 35 8a 15 00 00 	lea    0x158a(%rip),%rsi        # 80a4d8 <_IO_stdin_used+0x408>
  808f4e:	bf 01 00 00 00       	mov    $0x1,%edi
  808f53:	b8 00 00 00 00       	mov    $0x0,%eax
  808f58:	e8 83 7e bf ff       	call   400de0 <__printf_chk@plt>
  808f5d:	5b                   	pop    %rbx
  808f5e:	c3                   	ret
  808f5f:	48 8d 3d 54 15 00 00 	lea    0x1554(%rip),%rdi        # 80a4ba <_IO_stdin_used+0x3ea>
  808f66:	e8 55 7d bf ff       	call   400cc0 <puts@plt>
  808f6b:	b8 00 00 00 00       	mov    $0x0,%eax
  808f70:	e8 f5 fc ff ff       	call   808c6a <check_fail>
  808f75:	89 f9                	mov    %edi,%ecx
  808f77:	48 8d 35 7a 16 00 00 	lea    0x167a(%rip),%rsi        # 80a5f8 <_IO_stdin_used+0x528>
  808f7e:	bf 01 00 00 00       	mov    $0x1,%edi
  808f83:	b8 00 00 00 00       	mov    $0x0,%eax
  808f88:	e8 53 7e bf ff       	call   400de0 <__printf_chk@plt>
  808f8d:	b8 00 00 00 00       	mov    $0x0,%eax
  808f92:	e8 d3 fc ff ff       	call   808c6a <check_fail>
  808f97:	39 3d 5f 35 20 00    	cmp    %edi,0x20355f(%rip)        # a0c4fc <vlevel>
  808f9d:	74 1a                	je     808fb9 <validate+0xa0>
  808f9f:	48 8d 3d 14 15 00 00 	lea    0x1514(%rip),%rdi        # 80a4ba <_IO_stdin_used+0x3ea>
  808fa6:	e8 15 7d bf ff       	call   400cc0 <puts@plt>
  808fab:	89 de                	mov    %ebx,%esi
  808fad:	bf 00 00 00 00       	mov    $0x0,%edi
  808fb2:	e8 3d fd ff ff       	call   808cf4 <notify_server>
  808fb7:	eb a4                	jmp    808f5d <validate+0x44>
  808fb9:	0f be 0d 70 41 20 00 	movsbl 0x204170(%rip),%ecx        # a0d130 <target_prefix>
  808fc0:	89 fa                	mov    %edi,%edx
  808fc2:	48 8d 35 57 16 00 00 	lea    0x1657(%rip),%rsi        # 80a620 <_IO_stdin_used+0x550>
  808fc9:	bf 01 00 00 00       	mov    $0x1,%edi
  808fce:	b8 00 00 00 00       	mov    $0x0,%eax
  808fd3:	e8 08 7e bf ff       	call   400de0 <__printf_chk@plt>
  808fd8:	89 de                	mov    %ebx,%esi
  808fda:	bf 01 00 00 00       	mov    $0x1,%edi
  808fdf:	e8 10 fd ff ff       	call   808cf4 <notify_server>
  808fe4:	e9 74 ff ff ff       	jmp    808f5d <validate+0x44>

0000000000808fe9 <fail>:
  808fe9:	48 83 ec 08          	sub    $0x8,%rsp
  808fed:	83 3d 14 35 20 00 00 	cmpl   $0x0,0x203514(%rip)        # a0c508 <is_checker>
  808ff4:	75 11                	jne    809007 <fail+0x1e>
  808ff6:	89 fe                	mov    %edi,%esi
  808ff8:	bf 00 00 00 00       	mov    $0x0,%edi
  808ffd:	e8 f2 fc ff ff       	call   808cf4 <notify_server>
  809002:	48 83 c4 08          	add    $0x8,%rsp
  809006:	c3                   	ret
  809007:	b8 00 00 00 00       	mov    $0x0,%eax
  80900c:	e8 59 fc ff ff       	call   808c6a <check_fail>

0000000000809011 <bushandler>:
  809011:	48 83 ec 08          	sub    $0x8,%rsp
  809015:	83 3d ec 34 20 00 00 	cmpl   $0x0,0x2034ec(%rip)        # a0c508 <is_checker>
  80901c:	74 16                	je     809034 <bushandler+0x23>
  80901e:	48 8d 3d c8 14 00 00 	lea    0x14c8(%rip),%rdi        # 80a4ed <_IO_stdin_used+0x41d>
  809025:	e8 96 7c bf ff       	call   400cc0 <puts@plt>
  80902a:	b8 00 00 00 00       	mov    $0x0,%eax
  80902f:	e8 36 fc ff ff       	call   808c6a <check_fail>
  809034:	48 8d 3d 1d 16 00 00 	lea    0x161d(%rip),%rdi        # 80a658 <_IO_stdin_used+0x588>
  80903b:	e8 80 7c bf ff       	call   400cc0 <puts@plt>
  809040:	48 8d 3d b0 14 00 00 	lea    0x14b0(%rip),%rdi        # 80a4f7 <_IO_stdin_used+0x427>
  809047:	e8 74 7c bf ff       	call   400cc0 <puts@plt>
  80904c:	be 00 00 00 00       	mov    $0x0,%esi
  809051:	bf 00 00 00 00       	mov    $0x0,%edi
  809056:	e8 99 fc ff ff       	call   808cf4 <notify_server>
  80905b:	bf 01 00 00 00       	mov    $0x1,%edi
  809060:	e8 bb 7d bf ff       	call   400e20 <exit@plt>

0000000000809065 <seghandler>:
  809065:	48 83 ec 08          	sub    $0x8,%rsp
  809069:	83 3d 98 34 20 00 00 	cmpl   $0x0,0x203498(%rip)        # a0c508 <is_checker>
  809070:	74 16                	je     809088 <seghandler+0x23>
  809072:	48 8d 3d 94 14 00 00 	lea    0x1494(%rip),%rdi        # 80a50d <_IO_stdin_used+0x43d>
  809079:	e8 42 7c bf ff       	call   400cc0 <puts@plt>
  80907e:	b8 00 00 00 00       	mov    $0x0,%eax
  809083:	e8 e2 fb ff ff       	call   808c6a <check_fail>
  809088:	48 8d 3d e9 15 00 00 	lea    0x15e9(%rip),%rdi        # 80a678 <_IO_stdin_used+0x5a8>
  80908f:	e8 2c 7c bf ff       	call   400cc0 <puts@plt>
  809094:	48 8d 3d 5c 14 00 00 	lea    0x145c(%rip),%rdi        # 80a4f7 <_IO_stdin_used+0x427>
  80909b:	e8 20 7c bf ff       	call   400cc0 <puts@plt>
  8090a0:	be 00 00 00 00       	mov    $0x0,%esi
  8090a5:	bf 00 00 00 00       	mov    $0x0,%edi
  8090aa:	e8 45 fc ff ff       	call   808cf4 <notify_server>
  8090af:	bf 01 00 00 00       	mov    $0x1,%edi
  8090b4:	e8 67 7d bf ff       	call   400e20 <exit@plt>

00000000008090b9 <illegalhandler>:
  8090b9:	48 83 ec 08          	sub    $0x8,%rsp
  8090bd:	83 3d 44 34 20 00 00 	cmpl   $0x0,0x203444(%rip)        # a0c508 <is_checker>
  8090c4:	74 16                	je     8090dc <illegalhandler+0x23>
  8090c6:	48 8d 3d 53 14 00 00 	lea    0x1453(%rip),%rdi        # 80a520 <_IO_stdin_used+0x450>
  8090cd:	e8 ee 7b bf ff       	call   400cc0 <puts@plt>
  8090d2:	b8 00 00 00 00       	mov    $0x0,%eax
  8090d7:	e8 8e fb ff ff       	call   808c6a <check_fail>
  8090dc:	48 8d 3d bd 15 00 00 	lea    0x15bd(%rip),%rdi        # 80a6a0 <_IO_stdin_used+0x5d0>
  8090e3:	e8 d8 7b bf ff       	call   400cc0 <puts@plt>
  8090e8:	48 8d 3d 08 14 00 00 	lea    0x1408(%rip),%rdi        # 80a4f7 <_IO_stdin_used+0x427>
  8090ef:	e8 cc 7b bf ff       	call   400cc0 <puts@plt>
  8090f4:	be 00 00 00 00       	mov    $0x0,%esi
  8090f9:	bf 00 00 00 00       	mov    $0x0,%edi
  8090fe:	e8 f1 fb ff ff       	call   808cf4 <notify_server>
  809103:	bf 01 00 00 00       	mov    $0x1,%edi
  809108:	e8 13 7d bf ff       	call   400e20 <exit@plt>

000000000080910d <sigalrmhandler>:
  80910d:	48 83 ec 08          	sub    $0x8,%rsp
  809111:	83 3d f0 33 20 00 00 	cmpl   $0x0,0x2033f0(%rip)        # a0c508 <is_checker>
  809118:	74 16                	je     809130 <sigalrmhandler+0x23>
  80911a:	48 8d 3d 13 14 00 00 	lea    0x1413(%rip),%rdi        # 80a534 <_IO_stdin_used+0x464>
  809121:	e8 9a 7b bf ff       	call   400cc0 <puts@plt>
  809126:	b8 00 00 00 00       	mov    $0x0,%eax
  80912b:	e8 3a fb ff ff       	call   808c6a <check_fail>
  809130:	ba 05 00 00 00       	mov    $0x5,%edx
  809135:	48 8d 35 94 15 00 00 	lea    0x1594(%rip),%rsi        # 80a6d0 <_IO_stdin_used+0x600>
  80913c:	bf 01 00 00 00       	mov    $0x1,%edi
  809141:	b8 00 00 00 00       	mov    $0x0,%eax
  809146:	e8 95 7c bf ff       	call   400de0 <__printf_chk@plt>
  80914b:	be 00 00 00 00       	mov    $0x0,%esi
  809150:	bf 00 00 00 00       	mov    $0x0,%edi
  809155:	e8 9a fb ff ff       	call   808cf4 <notify_server>
  80915a:	bf 01 00 00 00       	mov    $0x1,%edi
  80915f:	e8 bc 7c bf ff       	call   400e20 <exit@plt>

0000000000809164 <launch>:
  809164:	55                   	push   %rbp
  809165:	48 89 e5             	mov    %rsp,%rbp
  809168:	48 83 ec 10          	sub    $0x10,%rsp
  80916c:	48 89 fa             	mov    %rdi,%rdx
  80916f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809176:	00 00 
  809178:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  80917c:	31 c0                	xor    %eax,%eax
  80917e:	48 8d 47 1e          	lea    0x1e(%rdi),%rax
  809182:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
  809186:	48 29 c4             	sub    %rax,%rsp
  809189:	48 8d 7c 24 0f       	lea    0xf(%rsp),%rdi
  80918e:	48 83 e7 f0          	and    $0xfffffffffffffff0,%rdi
  809192:	be f4 00 00 00       	mov    $0xf4,%esi
  809197:	e8 64 7b bf ff       	call   400d00 <memset@plt>
  80919c:	48 8b 05 fd 32 20 00 	mov    0x2032fd(%rip),%rax        # a0c4a0 <stdin@GLIBC_2.2.5>
  8091a3:	48 39 05 46 33 20 00 	cmp    %rax,0x203346(%rip)        # a0c4f0 <infile>
  8091aa:	74 3a                	je     8091e6 <launch+0x82>
  8091ac:	c7 05 46 33 20 00 00 	movl   $0x0,0x203346(%rip)        # a0c4fc <vlevel>
  8091b3:	00 00 00 
  8091b6:	b8 00 00 00 00       	mov    $0x0,%eax
  8091bb:	e8 0f fa ff ff       	call   808bcf <test>
  8091c0:	83 3d 41 33 20 00 00 	cmpl   $0x0,0x203341(%rip)        # a0c508 <is_checker>
  8091c7:	75 35                	jne    8091fe <launch+0x9a>
  8091c9:	48 8d 3d 84 13 00 00 	lea    0x1384(%rip),%rdi        # 80a554 <_IO_stdin_used+0x484>
  8091d0:	e8 eb 7a bf ff       	call   400cc0 <puts@plt>
  8091d5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  8091d9:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  8091e0:	00 00 
  8091e2:	75 30                	jne    809214 <launch+0xb0>
  8091e4:	c9                   	leave
  8091e5:	c3                   	ret
  8091e6:	48 8d 35 4f 13 00 00 	lea    0x134f(%rip),%rsi        # 80a53c <_IO_stdin_used+0x46c>
  8091ed:	bf 01 00 00 00       	mov    $0x1,%edi
  8091f2:	b8 00 00 00 00       	mov    $0x0,%eax
  8091f7:	e8 e4 7b bf ff       	call   400de0 <__printf_chk@plt>
  8091fc:	eb ae                	jmp    8091ac <launch+0x48>
  8091fe:	48 8d 3d 44 13 00 00 	lea    0x1344(%rip),%rdi        # 80a549 <_IO_stdin_used+0x479>
  809205:	e8 b6 7a bf ff       	call   400cc0 <puts@plt>
  80920a:	b8 00 00 00 00       	mov    $0x0,%eax
  80920f:	e8 56 fa ff ff       	call   808c6a <check_fail>
  809214:	e8 c7 7a bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809219 <stable_launch>:
  809219:	53                   	push   %rbx
  80921a:	48 89 3d c7 32 20 00 	mov    %rdi,0x2032c7(%rip)        # a0c4e8 <global_offset>
  809221:	41 b9 00 00 00 00    	mov    $0x0,%r9d
  809227:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  80922d:	b9 32 01 00 00       	mov    $0x132,%ecx
  809232:	ba 07 00 00 00       	mov    $0x7,%edx
  809237:	be 00 00 10 00       	mov    $0x100000,%esi
  80923c:	bf 00 60 58 55       	mov    $0x55586000,%edi
  809241:	e8 aa 7a bf ff       	call   400cf0 <mmap@plt>
  809246:	48 89 c3             	mov    %rax,%rbx
  809249:	48 3d 00 60 58 55    	cmp    $0x55586000,%rax
  80924f:	75 43                	jne    809294 <stable_launch+0x7b>
  809251:	48 8d 90 f8 ff 0f 00 	lea    0xffff8(%rax),%rdx
  809258:	48 89 15 c9 3e 20 00 	mov    %rdx,0x203ec9(%rip)        # a0d128 <stack_top>
  80925f:	48 89 e0             	mov    %rsp,%rax
  809262:	48 89 d4             	mov    %rdx,%rsp
  809265:	48 89 c2             	mov    %rax,%rdx
  809268:	48 89 15 71 32 20 00 	mov    %rdx,0x203271(%rip)        # a0c4e0 <global_save_stack>
  80926f:	48 8b 3d 72 32 20 00 	mov    0x203272(%rip),%rdi        # a0c4e8 <global_offset>
  809276:	e8 e9 fe ff ff       	call   809164 <launch>
  80927b:	48 8b 05 5e 32 20 00 	mov    0x20325e(%rip),%rax        # a0c4e0 <global_save_stack>
  809282:	48 89 c4             	mov    %rax,%rsp
  809285:	be 00 00 10 00       	mov    $0x100000,%esi
  80928a:	48 89 df             	mov    %rbx,%rdi
  80928d:	e8 3e 7b bf ff       	call   400dd0 <munmap@plt>
  809292:	5b                   	pop    %rbx
  809293:	c3                   	ret
  809294:	be 00 00 10 00       	mov    $0x100000,%esi
  809299:	48 89 c7             	mov    %rax,%rdi
  80929c:	e8 2f 7b bf ff       	call   400dd0 <munmap@plt>
  8092a1:	b9 00 60 58 55       	mov    $0x55586000,%ecx
  8092a6:	48 8d 15 5b 14 00 00 	lea    0x145b(%rip),%rdx        # 80a708 <_IO_stdin_used+0x638>
  8092ad:	be 01 00 00 00       	mov    $0x1,%esi
  8092b2:	48 8b 3d 07 32 20 00 	mov    0x203207(%rip),%rdi        # a0c4c0 <stderr@GLIBC_2.2.5>
  8092b9:	b8 00 00 00 00       	mov    $0x0,%eax
  8092be:	e8 7d 7b bf ff       	call   400e40 <__fprintf_chk@plt>
  8092c3:	bf 01 00 00 00       	mov    $0x1,%edi
  8092c8:	e8 53 7b bf ff       	call   400e20 <exit@plt>

00000000008092cd <rio_readinitb>:
  8092cd:	89 37                	mov    %esi,(%rdi)
  8092cf:	c7 47 04 00 00 00 00 	movl   $0x0,0x4(%rdi)
  8092d6:	48 8d 47 10          	lea    0x10(%rdi),%rax
  8092da:	48 89 47 08          	mov    %rax,0x8(%rdi)
  8092de:	c3                   	ret

00000000008092df <sigalrm_handler>:
  8092df:	48 83 ec 08          	sub    $0x8,%rsp
  8092e3:	b9 00 00 00 00       	mov    $0x0,%ecx
  8092e8:	48 8d 15 51 14 00 00 	lea    0x1451(%rip),%rdx        # 80a740 <trans_char+0x10>
  8092ef:	be 01 00 00 00       	mov    $0x1,%esi
  8092f4:	48 8b 3d c5 31 20 00 	mov    0x2031c5(%rip),%rdi        # a0c4c0 <stderr@GLIBC_2.2.5>
  8092fb:	b8 00 00 00 00       	mov    $0x0,%eax
  809300:	e8 3b 7b bf ff       	call   400e40 <__fprintf_chk@plt>
  809305:	bf 01 00 00 00       	mov    $0x1,%edi
  80930a:	e8 11 7b bf ff       	call   400e20 <exit@plt>

000000000080930f <rio_writen>:
  80930f:	41 55                	push   %r13
  809311:	41 54                	push   %r12
  809313:	55                   	push   %rbp
  809314:	53                   	push   %rbx
  809315:	48 83 ec 08          	sub    $0x8,%rsp
  809319:	41 89 fc             	mov    %edi,%r12d
  80931c:	48 89 f5             	mov    %rsi,%rbp
  80931f:	49 89 d5             	mov    %rdx,%r13
  809322:	48 89 d3             	mov    %rdx,%rbx
  809325:	eb 06                	jmp    80932d <rio_writen+0x1e>
  809327:	48 29 c3             	sub    %rax,%rbx
  80932a:	48 01 c5             	add    %rax,%rbp
  80932d:	48 85 db             	test   %rbx,%rbx
  809330:	74 24                	je     809356 <rio_writen+0x47>
  809332:	48 89 da             	mov    %rbx,%rdx
  809335:	48 89 ee             	mov    %rbp,%rsi
  809338:	44 89 e7             	mov    %r12d,%edi
  80933b:	e8 90 79 bf ff       	call   400cd0 <write@plt>
  809340:	48 85 c0             	test   %rax,%rax
  809343:	7f e2                	jg     809327 <rio_writen+0x18>
  809345:	e8 36 79 bf ff       	call   400c80 <__errno_location@plt>
  80934a:	83 38 04             	cmpl   $0x4,(%rax)
  80934d:	75 15                	jne    809364 <rio_writen+0x55>
  80934f:	b8 00 00 00 00       	mov    $0x0,%eax
  809354:	eb d1                	jmp    809327 <rio_writen+0x18>
  809356:	4c 89 e8             	mov    %r13,%rax
  809359:	48 83 c4 08          	add    $0x8,%rsp
  80935d:	5b                   	pop    %rbx
  80935e:	5d                   	pop    %rbp
  80935f:	41 5c                	pop    %r12
  809361:	41 5d                	pop    %r13
  809363:	c3                   	ret
  809364:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  80936b:	eb ec                	jmp    809359 <rio_writen+0x4a>

000000000080936d <rio_read>:
  80936d:	41 55                	push   %r13
  80936f:	41 54                	push   %r12
  809371:	55                   	push   %rbp
  809372:	53                   	push   %rbx
  809373:	48 83 ec 08          	sub    $0x8,%rsp
  809377:	48 89 fb             	mov    %rdi,%rbx
  80937a:	49 89 f5             	mov    %rsi,%r13
  80937d:	49 89 d4             	mov    %rdx,%r12
  809380:	eb 0a                	jmp    80938c <rio_read+0x1f>
  809382:	e8 f9 78 bf ff       	call   400c80 <__errno_location@plt>
  809387:	83 38 04             	cmpl   $0x4,(%rax)
  80938a:	75 5c                	jne    8093e8 <rio_read+0x7b>
  80938c:	8b 6b 04             	mov    0x4(%rbx),%ebp
  80938f:	85 ed                	test   %ebp,%ebp
  809391:	7f 24                	jg     8093b7 <rio_read+0x4a>
  809393:	48 8d 6b 10          	lea    0x10(%rbx),%rbp
  809397:	8b 3b                	mov    (%rbx),%edi
  809399:	ba 00 20 00 00       	mov    $0x2000,%edx
  80939e:	48 89 ee             	mov    %rbp,%rsi
  8093a1:	e8 8a 79 bf ff       	call   400d30 <read@plt>
  8093a6:	89 43 04             	mov    %eax,0x4(%rbx)
  8093a9:	85 c0                	test   %eax,%eax
  8093ab:	78 d5                	js     809382 <rio_read+0x15>
  8093ad:	85 c0                	test   %eax,%eax
  8093af:	74 40                	je     8093f1 <rio_read+0x84>
  8093b1:	48 89 6b 08          	mov    %rbp,0x8(%rbx)
  8093b5:	eb d5                	jmp    80938c <rio_read+0x1f>
  8093b7:	89 e8                	mov    %ebp,%eax
  8093b9:	4c 39 e0             	cmp    %r12,%rax
  8093bc:	72 03                	jb     8093c1 <rio_read+0x54>
  8093be:	44 89 e5             	mov    %r12d,%ebp
  8093c1:	4c 63 e5             	movslq %ebp,%r12
  8093c4:	48 8b 73 08          	mov    0x8(%rbx),%rsi
  8093c8:	4c 89 e2             	mov    %r12,%rdx
  8093cb:	4c 89 ef             	mov    %r13,%rdi
  8093ce:	e8 ad 79 bf ff       	call   400d80 <memcpy@plt>
  8093d3:	4c 01 63 08          	add    %r12,0x8(%rbx)
  8093d7:	29 6b 04             	sub    %ebp,0x4(%rbx)
  8093da:	4c 89 e0             	mov    %r12,%rax
  8093dd:	48 83 c4 08          	add    $0x8,%rsp
  8093e1:	5b                   	pop    %rbx
  8093e2:	5d                   	pop    %rbp
  8093e3:	41 5c                	pop    %r12
  8093e5:	41 5d                	pop    %r13
  8093e7:	c3                   	ret
  8093e8:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  8093ef:	eb ec                	jmp    8093dd <rio_read+0x70>
  8093f1:	b8 00 00 00 00       	mov    $0x0,%eax
  8093f6:	eb e5                	jmp    8093dd <rio_read+0x70>

00000000008093f8 <rio_readlineb>:
  8093f8:	41 55                	push   %r13
  8093fa:	41 54                	push   %r12
  8093fc:	55                   	push   %rbp
  8093fd:	53                   	push   %rbx
  8093fe:	48 83 ec 18          	sub    $0x18,%rsp
  809402:	49 89 fd             	mov    %rdi,%r13
  809405:	48 89 f5             	mov    %rsi,%rbp
  809408:	49 89 d4             	mov    %rdx,%r12
  80940b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809412:	00 00 
  809414:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  809419:	31 c0                	xor    %eax,%eax
  80941b:	bb 01 00 00 00       	mov    $0x1,%ebx
  809420:	4c 39 e3             	cmp    %r12,%rbx
  809423:	73 47                	jae    80946c <rio_readlineb+0x74>
  809425:	48 8d 74 24 07       	lea    0x7(%rsp),%rsi
  80942a:	ba 01 00 00 00       	mov    $0x1,%edx
  80942f:	4c 89 ef             	mov    %r13,%rdi
  809432:	e8 36 ff ff ff       	call   80936d <rio_read>
  809437:	83 f8 01             	cmp    $0x1,%eax
  80943a:	75 1c                	jne    809458 <rio_readlineb+0x60>
  80943c:	48 8d 45 01          	lea    0x1(%rbp),%rax
  809440:	0f b6 54 24 07       	movzbl 0x7(%rsp),%edx
  809445:	88 55 00             	mov    %dl,0x0(%rbp)
  809448:	80 7c 24 07 0a       	cmpb   $0xa,0x7(%rsp)
  80944d:	74 1a                	je     809469 <rio_readlineb+0x71>
  80944f:	48 83 c3 01          	add    $0x1,%rbx
  809453:	48 89 c5             	mov    %rax,%rbp
  809456:	eb c8                	jmp    809420 <rio_readlineb+0x28>
  809458:	85 c0                	test   %eax,%eax
  80945a:	75 32                	jne    80948e <rio_readlineb+0x96>
  80945c:	48 83 fb 01          	cmp    $0x1,%rbx
  809460:	75 0a                	jne    80946c <rio_readlineb+0x74>
  809462:	b8 00 00 00 00       	mov    $0x0,%eax
  809467:	eb 0a                	jmp    809473 <rio_readlineb+0x7b>
  809469:	48 89 c5             	mov    %rax,%rbp
  80946c:	c6 45 00 00          	movb   $0x0,0x0(%rbp)
  809470:	48 89 d8             	mov    %rbx,%rax
  809473:	48 8b 4c 24 08       	mov    0x8(%rsp),%rcx
  809478:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  80947f:	00 00 
  809481:	75 14                	jne    809497 <rio_readlineb+0x9f>
  809483:	48 83 c4 18          	add    $0x18,%rsp
  809487:	5b                   	pop    %rbx
  809488:	5d                   	pop    %rbp
  809489:	41 5c                	pop    %r12
  80948b:	41 5d                	pop    %r13
  80948d:	c3                   	ret
  80948e:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  809495:	eb dc                	jmp    809473 <rio_readlineb+0x7b>
  809497:	e8 44 78 bf ff       	call   400ce0 <__stack_chk_fail@plt>

000000000080949c <urlencode>:
  80949c:	41 54                	push   %r12
  80949e:	55                   	push   %rbp
  80949f:	53                   	push   %rbx
  8094a0:	48 83 ec 10          	sub    $0x10,%rsp
  8094a4:	48 89 fb             	mov    %rdi,%rbx
  8094a7:	48 89 f5             	mov    %rsi,%rbp
  8094aa:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  8094b1:	00 00 
  8094b3:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  8094b8:	31 c0                	xor    %eax,%eax
  8094ba:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  8094c1:	f2 ae                	repnz scas %es:(%rdi),%al
  8094c3:	48 89 ce             	mov    %rcx,%rsi
  8094c6:	48 f7 d6             	not    %rsi
  8094c9:	8d 46 ff             	lea    -0x1(%rsi),%eax
  8094cc:	eb 0f                	jmp    8094dd <urlencode+0x41>
  8094ce:	44 88 45 00          	mov    %r8b,0x0(%rbp)
  8094d2:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
  8094d6:	48 83 c3 01          	add    $0x1,%rbx
  8094da:	44 89 e0             	mov    %r12d,%eax
  8094dd:	44 8d 60 ff          	lea    -0x1(%rax),%r12d
  8094e1:	85 c0                	test   %eax,%eax
  8094e3:	0f 84 a8 00 00 00    	je     809591 <urlencode+0xf5>
  8094e9:	44 0f b6 03          	movzbl (%rbx),%r8d
  8094ed:	41 80 f8 2a          	cmp    $0x2a,%r8b
  8094f1:	0f 94 c2             	sete   %dl
  8094f4:	41 80 f8 2d          	cmp    $0x2d,%r8b
  8094f8:	0f 94 c0             	sete   %al
  8094fb:	08 c2                	or     %al,%dl
  8094fd:	75 cf                	jne    8094ce <urlencode+0x32>
  8094ff:	41 80 f8 2e          	cmp    $0x2e,%r8b
  809503:	74 c9                	je     8094ce <urlencode+0x32>
  809505:	41 80 f8 5f          	cmp    $0x5f,%r8b
  809509:	74 c3                	je     8094ce <urlencode+0x32>
  80950b:	41 8d 40 d0          	lea    -0x30(%r8),%eax
  80950f:	3c 09                	cmp    $0x9,%al
  809511:	76 bb                	jbe    8094ce <urlencode+0x32>
  809513:	41 8d 40 bf          	lea    -0x41(%r8),%eax
  809517:	3c 19                	cmp    $0x19,%al
  809519:	76 b3                	jbe    8094ce <urlencode+0x32>
  80951b:	41 8d 40 9f          	lea    -0x61(%r8),%eax
  80951f:	3c 19                	cmp    $0x19,%al
  809521:	76 ab                	jbe    8094ce <urlencode+0x32>
  809523:	41 80 f8 20          	cmp    $0x20,%r8b
  809527:	74 56                	je     80957f <urlencode+0xe3>
  809529:	41 8d 40 e0          	lea    -0x20(%r8),%eax
  80952d:	3c 5f                	cmp    $0x5f,%al
  80952f:	0f 96 c2             	setbe  %dl
  809532:	41 80 f8 09          	cmp    $0x9,%r8b
  809536:	0f 94 c0             	sete   %al
  809539:	08 c2                	or     %al,%dl
  80953b:	74 4f                	je     80958c <urlencode+0xf0>
  80953d:	48 89 e7             	mov    %rsp,%rdi
  809540:	45 0f b6 c0          	movzbl %r8b,%r8d
  809544:	48 8d 0d 8d 12 00 00 	lea    0x128d(%rip),%rcx        # 80a7d8 <trans_char+0xa8>
  80954b:	ba 08 00 00 00       	mov    $0x8,%edx
  809550:	be 01 00 00 00       	mov    $0x1,%esi
  809555:	b8 00 00 00 00       	mov    $0x0,%eax
  80955a:	e8 f1 78 bf ff       	call   400e50 <__sprintf_chk@plt>
  80955f:	0f b6 04 24          	movzbl (%rsp),%eax
  809563:	88 45 00             	mov    %al,0x0(%rbp)
  809566:	0f b6 44 24 01       	movzbl 0x1(%rsp),%eax
  80956b:	88 45 01             	mov    %al,0x1(%rbp)
  80956e:	0f b6 44 24 02       	movzbl 0x2(%rsp),%eax
  809573:	88 45 02             	mov    %al,0x2(%rbp)
  809576:	48 8d 6d 03          	lea    0x3(%rbp),%rbp
  80957a:	e9 57 ff ff ff       	jmp    8094d6 <urlencode+0x3a>
  80957f:	c6 45 00 2b          	movb   $0x2b,0x0(%rbp)
  809583:	48 8d 6d 01          	lea    0x1(%rbp),%rbp
  809587:	e9 4a ff ff ff       	jmp    8094d6 <urlencode+0x3a>
  80958c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809591:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  809596:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
  80959d:	00 00 
  80959f:	75 09                	jne    8095aa <urlencode+0x10e>
  8095a1:	48 83 c4 10          	add    $0x10,%rsp
  8095a5:	5b                   	pop    %rbx
  8095a6:	5d                   	pop    %rbp
  8095a7:	41 5c                	pop    %r12
  8095a9:	c3                   	ret
  8095aa:	e8 31 77 bf ff       	call   400ce0 <__stack_chk_fail@plt>

00000000008095af <submitr>:
  8095af:	41 57                	push   %r15
  8095b1:	41 56                	push   %r14
  8095b3:	41 55                	push   %r13
  8095b5:	41 54                	push   %r12
  8095b7:	55                   	push   %rbp
  8095b8:	53                   	push   %rbx
  8095b9:	48 81 ec 68 a0 00 00 	sub    $0xa068,%rsp
  8095c0:	49 89 fd             	mov    %rdi,%r13
  8095c3:	89 74 24 14          	mov    %esi,0x14(%rsp)
  8095c7:	49 89 d7             	mov    %rdx,%r15
  8095ca:	48 89 4c 24 08       	mov    %rcx,0x8(%rsp)
  8095cf:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
  8095d4:	4d 89 ce             	mov    %r9,%r14
  8095d7:	48 8b ac 24 a0 a0 00 	mov    0xa0a0(%rsp),%rbp
  8095de:	00 
  8095df:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  8095e6:	00 00 
  8095e8:	48 89 84 24 58 a0 00 	mov    %rax,0xa058(%rsp)
  8095ef:	00 
  8095f0:	31 c0                	xor    %eax,%eax
  8095f2:	c7 44 24 2c 00 00 00 	movl   $0x0,0x2c(%rsp)
  8095f9:	00 
  8095fa:	ba 00 00 00 00       	mov    $0x0,%edx
  8095ff:	be 01 00 00 00       	mov    $0x1,%esi
  809604:	bf 02 00 00 00       	mov    $0x2,%edi
  809609:	e8 52 78 bf ff       	call   400e60 <socket@plt>
  80960e:	85 c0                	test   %eax,%eax
  809610:	0f 88 a9 02 00 00    	js     8098bf <submitr+0x310>
  809616:	89 c3                	mov    %eax,%ebx
  809618:	4c 89 ef             	mov    %r13,%rdi
  80961b:	e8 30 77 bf ff       	call   400d50 <gethostbyname@plt>
  809620:	48 85 c0             	test   %rax,%rax
  809623:	0f 84 e2 02 00 00    	je     80990b <submitr+0x35c>
  809629:	4c 8d 64 24 30       	lea    0x30(%rsp),%r12
  80962e:	48 c7 44 24 32 00 00 	movq   $0x0,0x32(%rsp)
  809635:	00 00 
  809637:	c7 44 24 3a 00 00 00 	movl   $0x0,0x3a(%rsp)
  80963e:	00 
  80963f:	66 c7 44 24 3e 00 00 	movw   $0x0,0x3e(%rsp)
  809646:	66 c7 44 24 30 02 00 	movw   $0x2,0x30(%rsp)
  80964d:	48 63 50 14          	movslq 0x14(%rax),%rdx
  809651:	48 8b 40 18          	mov    0x18(%rax),%rax
  809655:	48 8b 30             	mov    (%rax),%rsi
  809658:	48 8d 7c 24 34       	lea    0x34(%rsp),%rdi
  80965d:	b9 0c 00 00 00       	mov    $0xc,%ecx
  809662:	e8 f9 76 bf ff       	call   400d60 <__memmove_chk@plt>
  809667:	0f b7 44 24 14       	movzwl 0x14(%rsp),%eax
  80966c:	66 c1 c8 08          	ror    $0x8,%ax
  809670:	66 89 44 24 32       	mov    %ax,0x32(%rsp)
  809675:	ba 10 00 00 00       	mov    $0x10,%edx
  80967a:	4c 89 e6             	mov    %r12,%rsi
  80967d:	89 df                	mov    %ebx,%edi
  80967f:	e8 ac 77 bf ff       	call   400e30 <connect@plt>
  809684:	85 c0                	test   %eax,%eax
  809686:	0f 88 e7 02 00 00    	js     809973 <submitr+0x3c4>
  80968c:	48 c7 c6 ff ff ff ff 	mov    $0xffffffffffffffff,%rsi
  809693:	b8 00 00 00 00       	mov    $0x0,%eax
  809698:	48 89 f1             	mov    %rsi,%rcx
  80969b:	4c 89 f7             	mov    %r14,%rdi
  80969e:	f2 ae                	repnz scas %es:(%rdi),%al
  8096a0:	48 89 ca             	mov    %rcx,%rdx
  8096a3:	48 f7 d2             	not    %rdx
  8096a6:	48 89 f1             	mov    %rsi,%rcx
  8096a9:	4c 89 ff             	mov    %r15,%rdi
  8096ac:	f2 ae                	repnz scas %es:(%rdi),%al
  8096ae:	48 f7 d1             	not    %rcx
  8096b1:	49 89 c8             	mov    %rcx,%r8
  8096b4:	48 89 f1             	mov    %rsi,%rcx
  8096b7:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
  8096bc:	f2 ae                	repnz scas %es:(%rdi),%al
  8096be:	48 f7 d1             	not    %rcx
  8096c1:	4d 8d 44 08 fe       	lea    -0x2(%r8,%rcx,1),%r8
  8096c6:	48 89 f1             	mov    %rsi,%rcx
  8096c9:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
  8096ce:	f2 ae                	repnz scas %es:(%rdi),%al
  8096d0:	48 89 c8             	mov    %rcx,%rax
  8096d3:	48 f7 d0             	not    %rax
  8096d6:	49 8d 4c 00 ff       	lea    -0x1(%r8,%rax,1),%rcx
  8096db:	48 8d 44 52 fd       	lea    -0x3(%rdx,%rdx,2),%rax
  8096e0:	48 8d 84 01 80 00 00 	lea    0x80(%rcx,%rax,1),%rax
  8096e7:	00 
  8096e8:	48 3d 00 20 00 00    	cmp    $0x2000,%rax
  8096ee:	0f 87 d9 02 00 00    	ja     8099cd <submitr+0x41e>
  8096f4:	48 8d b4 24 50 40 00 	lea    0x4050(%rsp),%rsi
  8096fb:	00 
  8096fc:	b9 00 04 00 00       	mov    $0x400,%ecx
  809701:	b8 00 00 00 00       	mov    $0x0,%eax
  809706:	48 89 f7             	mov    %rsi,%rdi
  809709:	f3 48 ab             	rep stos %rax,%es:(%rdi)
  80970c:	4c 89 f7             	mov    %r14,%rdi
  80970f:	e8 88 fd ff ff       	call   80949c <urlencode>
  809714:	85 c0                	test   %eax,%eax
  809716:	0f 88 24 03 00 00    	js     809a40 <submitr+0x491>
  80971c:	4c 8d a4 24 50 20 00 	lea    0x2050(%rsp),%r12
  809723:	00 
  809724:	41 55                	push   %r13
  809726:	48 8d 84 24 58 40 00 	lea    0x4058(%rsp),%rax
  80972d:	00 
  80972e:	50                   	push   %rax
  80972f:	4d 89 f9             	mov    %r15,%r9
  809732:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
  809737:	48 8d 0d 2a 10 00 00 	lea    0x102a(%rip),%rcx        # 80a768 <trans_char+0x38>
  80973e:	ba 00 20 00 00       	mov    $0x2000,%edx
  809743:	be 01 00 00 00       	mov    $0x1,%esi
  809748:	4c 89 e7             	mov    %r12,%rdi
  80974b:	b8 00 00 00 00       	mov    $0x0,%eax
  809750:	e8 fb 76 bf ff       	call   400e50 <__sprintf_chk@plt>
  809755:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  80975c:	b8 00 00 00 00       	mov    $0x0,%eax
  809761:	4c 89 e7             	mov    %r12,%rdi
  809764:	f2 ae                	repnz scas %es:(%rdi),%al
  809766:	48 89 ca             	mov    %rcx,%rdx
  809769:	48 f7 d2             	not    %rdx
  80976c:	48 8d 52 ff          	lea    -0x1(%rdx),%rdx
  809770:	4c 89 e6             	mov    %r12,%rsi
  809773:	89 df                	mov    %ebx,%edi
  809775:	e8 95 fb ff ff       	call   80930f <rio_writen>
  80977a:	48 83 c4 10          	add    $0x10,%rsp
  80977e:	48 85 c0             	test   %rax,%rax
  809781:	0f 88 44 03 00 00    	js     809acb <submitr+0x51c>
  809787:	4c 8d 64 24 40       	lea    0x40(%rsp),%r12
  80978c:	89 de                	mov    %ebx,%esi
  80978e:	4c 89 e7             	mov    %r12,%rdi
  809791:	e8 37 fb ff ff       	call   8092cd <rio_readinitb>
  809796:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  80979d:	00 
  80979e:	ba 00 20 00 00       	mov    $0x2000,%edx
  8097a3:	4c 89 e7             	mov    %r12,%rdi
  8097a6:	e8 4d fc ff ff       	call   8093f8 <rio_readlineb>
  8097ab:	48 85 c0             	test   %rax,%rax
  8097ae:	0f 8e 86 03 00 00    	jle    809b3a <submitr+0x58b>
  8097b4:	48 8d 4c 24 2c       	lea    0x2c(%rsp),%rcx
  8097b9:	48 8d 94 24 50 60 00 	lea    0x6050(%rsp),%rdx
  8097c0:	00 
  8097c1:	48 8d bc 24 50 20 00 	lea    0x2050(%rsp),%rdi
  8097c8:	00 
  8097c9:	4c 8d 84 24 50 80 00 	lea    0x8050(%rsp),%r8
  8097d0:	00 
  8097d1:	48 8d 35 07 10 00 00 	lea    0x1007(%rip),%rsi        # 80a7df <trans_char+0xaf>
  8097d8:	b8 00 00 00 00       	mov    $0x0,%eax
  8097dd:	e8 de 75 bf ff       	call   400dc0 <__isoc99_sscanf@plt>
  8097e2:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  8097e9:	00 
  8097ea:	b9 03 00 00 00       	mov    $0x3,%ecx
  8097ef:	48 8d 3d 00 10 00 00 	lea    0x1000(%rip),%rdi        # 80a7f6 <trans_char+0xc6>
  8097f6:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  8097f8:	0f 97 c0             	seta   %al
  8097fb:	1c 00                	sbb    $0x0,%al
  8097fd:	84 c0                	test   %al,%al
  8097ff:	0f 84 b3 03 00 00    	je     809bb8 <submitr+0x609>
  809805:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  80980c:	00 
  80980d:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
  809812:	ba 00 20 00 00       	mov    $0x2000,%edx
  809817:	e8 dc fb ff ff       	call   8093f8 <rio_readlineb>
  80981c:	48 85 c0             	test   %rax,%rax
  80981f:	7f c1                	jg     8097e2 <submitr+0x233>
  809821:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809828:	3a 20 43 
  80982b:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809832:	20 75 6e 
  809835:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809839:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  80983d:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809844:	74 6f 20 
  809847:	48 ba 72 65 61 64 20 	movabs $0x6165682064616572,%rdx
  80984e:	68 65 61 
  809851:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809855:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809859:	48 b8 64 65 72 73 20 	movabs $0x6f72662073726564,%rax
  809860:	66 72 6f 
  809863:	48 ba 6d 20 74 68 65 	movabs $0x657220656874206d,%rdx
  80986a:	20 72 65 
  80986d:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809871:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809875:	48 b8 73 75 6c 74 20 	movabs $0x72657320746c7573,%rax
  80987c:	73 65 72 
  80987f:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809883:	c7 45 38 76 65 72 00 	movl   $0x726576,0x38(%rbp)
  80988a:	89 df                	mov    %ebx,%edi
  80988c:	e8 8f 74 bf ff       	call   400d20 <close@plt>
  809891:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809896:	48 8b 9c 24 58 a0 00 	mov    0xa058(%rsp),%rbx
  80989d:	00 
  80989e:	64 48 33 1c 25 28 00 	xor    %fs:0x28,%rbx
  8098a5:	00 00 
  8098a7:	0f 85 7e 04 00 00    	jne    809d2b <submitr+0x77c>
  8098ad:	48 81 c4 68 a0 00 00 	add    $0xa068,%rsp
  8098b4:	5b                   	pop    %rbx
  8098b5:	5d                   	pop    %rbp
  8098b6:	41 5c                	pop    %r12
  8098b8:	41 5d                	pop    %r13
  8098ba:	41 5e                	pop    %r14
  8098bc:	41 5f                	pop    %r15
  8098be:	c3                   	ret
  8098bf:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  8098c6:	3a 20 43 
  8098c9:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  8098d0:	20 75 6e 
  8098d3:	48 89 45 00          	mov    %rax,0x0(%rbp)
  8098d7:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  8098db:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  8098e2:	74 6f 20 
  8098e5:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
  8098ec:	65 20 73 
  8098ef:	48 89 45 10          	mov    %rax,0x10(%rbp)
  8098f3:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  8098f7:	c7 45 20 6f 63 6b 65 	movl   $0x656b636f,0x20(%rbp)
  8098fe:	66 c7 45 24 74 00    	movw   $0x74,0x24(%rbp)
  809904:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809909:	eb 8b                	jmp    809896 <submitr+0x2e7>
  80990b:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
  809912:	3a 20 44 
  809915:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
  80991c:	20 75 6e 
  80991f:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809923:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809927:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  80992e:	74 6f 20 
  809931:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
  809938:	76 65 20 
  80993b:	48 89 45 10          	mov    %rax,0x10(%rbp)
  80993f:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809943:	48 b8 73 65 72 76 65 	movabs $0x6120726576726573,%rax
  80994a:	72 20 61 
  80994d:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809951:	c7 45 28 64 64 72 65 	movl   $0x65726464,0x28(%rbp)
  809958:	66 c7 45 2c 73 73    	movw   $0x7373,0x2c(%rbp)
  80995e:	c6 45 2e 00          	movb   $0x0,0x2e(%rbp)
  809962:	89 df                	mov    %ebx,%edi
  809964:	e8 b7 73 bf ff       	call   400d20 <close@plt>
  809969:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  80996e:	e9 23 ff ff ff       	jmp    809896 <submitr+0x2e7>
  809973:	48 b8 45 72 72 6f 72 	movabs $0x55203a726f727245,%rax
  80997a:	3a 20 55 
  80997d:	48 ba 6e 61 62 6c 65 	movabs $0x6f7420656c62616e,%rdx
  809984:	20 74 6f 
  809987:	48 89 45 00          	mov    %rax,0x0(%rbp)
  80998b:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  80998f:	48 b8 20 63 6f 6e 6e 	movabs $0x7463656e6e6f6320,%rax
  809996:	65 63 74 
  809999:	48 ba 20 74 6f 20 74 	movabs $0x20656874206f7420,%rdx
  8099a0:	68 65 20 
  8099a3:	48 89 45 10          	mov    %rax,0x10(%rbp)
  8099a7:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  8099ab:	c7 45 20 73 65 72 76 	movl   $0x76726573,0x20(%rbp)
  8099b2:	66 c7 45 24 65 72    	movw   $0x7265,0x24(%rbp)
  8099b8:	c6 45 26 00          	movb   $0x0,0x26(%rbp)
  8099bc:	89 df                	mov    %ebx,%edi
  8099be:	e8 5d 73 bf ff       	call   400d20 <close@plt>
  8099c3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  8099c8:	e9 c9 fe ff ff       	jmp    809896 <submitr+0x2e7>
  8099cd:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
  8099d4:	3a 20 52 
  8099d7:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
  8099de:	20 73 74 
  8099e1:	48 89 45 00          	mov    %rax,0x0(%rbp)
  8099e5:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  8099e9:	48 b8 72 69 6e 67 20 	movabs $0x6f6f7420676e6972,%rax
  8099f0:	74 6f 6f 
  8099f3:	48 ba 20 6c 61 72 67 	movabs $0x202e656772616c20,%rdx
  8099fa:	65 2e 20 
  8099fd:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809a01:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809a05:	48 b8 49 6e 63 72 65 	movabs $0x6573616572636e49,%rax
  809a0c:	61 73 65 
  809a0f:	48 ba 20 53 55 42 4d 	movabs $0x5254494d42555320,%rdx
  809a16:	49 54 52 
  809a19:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809a1d:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809a21:	48 b8 5f 4d 41 58 42 	movabs $0x46554258414d5f,%rax
  809a28:	55 46 00 
  809a2b:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809a2f:	89 df                	mov    %ebx,%edi
  809a31:	e8 ea 72 bf ff       	call   400d20 <close@plt>
  809a36:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809a3b:	e9 56 fe ff ff       	jmp    809896 <submitr+0x2e7>
  809a40:	48 b8 45 72 72 6f 72 	movabs $0x52203a726f727245,%rax
  809a47:	3a 20 52 
  809a4a:	48 ba 65 73 75 6c 74 	movabs $0x747320746c757365,%rdx
  809a51:	20 73 74 
  809a54:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809a58:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809a5c:	48 b8 72 69 6e 67 20 	movabs $0x6e6f6320676e6972,%rax
  809a63:	63 6f 6e 
  809a66:	48 ba 74 61 69 6e 73 	movabs $0x6e6120736e696174,%rdx
  809a6d:	20 61 6e 
  809a70:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809a74:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809a78:	48 b8 20 69 6c 6c 65 	movabs $0x6c6167656c6c6920,%rax
  809a7f:	67 61 6c 
  809a82:	48 ba 20 6f 72 20 75 	movabs $0x72706e7520726f20,%rdx
  809a89:	6e 70 72 
  809a8c:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809a90:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809a94:	48 b8 69 6e 74 61 62 	movabs $0x20656c6261746e69,%rax
  809a9b:	6c 65 20 
  809a9e:	48 ba 63 68 61 72 61 	movabs $0x6574636172616863,%rdx
  809aa5:	63 74 65 
  809aa8:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809aac:	48 89 55 38          	mov    %rdx,0x38(%rbp)
  809ab0:	66 c7 45 40 72 2e    	movw   $0x2e72,0x40(%rbp)
  809ab6:	c6 45 42 00          	movb   $0x0,0x42(%rbp)
  809aba:	89 df                	mov    %ebx,%edi
  809abc:	e8 5f 72 bf ff       	call   400d20 <close@plt>
  809ac1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809ac6:	e9 cb fd ff ff       	jmp    809896 <submitr+0x2e7>
  809acb:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809ad2:	3a 20 43 
  809ad5:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809adc:	20 75 6e 
  809adf:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809ae3:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809ae7:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809aee:	74 6f 20 
  809af1:	48 ba 77 72 69 74 65 	movabs $0x6f74206574697277,%rdx
  809af8:	20 74 6f 
  809afb:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809aff:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809b03:	48 b8 20 74 68 65 20 	movabs $0x7365722065687420,%rax
  809b0a:	72 65 73 
  809b0d:	48 ba 75 6c 74 20 73 	movabs $0x7672657320746c75,%rdx
  809b14:	65 72 76 
  809b17:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809b1b:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809b1f:	66 c7 45 30 65 72    	movw   $0x7265,0x30(%rbp)
  809b25:	c6 45 32 00          	movb   $0x0,0x32(%rbp)
  809b29:	89 df                	mov    %ebx,%edi
  809b2b:	e8 f0 71 bf ff       	call   400d20 <close@plt>
  809b30:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809b35:	e9 5c fd ff ff       	jmp    809896 <submitr+0x2e7>
  809b3a:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809b41:	3a 20 43 
  809b44:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809b4b:	20 75 6e 
  809b4e:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809b52:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809b56:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809b5d:	74 6f 20 
  809b60:	48 ba 72 65 61 64 20 	movabs $0x7269662064616572,%rdx
  809b67:	66 69 72 
  809b6a:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809b6e:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809b72:	48 b8 73 74 20 68 65 	movabs $0x6564616568207473,%rax
  809b79:	61 64 65 
  809b7c:	48 ba 72 20 66 72 6f 	movabs $0x72206d6f72662072,%rdx
  809b83:	6d 20 72 
  809b86:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809b8a:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809b8e:	48 b8 65 73 75 6c 74 	movabs $0x657320746c757365,%rax
  809b95:	20 73 65 
  809b98:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809b9c:	c7 45 38 72 76 65 72 	movl   $0x72657672,0x38(%rbp)
  809ba3:	c6 45 3c 00          	movb   $0x0,0x3c(%rbp)
  809ba7:	89 df                	mov    %ebx,%edi
  809ba9:	e8 72 71 bf ff       	call   400d20 <close@plt>
  809bae:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809bb3:	e9 de fc ff ff       	jmp    809896 <submitr+0x2e7>
  809bb8:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  809bbf:	00 
  809bc0:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
  809bc5:	ba 00 20 00 00       	mov    $0x2000,%edx
  809bca:	e8 29 f8 ff ff       	call   8093f8 <rio_readlineb>
  809bcf:	48 85 c0             	test   %rax,%rax
  809bd2:	0f 8e 96 00 00 00    	jle    809c6e <submitr+0x6bf>
  809bd8:	44 8b 44 24 2c       	mov    0x2c(%rsp),%r8d
  809bdd:	41 81 f8 c8 00 00 00 	cmp    $0xc8,%r8d
  809be4:	0f 85 08 01 00 00    	jne    809cf2 <submitr+0x743>
  809bea:	48 8d b4 24 50 20 00 	lea    0x2050(%rsp),%rsi
  809bf1:	00 
  809bf2:	48 89 ef             	mov    %rbp,%rdi
  809bf5:	e8 b6 70 bf ff       	call   400cb0 <strcpy@plt>
  809bfa:	89 df                	mov    %ebx,%edi
  809bfc:	e8 1f 71 bf ff       	call   400d20 <close@plt>
  809c01:	b9 04 00 00 00       	mov    $0x4,%ecx
  809c06:	48 8d 3d e3 0b 00 00 	lea    0xbe3(%rip),%rdi        # 80a7f0 <trans_char+0xc0>
  809c0d:	48 89 ee             	mov    %rbp,%rsi
  809c10:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809c12:	0f 97 c0             	seta   %al
  809c15:	1c 00                	sbb    $0x0,%al
  809c17:	0f be c0             	movsbl %al,%eax
  809c1a:	85 c0                	test   %eax,%eax
  809c1c:	0f 84 74 fc ff ff    	je     809896 <submitr+0x2e7>
  809c22:	b9 05 00 00 00       	mov    $0x5,%ecx
  809c27:	48 8d 3d c6 0b 00 00 	lea    0xbc6(%rip),%rdi        # 80a7f4 <trans_char+0xc4>
  809c2e:	48 89 ee             	mov    %rbp,%rsi
  809c31:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809c33:	0f 97 c0             	seta   %al
  809c36:	1c 00                	sbb    $0x0,%al
  809c38:	0f be c0             	movsbl %al,%eax
  809c3b:	85 c0                	test   %eax,%eax
  809c3d:	0f 84 53 fc ff ff    	je     809896 <submitr+0x2e7>
  809c43:	b9 03 00 00 00       	mov    $0x3,%ecx
  809c48:	48 8d 3d aa 0b 00 00 	lea    0xbaa(%rip),%rdi        # 80a7f9 <trans_char+0xc9>
  809c4f:	48 89 ee             	mov    %rbp,%rsi
  809c52:	f3 a6                	repz cmpsb %es:(%rdi),%ds:(%rsi)
  809c54:	0f 97 c0             	seta   %al
  809c57:	1c 00                	sbb    $0x0,%al
  809c59:	0f be c0             	movsbl %al,%eax
  809c5c:	85 c0                	test   %eax,%eax
  809c5e:	0f 84 32 fc ff ff    	je     809896 <submitr+0x2e7>
  809c64:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809c69:	e9 28 fc ff ff       	jmp    809896 <submitr+0x2e7>
  809c6e:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809c75:	3a 20 43 
  809c78:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809c7f:	20 75 6e 
  809c82:	48 89 45 00          	mov    %rax,0x0(%rbp)
  809c86:	48 89 55 08          	mov    %rdx,0x8(%rbp)
  809c8a:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809c91:	74 6f 20 
  809c94:	48 ba 72 65 61 64 20 	movabs $0x6174732064616572,%rdx
  809c9b:	73 74 61 
  809c9e:	48 89 45 10          	mov    %rax,0x10(%rbp)
  809ca2:	48 89 55 18          	mov    %rdx,0x18(%rbp)
  809ca6:	48 b8 74 75 73 20 6d 	movabs $0x7373656d20737574,%rax
  809cad:	65 73 73 
  809cb0:	48 ba 61 67 65 20 66 	movabs $0x6d6f726620656761,%rdx
  809cb7:	72 6f 6d 
  809cba:	48 89 45 20          	mov    %rax,0x20(%rbp)
  809cbe:	48 89 55 28          	mov    %rdx,0x28(%rbp)
  809cc2:	48 b8 20 72 65 73 75 	movabs $0x20746c7573657220,%rax
  809cc9:	6c 74 20 
  809ccc:	48 89 45 30          	mov    %rax,0x30(%rbp)
  809cd0:	c7 45 38 73 65 72 76 	movl   $0x76726573,0x38(%rbp)
  809cd7:	66 c7 45 3c 65 72    	movw   $0x7265,0x3c(%rbp)
  809cdd:	c6 45 3e 00          	movb   $0x0,0x3e(%rbp)
  809ce1:	89 df                	mov    %ebx,%edi
  809ce3:	e8 38 70 bf ff       	call   400d20 <close@plt>
  809ce8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809ced:	e9 a4 fb ff ff       	jmp    809896 <submitr+0x2e7>
  809cf2:	4c 8d 8c 24 50 80 00 	lea    0x8050(%rsp),%r9
  809cf9:	00 
  809cfa:	48 8d 0d a7 0a 00 00 	lea    0xaa7(%rip),%rcx        # 80a7a8 <trans_char+0x78>
  809d01:	48 c7 c2 ff ff ff ff 	mov    $0xffffffffffffffff,%rdx
  809d08:	be 01 00 00 00       	mov    $0x1,%esi
  809d0d:	48 89 ef             	mov    %rbp,%rdi
  809d10:	b8 00 00 00 00       	mov    $0x0,%eax
  809d15:	e8 36 71 bf ff       	call   400e50 <__sprintf_chk@plt>
  809d1a:	89 df                	mov    %ebx,%edi
  809d1c:	e8 ff 6f bf ff       	call   400d20 <close@plt>
  809d21:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809d26:	e9 6b fb ff ff       	jmp    809896 <submitr+0x2e7>
  809d2b:	e8 b0 6f bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809d30 <init_timeout>:
  809d30:	85 ff                	test   %edi,%edi
  809d32:	74 28                	je     809d5c <init_timeout+0x2c>
  809d34:	53                   	push   %rbx
  809d35:	89 fb                	mov    %edi,%ebx
  809d37:	85 ff                	test   %edi,%edi
  809d39:	78 1a                	js     809d55 <init_timeout+0x25>
  809d3b:	48 8d 35 9d f5 ff ff 	lea    -0xa63(%rip),%rsi        # 8092df <sigalrm_handler>
  809d42:	bf 0e 00 00 00       	mov    $0xe,%edi
  809d47:	e8 f4 6f bf ff       	call   400d40 <signal@plt>
  809d4c:	89 df                	mov    %ebx,%edi
  809d4e:	e8 bd 6f bf ff       	call   400d10 <alarm@plt>
  809d53:	5b                   	pop    %rbx
  809d54:	c3                   	ret
  809d55:	bb 00 00 00 00       	mov    $0x0,%ebx
  809d5a:	eb df                	jmp    809d3b <init_timeout+0xb>
  809d5c:	f3 c3                	repz ret

0000000000809d5e <init_driver>:
  809d5e:	41 54                	push   %r12
  809d60:	55                   	push   %rbp
  809d61:	53                   	push   %rbx
  809d62:	48 83 ec 20          	sub    $0x20,%rsp
  809d66:	49 89 fc             	mov    %rdi,%r12
  809d69:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  809d70:	00 00 
  809d72:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  809d77:	31 c0                	xor    %eax,%eax
  809d79:	be 01 00 00 00       	mov    $0x1,%esi
  809d7e:	bf 0d 00 00 00       	mov    $0xd,%edi
  809d83:	e8 b8 6f bf ff       	call   400d40 <signal@plt>
  809d88:	be 01 00 00 00       	mov    $0x1,%esi
  809d8d:	bf 1d 00 00 00       	mov    $0x1d,%edi
  809d92:	e8 a9 6f bf ff       	call   400d40 <signal@plt>
  809d97:	be 01 00 00 00       	mov    $0x1,%esi
  809d9c:	bf 1d 00 00 00       	mov    $0x1d,%edi
  809da1:	e8 9a 6f bf ff       	call   400d40 <signal@plt>
  809da6:	ba 00 00 00 00       	mov    $0x0,%edx
  809dab:	be 01 00 00 00       	mov    $0x1,%esi
  809db0:	bf 02 00 00 00       	mov    $0x2,%edi
  809db5:	e8 a6 70 bf ff       	call   400e60 <socket@plt>
  809dba:	85 c0                	test   %eax,%eax
  809dbc:	0f 88 a3 00 00 00    	js     809e65 <init_driver+0x107>
  809dc2:	89 c3                	mov    %eax,%ebx
  809dc4:	48 8d 3d 56 05 00 00 	lea    0x556(%rip),%rdi        # 80a321 <_IO_stdin_used+0x251>
  809dcb:	e8 80 6f bf ff       	call   400d50 <gethostbyname@plt>
  809dd0:	48 85 c0             	test   %rax,%rax
  809dd3:	0f 84 df 00 00 00    	je     809eb8 <init_driver+0x15a>
  809dd9:	48 89 e5             	mov    %rsp,%rbp
  809ddc:	48 c7 44 24 02 00 00 	movq   $0x0,0x2(%rsp)
  809de3:	00 00 
  809de5:	c7 45 0a 00 00 00 00 	movl   $0x0,0xa(%rbp)
  809dec:	66 c7 45 0e 00 00    	movw   $0x0,0xe(%rbp)
  809df2:	66 c7 04 24 02 00    	movw   $0x2,(%rsp)
  809df8:	48 63 50 14          	movslq 0x14(%rax),%rdx
  809dfc:	48 8b 40 18          	mov    0x18(%rax),%rax
  809e00:	48 8b 30             	mov    (%rax),%rsi
  809e03:	48 8d 7d 04          	lea    0x4(%rbp),%rdi
  809e07:	b9 0c 00 00 00       	mov    $0xc,%ecx
  809e0c:	e8 4f 6f bf ff       	call   400d60 <__memmove_chk@plt>
  809e11:	66 c7 44 24 02 3c 9a 	movw   $0x9a3c,0x2(%rsp)
  809e18:	ba 10 00 00 00       	mov    $0x10,%edx
  809e1d:	48 89 ee             	mov    %rbp,%rsi
  809e20:	89 df                	mov    %ebx,%edi
  809e22:	e8 09 70 bf ff       	call   400e30 <connect@plt>
  809e27:	85 c0                	test   %eax,%eax
  809e29:	0f 88 fb 00 00 00    	js     809f2a <init_driver+0x1cc>
  809e2f:	89 df                	mov    %ebx,%edi
  809e31:	e8 ea 6e bf ff       	call   400d20 <close@plt>
  809e36:	66 41 c7 04 24 4f 4b 	movw   $0x4b4f,(%r12)
  809e3d:	41 c6 44 24 02 00    	movb   $0x0,0x2(%r12)
  809e43:	b8 00 00 00 00       	mov    $0x0,%eax
  809e48:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
  809e4d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  809e54:	00 00 
  809e56:	0f 85 28 01 00 00    	jne    809f84 <init_driver+0x226>
  809e5c:	48 83 c4 20          	add    $0x20,%rsp
  809e60:	5b                   	pop    %rbx
  809e61:	5d                   	pop    %rbp
  809e62:	41 5c                	pop    %r12
  809e64:	c3                   	ret
  809e65:	48 b8 45 72 72 6f 72 	movabs $0x43203a726f727245,%rax
  809e6c:	3a 20 43 
  809e6f:	48 ba 6c 69 65 6e 74 	movabs $0x6e7520746e65696c,%rdx
  809e76:	20 75 6e 
  809e79:	49 89 04 24          	mov    %rax,(%r12)
  809e7d:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  809e82:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809e89:	74 6f 20 
  809e8c:	48 ba 63 72 65 61 74 	movabs $0x7320657461657263,%rdx
  809e93:	65 20 73 
  809e96:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  809e9b:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  809ea0:	41 c7 44 24 20 6f 63 	movl   $0x656b636f,0x20(%r12)
  809ea7:	6b 65 
  809ea9:	66 41 c7 44 24 24 74 	movw   $0x74,0x24(%r12)
  809eb0:	00 
  809eb1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809eb6:	eb 90                	jmp    809e48 <init_driver+0xea>
  809eb8:	48 b8 45 72 72 6f 72 	movabs $0x44203a726f727245,%rax
  809ebf:	3a 20 44 
  809ec2:	48 ba 4e 53 20 69 73 	movabs $0x6e7520736920534e,%rdx
  809ec9:	20 75 6e 
  809ecc:	49 89 04 24          	mov    %rax,(%r12)
  809ed0:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  809ed5:	48 b8 61 62 6c 65 20 	movabs $0x206f7420656c6261,%rax
  809edc:	74 6f 20 
  809edf:	48 ba 72 65 73 6f 6c 	movabs $0x2065766c6f736572,%rdx
  809ee6:	76 65 20 
  809ee9:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  809eee:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  809ef3:	48 b8 73 65 72 76 65 	movabs $0x6120726576726573,%rax
  809efa:	72 20 61 
  809efd:	49 89 44 24 20       	mov    %rax,0x20(%r12)
  809f02:	41 c7 44 24 28 64 64 	movl   $0x65726464,0x28(%r12)
  809f09:	72 65 
  809f0b:	66 41 c7 44 24 2c 73 	movw   $0x7373,0x2c(%r12)
  809f12:	73 
  809f13:	41 c6 44 24 2e 00    	movb   $0x0,0x2e(%r12)
  809f19:	89 df                	mov    %ebx,%edi
  809f1b:	e8 00 6e bf ff       	call   400d20 <close@plt>
  809f20:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809f25:	e9 1e ff ff ff       	jmp    809e48 <init_driver+0xea>
  809f2a:	48 b8 45 72 72 6f 72 	movabs $0x55203a726f727245,%rax
  809f31:	3a 20 55 
  809f34:	48 ba 6e 61 62 6c 65 	movabs $0x6f7420656c62616e,%rdx
  809f3b:	20 74 6f 
  809f3e:	49 89 04 24          	mov    %rax,(%r12)
  809f42:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  809f47:	48 b8 20 63 6f 6e 6e 	movabs $0x7463656e6e6f6320,%rax
  809f4e:	65 63 74 
  809f51:	48 ba 20 74 6f 20 73 	movabs $0x76726573206f7420,%rdx
  809f58:	65 72 76 
  809f5b:	49 89 44 24 10       	mov    %rax,0x10(%r12)
  809f60:	49 89 54 24 18       	mov    %rdx,0x18(%r12)
  809f65:	66 41 c7 44 24 20 65 	movw   $0x7265,0x20(%r12)
  809f6c:	72 
  809f6d:	41 c6 44 24 22 00    	movb   $0x0,0x22(%r12)
  809f73:	89 df                	mov    %ebx,%edi
  809f75:	e8 a6 6d bf ff       	call   400d20 <close@plt>
  809f7a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  809f7f:	e9 c4 fe ff ff       	jmp    809e48 <init_driver+0xea>
  809f84:	e8 57 6d bf ff       	call   400ce0 <__stack_chk_fail@plt>

0000000000809f89 <driver_post>:
  809f89:	53                   	push   %rbx
  809f8a:	4c 89 cb             	mov    %r9,%rbx
  809f8d:	45 85 c0             	test   %r8d,%r8d
  809f90:	75 18                	jne    809faa <driver_post+0x21>
  809f92:	48 85 ff             	test   %rdi,%rdi
  809f95:	74 05                	je     809f9c <driver_post+0x13>
  809f97:	80 3f 00             	cmpb   $0x0,(%rdi)
  809f9a:	75 37                	jne    809fd3 <driver_post+0x4a>
  809f9c:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
  809fa1:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
  809fa5:	44 89 c0             	mov    %r8d,%eax
  809fa8:	5b                   	pop    %rbx
  809fa9:	c3                   	ret
  809faa:	48 89 ca             	mov    %rcx,%rdx
  809fad:	48 8d 35 48 08 00 00 	lea    0x848(%rip),%rsi        # 80a7fc <trans_char+0xcc>
  809fb4:	bf 01 00 00 00       	mov    $0x1,%edi
  809fb9:	b8 00 00 00 00       	mov    $0x0,%eax
  809fbe:	e8 1d 6e bf ff       	call   400de0 <__printf_chk@plt>
  809fc3:	66 c7 03 4f 4b       	movw   $0x4b4f,(%rbx)
  809fc8:	c6 43 02 00          	movb   $0x0,0x2(%rbx)
  809fcc:	b8 00 00 00 00       	mov    $0x0,%eax
  809fd1:	eb d5                	jmp    809fa8 <driver_post+0x1f>
  809fd3:	48 83 ec 08          	sub    $0x8,%rsp
  809fd7:	41 51                	push   %r9
  809fd9:	49 89 c9             	mov    %rcx,%r9
  809fdc:	49 89 d0             	mov    %rdx,%r8
  809fdf:	48 89 f9             	mov    %rdi,%rcx
  809fe2:	48 89 f2             	mov    %rsi,%rdx
  809fe5:	be 9a 3c 00 00       	mov    $0x3c9a,%esi
  809fea:	48 8d 3d 30 03 00 00 	lea    0x330(%rip),%rdi        # 80a321 <_IO_stdin_used+0x251>
  809ff1:	e8 b9 f5 ff ff       	call   8095af <submitr>
  809ff6:	48 83 c4 10          	add    $0x10,%rsp
  809ffa:	eb ac                	jmp    809fa8 <driver_post+0x1f>

0000000000809ffc <check>:
  809ffc:	89 f8                	mov    %edi,%eax
  809ffe:	c1 e8 1c             	shr    $0x1c,%eax
  80a001:	85 c0                	test   %eax,%eax
  80a003:	74 1d                	je     80a022 <check+0x26>
  80a005:	b9 00 00 00 00       	mov    $0x0,%ecx
  80a00a:	83 f9 1f             	cmp    $0x1f,%ecx
  80a00d:	7f 0d                	jg     80a01c <check+0x20>
  80a00f:	89 f8                	mov    %edi,%eax
  80a011:	d3 e8                	shr    %cl,%eax
  80a013:	3c 0a                	cmp    $0xa,%al
  80a015:	74 11                	je     80a028 <check+0x2c>
  80a017:	83 c1 08             	add    $0x8,%ecx
  80a01a:	eb ee                	jmp    80a00a <check+0xe>
  80a01c:	b8 01 00 00 00       	mov    $0x1,%eax
  80a021:	c3                   	ret
  80a022:	b8 00 00 00 00       	mov    $0x0,%eax
  80a027:	c3                   	ret
  80a028:	b8 00 00 00 00       	mov    $0x0,%eax
  80a02d:	c3                   	ret

000000000080a02e <gencookie>:
  80a02e:	53                   	push   %rbx
  80a02f:	83 c7 01             	add    $0x1,%edi
  80a032:	e8 59 6c bf ff       	call   400c90 <srandom@plt>
  80a037:	e8 64 6d bf ff       	call   400da0 <random@plt>
  80a03c:	89 c3                	mov    %eax,%ebx
  80a03e:	89 c7                	mov    %eax,%edi
  80a040:	e8 b7 ff ff ff       	call   809ffc <check>
  80a045:	85 c0                	test   %eax,%eax
  80a047:	74 ee                	je     80a037 <gencookie+0x9>
  80a049:	89 d8                	mov    %ebx,%eax
  80a04b:	5b                   	pop    %rbx
  80a04c:	c3                   	ret
  80a04d:	0f 1f 00             	nopl   (%rax)

000000000080a050 <__libc_csu_init>:
  80a050:	41 57                	push   %r15
  80a052:	41 56                	push   %r14
  80a054:	49 89 d7             	mov    %rdx,%r15
  80a057:	41 55                	push   %r13
  80a059:	41 54                	push   %r12
  80a05b:	4c 8d 25 ae 1d 20 00 	lea    0x201dae(%rip),%r12        # a0be10 <__frame_dummy_init_array_entry>
  80a062:	55                   	push   %rbp
  80a063:	48 8d 2d ae 1d 20 00 	lea    0x201dae(%rip),%rbp        # a0be18 <__do_global_dtors_aux_fini_array_entry>
  80a06a:	53                   	push   %rbx
  80a06b:	41 89 fd             	mov    %edi,%r13d
  80a06e:	49 89 f6             	mov    %rsi,%r14
  80a071:	4c 29 e5             	sub    %r12,%rbp
  80a074:	48 83 ec 08          	sub    $0x8,%rsp
  80a078:	48 c1 fd 03          	sar    $0x3,%rbp
  80a07c:	e8 c7 6b bf ff       	call   400c48 <_init>
  80a081:	48 85 ed             	test   %rbp,%rbp
  80a084:	74 20                	je     80a0a6 <__libc_csu_init+0x56>
  80a086:	31 db                	xor    %ebx,%ebx
  80a088:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  80a08f:	00 
  80a090:	4c 89 fa             	mov    %r15,%rdx
  80a093:	4c 89 f6             	mov    %r14,%rsi
  80a096:	44 89 ef             	mov    %r13d,%edi
  80a099:	41 ff 14 dc          	call   *(%r12,%rbx,8)
  80a09d:	48 83 c3 01          	add    $0x1,%rbx
  80a0a1:	48 39 dd             	cmp    %rbx,%rbp
  80a0a4:	75 ea                	jne    80a090 <__libc_csu_init+0x40>
  80a0a6:	48 83 c4 08          	add    $0x8,%rsp
  80a0aa:	5b                   	pop    %rbx
  80a0ab:	5d                   	pop    %rbp
  80a0ac:	41 5c                	pop    %r12
  80a0ae:	41 5d                	pop    %r13
  80a0b0:	41 5e                	pop    %r14
  80a0b2:	41 5f                	pop    %r15
  80a0b4:	c3                   	ret
  80a0b5:	90                   	nop
  80a0b6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  80a0bd:	00 00 00 

000000000080a0c0 <__libc_csu_fini>:
  80a0c0:	f3 c3                	repz ret

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

000000000080a0c4 <_fini>:
  80a0c4:	48 83 ec 08          	sub    $0x8,%rsp
  80a0c8:	48 83 c4 08          	add    $0x8,%rsp
  80a0cc:	c3                   	ret
