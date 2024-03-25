extern shellcode
global start

segment .text

start:
    push rbp                 
    mov rbp, rsp             
    and rsp, 0xFFFFFFFFFFFFFFF0 ; align stack with 16 bytes
    sub rsp, 0x20               ; allocate some space for our C function
    call shellcode         
    leave
    jmp 0xdeadbeef              ; oep