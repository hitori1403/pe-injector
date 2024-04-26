main:
	nasm -fwin64 src/start.asm -o obj/start.o
	gcc obj/start.o src/shellcode.c -o bin/shellcode.exe -O2 -s -fPIC -flto -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib 

cipher:
	gcc .\src\ciphers\rot128.c -o .\obj\cipher.o -O2 -s -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib -fPIC
	objcopy --dump-section .text=obj\cipher.bin .\obj\cipher.o
	print_as_shellcode.exe obj\cipher.bin

incbin:
	objcopy --dump-section .text=bin/shellcode.bin bin/shellcode.exe  
	nasm -fwin64 src/incbin.asm -o obj/incbin.o
	ld obj/incbin.o -o bin/incbin.exe

target:
	gcc src/target.c -o bin/target.exe -O2 -s

run: main target
	cd bin; ./shellcode.exe