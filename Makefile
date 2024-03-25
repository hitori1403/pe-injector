main:
	nasm -fwin64 src/start.asm -o obj/start.o
	gcc obj/start.o src/shellcode.c -o bin/shellcode.exe -O3 -flto -s -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib 

incbin:
	objcopy --dump-section .text=bin/shellcode.bin bin/shellcode.exe  
	nasm -fwin64 src/incbin.asm -o obj/incbin.o
	ld obj/incbin.o -o bin/incbin.exe

target:
	gcc src/target.c -o bin/target.exe -O2 -s

run: main target
	cd bin; ./shellcode.exe
