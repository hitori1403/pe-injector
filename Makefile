main:
	nasm -fwin64 src/start.asm -o obj/start.o
	gcc obj/start.o src/shellcode.c -o bin/shellcode.exe -O2 -s -fPIC -flto -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib -Wl,-Tlinker.ld

cipher:
	gcc .\src\ciphers\rot128.c -o .\obj\cipher.o -O2 -s -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib -fPIC
	objcopy --dump-section .text=obj\cipher.bin .\obj\cipher.o
	print_as_shellcode.exe obj\cipher.bin

target:
	gcc src/target/hello.c -o bin/hello.exe -O2 -s

run: main target
	cd bin; ./shellcode.exe