CC = gcc
CFLAGS = -Wall -Wextra

all: vuln vuln_asan

vuln: vuln_buffer.c
	$(CC) $(CFLAGS) -o vuln vuln_buffer.c -fno-stack-protector -z execstack

vuln_asan: vuln_buffer.c
	$(CC) $(CFLAGS) -o vuln_asan vuln_buffer.c -fsanitize=address -g -fno-omit-frame-pointer

clean:
	rm -f vuln vuln_asan

.PHONY: all clean
