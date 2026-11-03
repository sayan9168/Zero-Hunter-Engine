CC = gcc
CFLAGS = -Wall -Wextra
ZH_CC = ../../instrumentation/zh-cc

all: vuln vuln_asan vuln_maze

vuln: vuln_buffer.c
	$(CC) $(CFLAGS) -o vuln vuln_buffer.c -fno-stack-protector -z execstack

vuln_asan: vuln_buffer.c
	$(ZH_CC) $(CFLAGS) -o vuln_asan vuln_buffer.c

vuln_maze: vuln_maze.c
	$(ZH_CC) $(CFLAGS) -Wno-use-after-free -o vuln_maze vuln_maze.c

clean:
	rm -f vuln vuln_asan vuln_maze

.PHONY: all clean
