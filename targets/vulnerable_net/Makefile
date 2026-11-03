CFLAGS = -Wall -Wextra
ZH_CC = ../../instrumentation/zh-cc

all: vuln_net

vuln_net: vuln_net.c
	$(ZH_CC) $(CFLAGS) -o vuln_net vuln_net.c

clean:
	rm -f vuln_net

.PHONY: all clean
