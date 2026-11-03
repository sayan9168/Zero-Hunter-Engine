CFLAGS = -Wall -Wextra
ZH_CC = ../../instrumentation/zh-cc

all: vuln_vault

vuln_vault: vuln_vault.c
	$(ZH_CC) $(CFLAGS) -o vuln_vault vuln_vault.c

clean:
	rm -f vuln_vault

.PHONY: all clean
