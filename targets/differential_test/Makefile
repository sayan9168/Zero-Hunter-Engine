CFLAGS = -Wall -Wextra
ZH_CC = ../../instrumentation/zh-cc

all: parser_ref parser_buggy

parser_ref: parser_ref.c
	$(ZH_CC) $(CFLAGS) -o parser_ref parser_ref.c

parser_buggy: parser_buggy.c
	$(ZH_CC) $(CFLAGS) -o parser_buggy parser_buggy.c

clean:
	rm -f parser_ref parser_buggy

.PHONY: all clean
