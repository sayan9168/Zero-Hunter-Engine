CC ?= gcc
CFLAGS = -O3 -fPIC -Wall -Wextra

all: sancov_rt.o libsancov_rt.so

sancov_rt.o: sancov_rt.c
	$(CC) $(CFLAGS) -c sancov_rt.c -o sancov_rt.o

libsancov_rt.so: sancov_rt.c
	$(CC) $(CFLAGS) -shared sancov_rt.c -o libsancov_rt.so

clean:
	rm -f sancov_rt.o libsancov_rt.so

.PHONY: all clean
