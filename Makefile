# Assuming kernel source is in ~/linux, `make headers_install' there first.
# This hack will go away once kernel 5.12 is released.
CFLAGS=-I ~/linux/usr/include -static

all: lljail

clean:
	rm -f lljail
