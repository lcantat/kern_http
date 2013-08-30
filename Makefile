	
#
# Makefile for the RFC 2616 http module.
#

obj-$(CONFIG_HTTP) += http.o

http-y	:=  http_mod.o http_parser.o http_engine.o tcp_engine.o
			

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

