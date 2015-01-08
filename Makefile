TARGET=my_ping

include ../bench.mk

my_ping: arp.o dev.o pktbuff.o process.o
