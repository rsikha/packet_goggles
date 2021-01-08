GCC=gcc
LIB=pcap

all: src/packet_goggle.o
	${GCC} -o packet_goggle src/packet_goggle.c -l${LIB}

clean:
	rm -rf src/packet_goggle.o packet_goggle
