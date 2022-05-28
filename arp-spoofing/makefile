LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o my_info.o iphdr.h
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -pthread -o $@

clean:
	rm -f arp-spoof *.o
