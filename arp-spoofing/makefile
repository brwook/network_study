LDLIBS=-lpcap

all: arp-spoofing

arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o my_info.o iphdr.h
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -pthread -o $@

clean:
	rm -f arp-spoofing *.o
