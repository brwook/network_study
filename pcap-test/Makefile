all: pcap-test
pcap-test: main.c pcap-test.c
	gcc -o $@ $^ -lpcap

clean:
	rm -f pcap-test
