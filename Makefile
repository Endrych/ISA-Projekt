all:
	gcc myripsniffer.c sniffer.c -o build/myripsniffer -lpcap