all:
	gcc myripsniffer.c sniffer.c -o build/myripsniffer -lpcap
	gcc myripresponse.c sniffer.c -o build/myripresponse -lpcap