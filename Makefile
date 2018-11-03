all:
	gcc myripsniffer.c sniffer.c -o build/myripsniffer -lpcap
	gcc myripresponse.c response.c -o build/myripresponse -lpcap