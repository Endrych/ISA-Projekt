all:
	gcc myripsniffer.c sniffer.c -o myripsniffer -lpcap
	gcc myripresponse.c response.c -o myripresponse -lpcap