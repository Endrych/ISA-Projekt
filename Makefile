all:
	gcc myripsniffer.c sniffer_parser.c -o build/myripsniffer -lpcap