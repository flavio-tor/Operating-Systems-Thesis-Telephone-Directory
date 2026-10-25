.PHONY: all client server debug adduser

all:
	make client
	make server
	make adduser

debug:
	make client-d
	make server-d

client:
	gcc net_utils.c client.c shahash.c -o client -lssl -lcrypto

server:
	gcc net_utils.c lookup.c server.c -o server

client-d:
	gcc net_utils.c client.c shahash.c -D DEBUG -g -o client -lssl -lcrypto

server-d:	
	gcc net_utils.c lookup.c server.c -D DEBUG -g -o server

adduser:
	gcc add_user.c shahash.c -o add_user -lssl -lcrypto
