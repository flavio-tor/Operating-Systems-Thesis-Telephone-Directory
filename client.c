#include "net_utils.h"
#include <errno.h>
#include <crypt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include "shahash.h"
#define MAX_RESPONSE_LENGTH 20
#define MAX_NAME 128
#define MAX_UNAME 128
#define PASS_LEN SHA512_DIGEST_LENGTH*2
#define MAX_NUM 20
#define USER_ERROR 30
#define CRYPT_ARG "$6$12345678$"
#define flushstream(stdin) while(getchar() != '\n')

void err_man(char *s){
    /*
     * this function is used to spot eventual errors that occurr in the code
     * s: string to attach to output error
     * return value: none
     */
    fprintf(stderr, "%s error; errno is %s. Exiting\n", s, strerror(errno));
    exit(EXIT_FAILURE);
}

void login_process(int sockfd){
   
	char *temp_name, *uname, *pass, result[MAX_RESPONSE_LENGTH + 1];
	char *encrypted;

	login:

    printf("Insert username (max %d chars): ", MAX_UNAME);
	fflush(stdout); //NON SO PERCHÉ TENERLO DAVA PROBLEMI
	scanf("%ms", &temp_name);

	uname = strndup(temp_name, MAX_UNAME);

	if (uname == NULL) err_man("strndup()");

#ifdef DEBUG
	printf("got: %s, %s\n", temp_name, uname);
#endif

	free(temp_name);

	if (strchr(uname, ':') != NULL || strchr(uname, ',') != NULL){
		printf("Cannot use ':' or ',' as part of the username; try again\n");
		free(uname);
		goto login;
	}

    printf("Insert password: ");
    fflush(stdout);
	scanf("%ms", &pass);

	encrypted = sha512_hash(pass);

#ifdef DEBUG
	printf("sending:\n%s\n%s\n", uname, encrypted);
#endif

	char send_buff[MAX_UNAME + PASS_LEN + 2];

	memset(send_buff, 0, sizeof(send_buff)); //azzeriamo memoria dei buffer per sicurezza
	sprintf(send_buff, "%s:%s:", uname, encrypted);

	if(send(sockfd, send_buff, MAX_UNAME + PASS_LEN + 2, 0) < 0) err_man("send()");

	if(recv(sockfd, result, MAX_RESPONSE_LENGTH, 0) < 0) err_man("recv()");

	if (strcmp("ACCESS_GRANTED", result) != 0){
		printf("Invalid access credentials; try again\n");
		free(pass);
		free(encrypted);
		free(uname);

		goto login;
	}

	printf("Access granted; welcome %s\n", uname);

	free(encrypted);
	free(pass);
	free(uname);

	return;

}

int main(int argc, char **argv){

    if (argc < 3){
        perror("usage: program_name server_address server_port\n");
        exit(USER_ERROR);
    }

   //setup del socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); //usiamo TCP per le interazioni client-server

    if (sockfd < 0) err_man("(main) socket()");

#ifdef DEBUG
    printf("socket created\n");
#endif

    if (sockfd < 0) err_man("(main) socket()");

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

#ifdef DEBUG
    printf("memory set to 0\n");
#endif
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = strtoport(argv[2]);
    server_addr.sin_addr.s_addr = strtoaddr(argv[1]);

    if (server_addr.sin_port == -1 || server_addr.sin_addr.s_addr == -1){
        fprintf(stderr, "invalid server address or port; the syntax should be XXX.XXX.XXX.XXX ABCDE\n");
        exit(USER_ERROR);
    }

    printf("connecting to %s:%s\n", argv[1], argv[2]);

    if(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) err_man("(main) connect()");

#ifdef DEBUG
    printf("connection successful\n");
#endif

    login_process(sockfd);

	char op, response[MAX_RESPONSE_LENGTH + 1], name[MAX_NAME + 1], number[MAX_NUM + 1];
	int int_op, response_len, name_len, num_len;
	char send_buffer[MAX_NAME + MAX_NUM + 2];
	//le informazioni saranno inviate nel formato:
	//nome:numero:
	//ma solamente nel caso in cui si abbia bisogno di inviare più di una stringa alla volta

    while(1){

        //operation loop

		oloop:

		printf("----\nChoose the operation you want to perform:\n1) Find contact\n2) Create contact\n3) Quit\nInsert operation: ");
		fflush(stdout);
		if(scanf("%d", &int_op) != 1){
			printf("Invalid format: operation must be an integer; try again\n");
			flushstream(stdin);
			goto oloop;
		}

		if (int_op < 1 || int_op > 3){
			printf("Invalid operation; try again\n");
			goto oloop;
		}

		op = int_op + '0';

#ifdef DEBUG
		printf("operation: %c\n", op);
#endif
		
		if (send(sockfd, &op, 1, 0) < 0) err_man("send()");

		if (recv(sockfd, response, MAX_RESPONSE_LENGTH, 0) < 0) err_man("recv()");

		if (strcmp(response, "OP_GRANT") != 0){
			printf("Operation not permitted; user doesn't have the permissions to perform %s\n", (op == 1 ? "read" : "write"));
			goto oloop;
		}

		printf("Operation permitted\n----\n");

		switch(int_op){
			
			case 1: //read
				printf("Insert the name of the contact (max 128 characters): ");
				fflush(stdout);

				name_len = read(0, name, MAX_NAME);

				name[name_len - 1] = '\0';

				if (name_len <= 0) err_man("read()");

				while(strchr(name, ':') != NULL || strchr(name, ',') != NULL){
					printf("Can't have ':' or ',' in contact names; try again\n");
					name_len = read(0, name, MAX_NAME);
				}

				if (send(sockfd, name, name_len, 0) < 0) err_man("send()");

				num_len = recv(sockfd, number, MAX_NUM, 0);

				if (num_len < 0) err_man("recv()");

				if (strcmp(number, "NOT_FOUND") == 0){
					printf("Contact was not found\n");
				}
				else{
					printf("-----\nName: %s\nNumber: %s\n-----\n", name, number);
				}

				break;

			case 2: //write

				printf("Insert the name of the contact (max 128 characters): ");
				fflush(stdout);

				name_len = read(0, name, MAX_NAME);
				
				if (name_len <= 0) err_man("read()");
				
				while(strchr(name, ':') != NULL || strchr(name, ',') != NULL){
					printf("Can't have ':' or ',' in contact names; try again\n");
					name_len = read(0, name, MAX_NAME);
				}

				printf("Insert contact number (max 20 characters): ");
				fflush(stdout);

				num_len = read(0, number, MAX_NUM);
				
				if (num_len <= 0) err_man("read()");
				
				while(strchr(number, ':') != NULL || strchr(number, ',') != NULL){
					printf("Can't have ':' or ',' in contact names; try again\n");
					name_len = read(0, name, MAX_NAME);
				}

				name[name_len - 1] = '\0';
				number[num_len - 1] = '\0';

				memset(send_buffer, 0, sizeof(send_buffer));
				sprintf(send_buffer, "%s:%s:", name, number);

				if (send(sockfd, send_buffer, MAX_NAME + MAX_NUM + 2, 0) < 0) err_man("send()");

				printf("Contact sent\n");
				
				if (recv(sockfd, response, MAX_RESPONSE_LENGTH, 0) <= 0) err_man("recv()");
				
				if (strcmp(response, "DONE") == 0){
					printf("Contact was added succesfully\n");
				}
				
				else{//contact already exists
					printf("Contact already exists and was not added\n");
				}

				break;

			case 3:

				printf("Exiting; goodbye\n");

				exit(0);

				break;

			default:

				printf("Invalid operation and undefined behaviour\n");

				err_man("undefined behaviour");

				break;
		}


    }

}
