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
#define PASS_LEN SHA512_DIGEST_LENGTH*2 // 128 = lunghezza in caratteri dell'hash esadecimale.
#define MAX_NUM 20
#define USER_ERROR 30
#define CRYPT_ARG "$6$12345678$"
#define flushstream(stdin) while(getchar() != '\n')

void err_man(char *s){
    /*
     * funzione di gestione degli errori: stampa un messaggio di errore 
	 * e termina il programma. Non ha valore di ritorno.
    */
    fprintf(stderr, "%s error; errno is %s. Exiting\n", s, strerror(errno));
    exit(EXIT_FAILURE);
}

void login_process(int sockfd){
	 /*
     * funzione che gestisce il processo di login: chiede username e password, li 
	 * invia al server e riceve la risposta. Se l'accesso è negato, ripete il processo.
     */
   
	char *temp_name, *uname, *pass, result[MAX_RESPONSE_LENGTH + 1];
	char *encrypted;

	login:

    printf("Insert username (max %d chars): ", MAX_UNAME);
	fflush(stdout); //NON SO PERCHÉ TENERLO DAVA PROBLEMI
	scanf("%ms", &temp_name); //lettura username

	uname = strndup(temp_name, MAX_UNAME);

	if (uname == NULL) err_man("strndup()");

#ifdef DEBUG
	printf("got: %s, %s\n", temp_name, uname);
#endif

	free(temp_name);

	if (strchr(uname, ':') != NULL || strchr(uname, ',') != NULL){ //vieto l'utilizzo dei caratteri ':' e ',' negli username (strchr ritorna NULL se non trova i caratteri)
		printf("Cannot use ':' or ',' as part of the username; try again\n");
		free(uname);
		goto login;
	}

    printf("Insert password: ");
    fflush(stdout);
	scanf("%ms", &pass);

	encrypted = sha512_hash(pass); //criptazione della password

#ifdef DEBUG
	printf("sending:\n%s\n%s\n", uname, encrypted);
#endif

	char send_buff[MAX_UNAME + PASS_LEN + 2]; //preparo il buffer da inviare al server, che conterrà username e password criptata, separati da due punti

	memset(send_buff, 0, sizeof(send_buff)); //azzeriamo memoria dei buffer per sicurezza
	sprintf(send_buff, "%s:%s:", uname, encrypted); //formatto il buffer come: username:password_criptata:

	if(send(sockfd, send_buff, MAX_UNAME + PASS_LEN + 2, 0) < 0) err_man("send()"); //invio al server

	if(recv(sockfd, result, MAX_RESPONSE_LENGTH, 0) < 0) err_man("recv()"); //ricezione della risposta

	if (strcmp("ACCESS_GRANTED", result) != 0){ //se la risposta non è ACCESS_GRANTED, l'accesso è negato, libero quindi la memoria e ripeto il processo di login
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
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); //creazione del socket usando IPv4 (AF_INET) e protocollo TCP (SOCK_STREAM).
    if (sockfd < 0) err_man("(main) socket()");

#ifdef DEBUG
    printf("socket created\n");
#endif

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr)); //azzero la struttura server_addr per sicurezza

#ifdef DEBUG
    printf("memory set to 0\n");
#endif
//imposta la famiglia IPv4 e converte porta e IP usando strtoport e strtoaddr
    server_addr.sin_family = AF_INET; //imposto la famiglia IPv4 
    server_addr.sin_port = strtoport(argv[2]); //converto la porta usando strtoport
    server_addr.sin_addr.s_addr = strtoaddr(argv[1]); //converto l'indirizzo IP usando strtoaddr 
    if (server_addr.sin_port == -1 || server_addr.sin_addr.s_addr == -1){
        fprintf(stderr, "invalid server address or port; the syntax should be XXX.XXX.XXX.XXX ABCDE\n");
        exit(USER_ERROR);
    }

    printf("connecting to %s:%s\n", argv[1], argv[2]);
    if(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) err_man("(main) connect()"); //avvio three-way-handshake con il server

#ifdef DEBUG
    printf("connection successful\n");
#endif

    login_process(sockfd);

	char op, response[MAX_RESPONSE_LENGTH + 1], name[MAX_NAME + 1], number[MAX_NUM + 1];
	int int_op, response_len, name_len, num_len;
	char send_buffer[MAX_NAME + MAX_NUM + 2];
	//le informazioni saranno inviate nel formato: nome:numero, ma solamente nel caso in cui si abbia bisogno di inviare più di una stringa alla volta

    while(1){

        //loop principale del client: chiede all'utente quale operazione vuole eseguire, la invia al server e riceve la risposta. 
		//Se l'operazione è permessa, procede con la richiesta.

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

		flushstream(stdin);
		op = int_op + '0';

#ifdef DEBUG
		printf("operation: %c\n", op);
#endif
		
		if (send(sockfd, &op, 1, 0) < 0) err_man("send()");

		if (recv(sockfd, response, MAX_RESPONSE_LENGTH, 0) < 0) err_man("recv()");

		if (strcmp(response, "OP_GRANT") != 0){
			printf("Operation not permitted; user doesn't have the permissions to perform %s\n", (int_op == 1 ? "read" : "write"));
			goto oloop;
		}

		printf("Operation permitted\n----\n");

		switch(int_op){
			
			case 1: //lettura di un contatto: chiede il nome del contatto, lo invia al server e riceve il numero associato. 
				printf("Insert the name of the contact (max 128 characters): ");
				fflush(stdout);

				name_len = read(0, name, MAX_NAME);

				if (name_len <= 0) err_man("read()");
				name[name_len - 1] = '\0';

				while(strchr(name, ':') != NULL || strchr(name, ',') != NULL){
					printf("Can't have ':' or ',' in contact names; try again\n");
					name_len = read(0, name, MAX_NAME);
					if (name_len <= 0) err_man("read()"); name[name_len - 1] = '\0';
				}

				if (send(sockfd, name, name_len, 0) < 0) err_man("send()");

				num_len = recv(sockfd, number, MAX_NUM, 0);

				if (num_len < 0) err_man("recv()");

				if (strcmp(number, "NOT_FOUND") == 0){
					printf("Contact was not found\n"); //se il contatto non esiste, stampa un messaggio di errore.
				}
				else{
					printf("-----\nName: %s\nNumber: %s\n-----\n", name, number);
				}

				break;

			case 2: //scrittura di un contatto: chiede il nome e il numero del contatto, li invia al server e riceve una risposta. 

                printf("Insert the name of the contact (max 128 characters): ");
                fflush(stdout);

                name_len = read(0, name, MAX_NAME);
                if (name_len <= 0) err_man("read()");
                name[name_len - 1] = '\0';
                
                while(strchr(name, ':') != NULL || strchr(name, ',') != NULL){
                    printf("Can't have ':' or ',' in contact names; try again\n");
                    name_len = read(0, name, MAX_NAME);
                    if (name_len <= 0) err_man("read()");
                    name[name_len - 1] = '\0';
                }

                printf("Insert contact number (max 20 characters): ");
                fflush(stdout);

                num_len = read(0, number, MAX_NUM);
                if (num_len <= 0) err_man("read()");
                number[num_len - 1] = '\0';
                                
                while(strchr(number, ':') != NULL || strchr(number, ',') != NULL){
                    printf("Can't have ':' or ',' in contact numbers; try again\n");
                    num_len = read(0, number, MAX_NUM);
                    if (num_len <= 0) err_man("read()");
                    number[num_len - 1] = '\0';
                }

                memset(send_buffer, 0, sizeof(send_buffer));
                sprintf(send_buffer, "%s:%s:", name, number);

                if (send(sockfd, send_buffer, MAX_NAME + MAX_NUM + 2, 0) < 0) err_man("send()");

                printf("Contact sent\n");
                
                if (recv(sockfd, response, MAX_RESPONSE_LENGTH, 0) <= 0) err_man("recv()");
                
                if (strcmp(response, "DONE") == 0){
                    printf("Contact was added succesfully\n");
                }
                else{ // contatto già esistente
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
