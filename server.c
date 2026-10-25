#include <stdio.h>
#include <semaphore.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include "lookup.h"
#include "net_utils.h"
#include <openssl/sha.h>
#define gettid() syscall(SYS_gettid)

#define ADDR "127.0.0.1"
#define USER_ERROR 30
#define BACKLOG_SIZE 5
#define MAX_USERNAME 128
#define MAX_PASSWORD SHA512_DIGEST_LENGTH*2 //lunghezza massima della password crittografata
#define MAX_NAME 128
#define MAX_PHONE_NUMBER 20
#define READ 1
#define WRITE 2
#define QUIT 3
#define EZERO 0

sem_t write_file;

__thread char *tokenize; //TLS variable to use as **saveptr for strtok_r

typedef struct thread_arg{
	int sockfd; //file descriptor of the socket
	struct sockaddr client; //pointer to the client address
	int addrlen;
}Thrd_arg;

typedef enum perms{
	RD,
	WR,
	RDWR
}Perms;

void err_man(char *s){
/*
 * this function is used to spot eventual errors that occurr in the code
 * s: string to attach to output error
 * return value: none
 */
	fprintf(stderr, "%s error; errno is %s. Exiting\n", s, strerror(errno));
	exit(EXIT_FAILURE);
}

void thread_err(char *s, int sock){

	close(sock); //così da non avere socket appesi

	if (errno == EPIPE){
		printf("Thread %lu client disconnected (SIGPIPE); exiting\n", gettid());
		pthread_exit((void *) 0);
	}

	else if (errno == EZERO){
		printf("Thread %lu client disconnected (send() or recv() returned zero); exiting\n", gettid());
		pthread_exit((void *) 0);
	}

	else{
		fprintf(stderr, "%s error on %lu; errno is %s (id %d). Exiting thread\n", s, gettid(), strerror(errno), errno);
		pthread_exit((void *) -1);
	}

}

void *server_thread(void *arg){
	/*
	 * questa funzione si occupa di gestire le interazioni con
	 * il client
	 */

	//TODO effettua il controllo di 0 byte sulle receive

	printf("Thread alive\n");

	Thrd_arg *client_info = (Thrd_arg *) arg;

	int sockfd = client_info -> sockfd;
	
	struct sockaddr client_addr;
	
	memcpy(&client_addr, &(client_info -> client), sizeof(client_info -> client));

	int addrlen = client_info -> addrlen;

	free(client_info);

	//TODO: timeout massimo del socket

	//setup completato, recuperiamo nome utente e password
	
	char *mess;
	char buffer[MAX_USERNAME + MAX_PASSWORD + 3];
	char *uname, *pass;

	Perms permissions;

	login:

	//le informazioni saranno trasmesse nel seguente formato
	//nome_utente:password:
	
	if (recv(sockfd, buffer, MAX_USERNAME + MAX_PASSWORD + 2, MSG_WAITALL) <= 0) thread_err("recv()", sockfd);

	buffer[MAX_USERNAME + MAX_PASSWORD + 2] = '\0';

#ifdef DEBUG
	printf("received: %s\n", buffer);
#endif

	uname = strtok_r(buffer, ":", &tokenize);

#ifdef DEBUG
	printf("tok1\n");
#endif

	pass = strtok_r(NULL, ":", &tokenize);

#ifdef DEBUG
	printf("tokenization done\n");
#endif

	if(lookup_access(uname, pass)){ //returns != 0 if wrong username or password

		mess = "INVALID_ACCESS";

		if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

#ifdef DEBUG
		printf("access failed\n", uname, pass);
#endif
		goto login;

	}

	//if we're here the login was successful

#ifdef DEBUG
	printf("access granted\nuname: %s\npasswd: %s\n", uname, pass);
#endif

	permissions = get_permissions(uname);
	
	mess = "ACCESS_GRANTED";

	if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);
	
	char *name_buff, *number_buff;
	char receive_buff[MAX_NAME + MAX_PHONE_NUMBER + 2];
	int name_len, num_len;
	char op;
	int op_int;
	
	op_choose:

	if (recv(sockfd, &op, 1, 0) <= 0) thread_err("recv()", sockfd); //receive the operation
	/*
	 * 1) Find contact
	 * 2) Create contact
	 * 3) Quit
	 */

	op_int = op - '0';

#ifdef DEBUG
	printf("operation chosen: %d (received %c)\n", op_int, op);
#endif

	printf("Thread %lu asked operation %d\n", gettid(), op_int);

	switch(op_int){
		
		case READ:

			if (permissions == WR){
				mess = "OP_NO_GRANT";

				if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

				goto op_choose;
			}

			name_buff = (char *) malloc((MAX_NAME + 1) * sizeof(char));

			mess = "OP_GRANT";

			if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);
		
			if ((name_len = recv(sockfd, name_buff, MAX_NAME, 0)) <= 0) thread_err("recv()", sockfd);

			name_buff[name_len - 1] = '\0';

			number_buff = lookup_name(name_buff);

			if (number_buff == NULL){
				mess = "NOT_FOUND";
				
				if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);
				free(name_buff);
				free(number_buff);
				
				goto op_choose;
			}

			//si potrebbe mettere in number buff NUM:<numero>, così se uno mette come numero NOT_FOUND non succede niente

			if (send(sockfd, number_buff, strlen(number_buff) + 1, 0) <= 0) thread_err("send()", sockfd);

			free(name_buff);
			free(number_buff);

			break;

		case WRITE:
			
			if (permissions == RD){
				mess = "OP_NO_GRANT";

				if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

				goto op_choose;
			}

			mess = "OP_GRANT";

			if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

			//anche qui le informazioni saranno ricevute come -> nome_contatto:numero:

			if (recv(sockfd, receive_buff, sizeof(receive_buff), MSG_WAITALL) <= 0) thread_err("recv()", sockfd);

			name_buff = strtok_r(receive_buff, ":", &tokenize);
			number_buff = strtok_r(NULL, ":", &tokenize);

			/*
			if (lookup_name(name_buff) != NULL){
				//il contatto è già esistente
				mess = "C_EXISTS";
				
				if (send(sockfd, mess, strlen(mess) + 1, 0)) thread_err("send()");
				
				goto op_choose;
			}
			*/
			char *existing = lookup_name(name_buff);
            if (existing != NULL){
                free(existing); // Liberiamo la memoria allocata da lookup_name!
                
                //il contatto è già esistente
                mess = "C_EXISTS";
                
                if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);
                
                goto op_choose;
            }
	
			sem_wait(&write_file);

			if (add_contact(name_buff, number_buff)){
				thread_err("add_contact()", sockfd);
			}

			sem_post(&write_file);
			
			mess = "DONE";
			
			if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

			break;

		case QUIT:

			mess = "OP_GRANT";

			if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

			close(sockfd);

			pthread_exit(0);

			break;

		default:

			mess = "INVALID_OP";

			if (send(sockfd, mess, strlen(mess) + 1, 0) <= 0) thread_err("send()", sockfd);

			break;
			
	}

	goto op_choose;

}

void setup_handler(){
	
	struct sigaction siga;

	siga.sa_handler = SIG_IGN;
	sigemptyset(&siga.sa_mask);
	siga.sa_flags = 0;

	sigaction(SIGPIPE, &siga, NULL);

	return;

}

int main(int argc, char **argv){
	
	if (argc < 3){
		fprintf(stderr, "usage: program_name address port\n");
		exit(USER_ERROR);
	}

	//setup handler SIGPIPE
	setup_handler();

	//setup del semaforo
	
	sem_init(&write_file, 0, 1);

#ifdef DEBUG
	printf("semaphore initiated\n");
#endif

	//setup del socket

	int main_sock = socket(AF_INET, SOCK_STREAM, 0); //usiamo TCP per le interazioni client-server

	if (main_sock < 0) err_man("(main) socket()");

#ifdef DEBUG
	printf("socket created\n");
#endif

	if (main_sock < 0) err_man("(main) socket()");

	struct sockaddr_in serv_addr;

	memset(&serv_addr, 0, sizeof(serv_addr));

#ifdef DEBUG
	printf("memory set to 0\n");
#endif

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = strtoport(argv[2]);
	serv_addr.sin_addr.s_addr = strtoaddr(argv[1]);

	if (serv_addr.sin_port == -1 || serv_addr.sin_addr.s_addr == -1){
		fprintf(stderr, "invalid address or port; the syntax should be XXX.XXX.XXX.XXX ABCDE\n");
		exit(USER_ERROR);
	}

	printf("initiating listening on %s:%s\n", argv[1], argv[2]);

	if (bind(main_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) err_man("(main) bind()");

#ifdef DEBUG
	printf("bind successful\n");
#endif

	if (listen(main_sock, BACKLOG_SIZE) < 0) err_man("(main) listen");

#ifdef DEBUG
	printf("listen succeful\n");
#endif

	Thrd_arg *thread_arg;
	pthread_t tid;

	//inizio del main loop
	while(1){

		thread_arg = (Thrd_arg *) malloc(sizeof(Thrd_arg));

		thread_arg->addrlen = sizeof(struct sockaddr_in);

#ifdef DEBUG
		printf("initiating accept\n");
#endif

		thread_arg -> sockfd = accept(main_sock, &(thread_arg -> client) , &(thread_arg -> addrlen));
		
		if (thread_arg -> sockfd < 0) err_man("(main) accept()");

		printf("accept found; starting thread\n");

#ifdef DEBUG
//		server_thread((void *) thread_arg);
#endif

		if (pthread_create(&tid, NULL, server_thread, (void *) thread_arg)) err_man("(main) pthread_create");
		
		printf("Thread created; going back to listen\n");

		pthread_detach(tid);

	}

}
