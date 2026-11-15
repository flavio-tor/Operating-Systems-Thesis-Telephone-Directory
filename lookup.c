#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <string.h>
#include "lookup.h"
#define NOT_FOUND 2 //non trovato
#define FOUND 1 //trovato
#define RD 0 //read-only
#define WR 1 //write-only
#define RDWR 2 //read-write

// in questo file sono contenute tutte le funzioni relative alle interazioni con i seguenti file:
char *contacts_file = "contacts"; //file dei contatti e dei numeri di telefono
char *access_file = "passwd"; //file delle password e dei permessi


char *searchname(FILE *f, char *name, char **lookup_tok){
/* 
 * funzione che cerca il nome fornito nel file dei contatti e restituisce 
 * la riga del file dove è memorizzato il nome già tokenizzata una volta
*/

	int exit_cycle = 0;
	char *buff = NULL, *curr;
	size_t l = 0;
	int len;

	do{
    	if ((len = getline(&buff, &l, f)) < 0){
        	if (feof(f)) exit_cycle = NOT_FOUND; //se arrivo alla fine del file senza trovare il nome, esco
        }
        else {
            curr = strtok_r(buff, ",", lookup_tok); //tokenizzo la riga letta (con versione thread-safe). Il primo token è il nome
            if (curr != NULL && strcmp(curr, name) == 0) {
                exit_cycle = FOUND; //se il nome corrisponde a quello cercato, esco
            }
        }
    } while(!exit_cycle);

    if (exit_cycle == NOT_FOUND) {
        if (buff != NULL) free(buff); //se il nome non é nel file libero la memoria allocata da getline (evito memory leak)
        return NULL;
    }
	
	return buff;
	
}

char *lookup_name(char *name){
/* 
 * funzione che cerca un numero di telefono associato a un nome: apre il file dei contatti, 
 * cerca il nome e restituisce il numero di telefono associato.
*/

	if (name == NULL) return NULL;

	FILE *f = fopen(contacts_file, "r"); //apro il file in lettura
	if (f == NULL) return NULL;
	
	char *lookup_tok;

	char *buff = searchname(f, name, &lookup_tok); //Uso la fz searchname per far restituire la riga intera dell'utente e il puntatore tokenizzato.
	fclose(f);
	if (buff == NULL) return NULL;

	char *curr = strtok_r(NULL, ",", &lookup_tok); //passando NULL, strtok_r continua a tokenizzare la stringa precedente. Il secondo token è il numero di telefono

#ifdef DEBUG
	printf("Number to dup: %s\n", curr);
#endif

	char *ret = strdup(curr);

	free(buff);

	return ret; //return the phone number reallocated
}

int add_contact(char *name, char *number){
/* 
 * funzione che aggiunge un nuovo contatto al file dei contatti in fondo al file. 
 * Ritorna 0 se l'operazione è andata a buon fine, -1 altrimenti.
*/

	FILE *f = fopen(contacts_file, "a");

	fprintf(f, "%s,%s,\n", name, number); //aggiungo il contatto al file dei contatti con il formato "nome,numero,\n" (uso virgola come separatore)
	fflush(f);
	fclose(f);

	return 0;

}


// la struttura di get_permissions e lookup_access è simile a quella di lookup_name, ma invece di restituire il numero di telefono, 
// restituiscono i permessi o verificano la corrispondenza della password.


int get_permissions(char *name){
/* 
 * funzione che cerca l'username nel file delle password e restituisce i permessi associati a quell'utente. Ritorna -1 se non trova l'utente.
*/
	
	FILE *f = fopen(access_file, "r");

	if (f == NULL) return -1;

	char *lookup_tok;
	char *buff = searchname(f, name, &lookup_tok);

	fclose(f);

	if (buff == NULL) return -1;

	strtok_r(NULL, ",", &lookup_tok); //il secondo token è l'hash 
	
	char *curr = strtok_r(NULL, ",", &lookup_tok); //il terzo token è il numero di permessi 
	
	int ret = atoi(curr);

	free(buff);

	return ret;
}

int lookup_access(char *uname, char *pass){
/* 
 * funzione che verifica il login: cerca l'username, prende l'hash della password salvato nel file e 
 * lo confronta con quello che è arrivato dal client. Ritorna != 0 se non trova una corrispondenza valida
*/
	
	FILE *f = fopen(access_file, "r");

	if (f == NULL) return -1;

	char *lookup_tok;
	char *buff = searchname(f, uname, &lookup_tok);

	fclose(f);

	if (buff == NULL) return -1;

	char *curr = strtok_r(NULL, ",", &lookup_tok); //Il secondo token è l'hash 
	
	int ret;

	if (strcmp(curr, pass) == 0){
		ret = 0;
	}
	else ret = 1;

	free(buff);

	return ret;

}
