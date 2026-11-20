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
 * funzione ausiliaria che cerca un nome all'inizio delle righe di un file CSV e restituisce la riga corrispondente già tokenizzata una volta.
 * f: puntatore al file aperto in lettura. name: stringa contenente il nome da cercare.
 * lookup_tok: puntatore di stato (saveptr) utilizzato da strtok_r per thread-safety.
 * valore di ritorno: puntatore al buffer allocato dinamicamente contenente la riga trovata, oppure NULL se il nome non è presente.
*/

	int exit_cycle = 0;
	char *buff = NULL, *curr;
	size_t l = 0;
	int len;

	do{
    	if ((len = getline(&buff, &l, f)) < 0){
        	if (feof(f) || ferror(f)) exit_cycle = NOT_FOUND; //se arrivo alla fine del file senza trovare il nome, esco
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
 * funzione che cerca un contatto nel file dei contatti e ne estrae il numero di telefono associato.
 * name: stringa contenente il nome del contatto da cercare.
 * valore di ritorno: puntatore a una nuova stringa allocata dinamicamente contenente il numero di telefono, oppure NULL se il contatto non esiste.
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

	return ret; //ritorno il numero di telefono re-allocato 
	
}

int add_contact(char *name, char *number){
/* 
 * funzione che aggiunge un nuovo contatto in coda al file dei contatti nel formato CSV "nome,numero,\n".
 * name: stringa contenente il nome del contatto da salvare.
 * number: stringa contenente il numero di telefono da salvare.
 * valore di ritorno: 0 se l'operazione è andata a buon fine, -1 in caso di errore.
 */

	FILE *f = fopen(contacts_file, "a");
	if (f == NULL) return -1;

	fprintf(f, "%s,%s,\n", name, number); //aggiungo il contatto al file dei contatti con il formato "nome,numero,\n" (uso virgola come separatore)
	fflush(f);
	fclose(f);

	return 0;

}


// la struttura di get_permissions e lookup_access è simile a quella di lookup_name, ma invece di restituire il numero di telefono, 
// restituiscono i permessi o verificano la corrispondenza della password.


int get_permissions(char *name){
/* 
 * funzione che cerca un utente nel file delle password e ne recupera il livello di permessi.
 * name: stringa contenente lo username dell'utente.
 * valore di ritorno: intero rappresentante i permessi, oppure -1 se l'utente non viene trovato.
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
 * funzione che verifica le credenziali di accesso confrontando l'hash salvato nel file delle password con quello ricevuto dal client.
 * uname: stringa contenente lo username da autenticare. pass: stringa contenente l'hash esadecimale SHA-512 della password inviata dal client.
 * valore di ritorno: 0 se username e password corrispondono, != 0 (1 o -1) se le creden
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
