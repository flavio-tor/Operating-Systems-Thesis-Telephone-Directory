#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <string.h>
#include "lookup.h"
#define NOT_FOUND 2
#define FOUND 1
#define RD 0
#define WR 1
#define RDWR 2

char *contacts_file = "contacts";
char *access_file = "passwd";

/*
 * in questo codice sono contenute tutte le funzioni relative
 * alle interazioni con i file
 */

//attualmente funziona come una ricerca lineare

char *searchname(FILE *f, char *name, char **lookup_tok){

/* this function looks for the name passed in
 * the file passed and returns the line of the file where the name is stored
 * already tokenized once
 */

	int exit_cycle = 0;
	char *buff = NULL, *curr;
	size_t l = 0;
	int len;

	/*
	do{
		if (buff != NULL) free(buff);
		buff = NULL;
		
		if ((len = getline(&buff, &l, f)) < 0){
			if (feof(f)) exit_cycle = NOT_FOUND;
		}
		
		if (buff != NULL && exit_cycle != NOT_FOUND){
			curr = strtok_r(buff, ",", lookup_tok);
			if (strcmp(curr, name) == 0) exit_cycle = FOUND;
		}

	}while(!exit_cycle);

	if (exit_cycle == NOT_FOUND) return NULL;
	*/
	do{
    	if ((len = getline(&buff, &l, f)) < 0){
        	if (feof(f)) exit_cycle = NOT_FOUND;
        }
        else {
            curr = strtok_r(buff, ",", lookup_tok);
            if (curr != NULL && strcmp(curr, name) == 0) {
                exit_cycle = FOUND;
            }
        }
    } while(!exit_cycle);

    if (exit_cycle == NOT_FOUND) {
        if (buff != NULL) free(buff);
        return NULL;
    }
	
	return buff;
	
}

char *lookup_name(char *name){

	if (name == NULL) return NULL;

	FILE *f = fopen(contacts_file, "r");

	if (f == NULL) return NULL;
	
	char *lookup_tok;

	char *buff = searchname(f, name, &lookup_tok);

	fclose(f);

	if (buff == NULL) return NULL;

	char *curr = strtok_r(NULL, ",", &lookup_tok); //phone number

#ifdef DEBUG
	printf("Number to dup: %s\n", curr);
#endif

	char *ret = strdup(curr);

	free(buff);

	return ret; //return the phone number reallocated
}

int add_contact(char *name, char *number){

	FILE *f = fopen(contacts_file, "a");

	fprintf(f, "%s,%s,\n", name, number);
	fflush(f);
	fclose(f);

	return 0;

}

int get_permissions(char *name){
	
	FILE *f = fopen(access_file, "r");

	if (f == NULL) return -1;

	char *lookup_tok;

	char *buff = searchname(f, name, &lookup_tok);

	fclose(f);

	if (buff == NULL) return -1;

	strtok_r(NULL, ",", &lookup_tok); //skip password
	
	char *curr = strtok_r(NULL, ",", &lookup_tok);//get permissions
	
	int ret = atoi(curr);

	free(buff);

	return ret;
}

int lookup_access(char *uname, char *pass){
//ritorna != 0 se non trova una corrispondenza valida
	
	FILE *f = fopen(access_file, "r");

	if (f == NULL) return -1;

	char *lookup_tok;

	char *buff = searchname(f, uname, &lookup_tok);

	fclose(f);

	if (buff == NULL) return -1;

	char *curr = strtok_r(NULL, ",", &lookup_tok);
	
	int ret;

	if (strcmp(curr, pass) == 0){
		ret = 0;
	}
	else ret = 1;

	free(buff);

	return ret;

}
