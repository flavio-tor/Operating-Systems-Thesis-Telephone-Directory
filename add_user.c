#include "shahash.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <crypt.h>
#define flush(stdin) while(getchar() != '\n') //puliamo lo stdin (tasto invio)

int main(){
	
	char *name, *pass; //nome utente, password in chiaro
	int perms; //permessi dell'utente 

	printf("name: ");
	fflush(stdout);
	scanf("%ms", &name);
	printf("password: ");
	fflush(stdout);
	scanf("%ms", &pass);

perms:

	printf("perms (0 rd, 1 wr, 2 rdwr): ");
	
	if(scanf("%d", &perms) != 1){ //verifico che l'input sia un intero
		flush(stdin);
		printf("invalid value; try again\n");
		goto perms;
	}

	if (perms < 0 || perms > 2){ //verifico validità dei permessi
		printf("not a valid permission; try again\n");
		goto perms;
	}

	char *cr = sha512_hash(pass); //crittografia della password

	FILE *f = fopen("passwd", "a");

	fprintf(f, "%s,%s,%d,\n", name, cr, perms); //formatto la riga come: nome,hash,permessi
	fclose(f); 

	return 0;
}

