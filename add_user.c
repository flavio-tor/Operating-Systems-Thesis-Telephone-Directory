#include "shahash.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <crypt.h>
#define flush(stdin) while(getchar() != '\n')

int main(){
	
	char *name, *pass;
	int perms, n;

	printf("name: ");
	fflush(stdout);
	scanf("%ms", &name);
	printf("password: ");
	fflush(stdout);
	scanf("%ms", &pass);

perms:

	printf("perms (0 rd, 1 wr, 2 rdwr): ");
	
	if(scanf("%d", &perms) != 1){
		flush(stdin);
		printf("invalid value; try again\n");
		goto perms;
	}

	if (perms < 0 || perms > 2){
		printf("not a valid permission; try again\n");
		goto perms;
	}

	char *cr = sha512_hash(pass);

	FILE *f = fopen("passwd", "a");

	fprintf(f, "%s,%s,%d,\n", name, cr, perms);

	fclose(f); 

	return 0;
}

