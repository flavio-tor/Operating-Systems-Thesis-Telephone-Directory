#include <openssl/sha.h> //pppppp
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "shahash.h"
#include <string.h>

char* sha512_hash(const char* str) {
    
    unsigned char hash[SHA512_DIGEST_LENGTH];  //buffer per hash binario
    
    //cacolo dell'hash (inizializza il contesto SHA-512)
    SHA512(str, strlen(str), hash);

    //alloca stringa per rappresentazione esadecimale
    char* output = malloc((SHA512_DIGEST_LENGTH * 2) + 1); //in esadecimale ogni B è rappresentato da 2 caratteri + 1 per \0
    if (output == NULL) {
        return NULL;
    }

    //
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) { //scorro i 64 B binari
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA512_DIGEST_LENGTH * 2] = '\0';

    return output;  //ricorda di fare free() quando non serve più
}
