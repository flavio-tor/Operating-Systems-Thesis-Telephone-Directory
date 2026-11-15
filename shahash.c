#include <openssl/sha.h> 
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "shahash.h"
#include <string.h>

char* sha512_hash(const char* str) {
    
    unsigned char hash[SHA512_DIGEST_LENGTH];  //buffer per hash binario
    
    SHA512(str, strlen(str), hash); //calcolo dell'hash

    char* output = malloc((SHA512_DIGEST_LENGTH * 2) + 1); //alloco stringa per rappresentazione esadecimale
    if (output == NULL) {
        return NULL;
    }

    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]); //binario -> esadecimale
    }
    output[SHA512_DIGEST_LENGTH * 2] = '\0';

    return output;  //ricorda di fare free() quando non serve più
}
