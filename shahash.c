#include <openssl/sha.h> 
#include <stdio.h>
#include <stdlib.h>
#include "shahash.h"
#include <string.h>

char* sha512_hash(const char* str) {
    /*
     * funzione che calcola l'hash crittografico SHA-512 di una stringa e lo converte in formato esadecimale.
     * str: stringa in chiaro da crittografare.
     * valore di ritorno: puntatore alla stringa esadecimale allocata dinamicamente (128 caratteri + '\0'), oppure NULL in caso di errore di allocazione.
     */
    
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
