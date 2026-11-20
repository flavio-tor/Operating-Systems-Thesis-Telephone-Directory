#include "net_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

short int strtoport(char *port){ 
    /* 
     * funzione che converte una stringa contenente un numero di porta in un intero in NBO (network byte order).
     * port: stringa che rappresenta il numero di porta (es. "8080").
     * valore di ritorno: numero di porta convertito in NBO, oppure -1 in caso di errore.
    */

#ifdef DEBUG
    printf("started strtoport\n");
#endif

    short int host = atoi(port); // string -> num HBO/LE (host byte order / little endian)
    short int net = htons(host); // num HBO/LE -> num NB0/BE (network byte order / big endian)

#ifdef DEBUG
    printf("converted port is %d\n", net);
#endif

    return net; //porta in NBO

}

unsigned long strtoaddr(char *addr){ 
    /*
     * funzione che converte una stringa contenente un indirizzo IPv4 in un intero binario in NBO.
     * addr: stringa che rappresenta l'indirizzo IPv4 (es. "127.0.0.1").
     * valore di ritorno: indirizzo IPv4 convertito in network byte order, oppure -1 se il formato non è valido.
     */

#ifdef DEBUG
    printf("started strtoaddr\n");
#endif

    unsigned int a1, a2, a3, a4;

    int num = sscanf(addr, "%d.%d.%d.%d", &a1, &a2, &a3, &a4); //restituisce #valori letti con successo
    if (num < 4) return -1;

    unsigned long ret = a1 + (a2 << 8) + (a3 << 16) + (a4 << 24);

#ifdef DEBUG
    printf("converted address is %lu\n", ret);
#endif

    return ret; //indirizzo in NBO

}
