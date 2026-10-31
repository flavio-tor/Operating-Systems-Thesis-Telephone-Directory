#include "net_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

short int strtoport(char *port){ //es. "8080"
    /* 
     * questa funzione converte una stringa che indica una porta,
     * in un intero che rappresenta la porta in network byte order
     * (ritorna -1 in caso di errore)
    */

#ifdef DEBUG
    printf("started strtoport\n");
#endif

    short int host = atoi(port); //HBO
    short int net = htons(host); //NB0

#ifdef DEBUG
    printf("converted port is %d\n", net);
#endif

    return net; //porta in NBO

}

unsigned long strtoaddr(char *addr){ //es. "127.0.0.1"
    /*
     * questa funzione converte una stringa che indica un indirizzo IP
     * in un intero che rappresenta l'indirizzo in network byte order
     * (ritorna -1 in caso di errore)
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
