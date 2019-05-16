#include "headers/container.h"
#include <string.h>
#include <stdlib.h>


void Print(const ListIP * u, FILE * fp) {
    const ListIP * p = u;
    while(p != NULL){
        fprintf(fp,"%s : %d\n", p->d.address_ip, p->d.count_ip);
        p = p->next;
    }
}

ListIP * Find(ListIP * u, const Data x) {
    ListIP * p = u;
    while(p != NULL){
        if(!strcmp(p->d.address_ip, x.address_ip))
            return p;
        p = p->next;
    }
    return NULL;
}

void AddList(ListIP ** u, const Data x) {
    ListIP * p = (ListIP*)malloc(sizeof(ListIP));
    if(!p)
        return;
    strcpy(p->d.address_ip, x.address_ip);
    p->d.count_ip = x.count_ip;
    p->next = *u;
    *u = p;
}

void Clear(ListIP ** u) {

    if(*u == 0) return;
    ListIP *p = *u;
    ListIP *t;
    while(p) {
      t = p;
      p = p->next;
      free(t);
   }
   *u = NULL;
}

ListIP * Create(const Data d) {
	ListIP *list = (ListIP*)malloc(sizeof(ListIP));
    if(!list) return NULL;
    list->d = d;
	list->next = NULL;
	return list;

}