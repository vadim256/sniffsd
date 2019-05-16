#ifndef CONTAINER_H_
#define CONTAINER_H_

#include <stdio.h>

typedef struct data {
    char address_ip[256];
    int count_ip;
} Data;

typedef struct list_ip{
    Data d;
    struct list_ip * next;
} ListIP;

ListIP * Create(const Data);
void Print(const ListIP *, FILE * fp);
ListIP * Find(ListIP *, const Data);
void AddList(ListIP **, const Data);
void Clear(ListIP **);

#endif