#include "../headers/container.h"
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

node * create(node * root, Data key){
    node * tmp = (node*) malloc(sizeof(node));
    if(tmp == NULL)
        return tmp;
    tmp->key = key;
    tmp->parent = NULL;
    tmp->left = tmp->right = NULL;
    root = tmp;
    return tmp;
}

node * add(node * root, Data key){
    node * root2 = root, * root3 = NULL;
    node * tmp = (node*) malloc(sizeof(node));
    if(tmp == NULL)
        return tmp;
    tmp->key = key;
    while(root2 != NULL){
        root3 = root2;
        if(strcmp(key.address_ip, root2->key.address_ip) < 0){
            root2 = root2->left;
        } else {
            root2 = root2->right;
        }
    }
    tmp->parent = root3;
    tmp->left = NULL;
    tmp->right = NULL;
    
    if(strcmp(key.address_ip, root3->key.address_ip) < 0) 
        root3->left = tmp;
    else root3->right = tmp;

    return root;        
}

node * search(node * root, Data key){
    if(root == NULL || strcmp(key.address_ip, root->key.address_ip) == 0)
        return root;
    if(strcmp(key.address_ip, root->key.address_ip) < 0) search(root->left, key);

    else search(root->right, key);
}

void preorder(node * root, FILE * fd){
    if(root == NULL)
        return;
    if(root->key.count_ip >= 1)
        fprintf(fd, "%s | %d\n", root->key.address_ip, root->key.count_ip);
    preorder(root->left, fd);
    preorder(root->right, fd);
}