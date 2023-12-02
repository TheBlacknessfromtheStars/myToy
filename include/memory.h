//
// Created by 32319 on 2023/11/25.
//

#ifndef ACE_MEMORY_H
#define ACE_MEMORY_H

#include <stdio.h>
#include <string.h>
#include "inject.h"

#define ACCESS_READ(auth) (((auth)&8)>>3)
#define ACCESS_WRITE(auth) (((auth)&4)>>2)
#define ACCESS_EXEC(auth) (((auth)&2)>>1)

struct memInfo
{
    char segmentName[4096];
    uint8_t auth;
    int type;
    addr_t start;
    addr_t end;
    struct memInfo *next;
};
typedef struct memInfo memInfo_t;
typedef struct memInfo* memInfo_ptr;

struct memHead
{
    pid_t pid;
    memInfo_ptr types[9];
};

struct hitList
{
    size_t size;
    size_t current;
    addr_t *hitList;
};

enum
{
    Mem_Ca,
    Mem_Cb,
    Mem_Cd,
    Mem_Xa,
    Mem_Xs,
    Mem_A,
    Mem_J,
    Mem_S,
    Mem_O,
};

enum
{
    DWORD,
    BYTE,
    WORD,
    QWORD,
    FLOAT,
    DOUBLE,
};

ssize_t preadv(pid_t pid, addr_t address, void *buf, size_t size);
ssize_t pwritev(pid_t pid, addr_t address, void *buf, size_t size);
size_t judg_size(int type);
memInfo_ptr memInfo_alloc_node();
uint8_t parse_auth(const char *authStr);
int get_mem_type(char *str);
int process_mem_classify(pid_t pid, struct memHead *head);
void release_mem_classify(struct memHead *head);
int search(struct memHead *head, void *buf, int type, struct hitList *hits, int memType);
int init_hit_list(struct hitList *vec, size_t size);
int hit_list_insert(struct  hitList *vec, addr_t addr);
int hit_list_delete(struct  hitList *vec, addr_t addr);
int hit_list_free(struct hitList *vec);

unsigned char get_auth(pid_t pid, addr_t address);

#endif //ACE_MEMORY_H
