//
// Created by 32319 on 2023/11/29.
//

#ifndef ACE_BREAKPOINT_H
#define ACE_BREAKPOINT_H

#include "inject.h"

struct breakpoint_list
{
    unsigned int breakpoint_number;
    unsigned int old_code;
    addr_t address;
    struct breakpoint_list *next;
};
typedef struct breakpoint_list* breakpoint_t;

struct breakpoint_head
{
    pid_t pid;
    size_t quantity;
    breakpoint_t list;
};

void init_head(pid_t pid, struct breakpoint_head *head_ptr);
int create_breakpoint(struct breakpoint_head *head_ptr, addr_t address);
int delete_breakpoint(struct breakpoint_head *head_ptr, uint8_t num, addr_t address);
breakpoint_t find_breakpoint(struct breakpoint_head *head_ptr, addr_t address);
int wait_breakpoint(struct breakpoint_head *head_ptr);

#endif //ACE_BREAKPOINT_H
