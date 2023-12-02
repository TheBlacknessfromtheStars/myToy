//
// Created by 32319 on 2023/11/29.
//

#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "inject.h"
#include "memory.h"
#include "breakpoint.h"

breakpoint_t create_breakpoint_node(unsigned int num, unsigned int code, addr_t address)
{
    breakpoint_t node = calloc(1, sizeof(struct breakpoint_list));
    if(!node)
        return NULL;
    node->breakpoint_number = num;
    node->old_code = code;
    node->address = address;
    node->next = NULL;

    return node;
}

void init_head(pid_t pid, struct breakpoint_head *head_ptr)
{
    if(!head_ptr)
    {
        fprintf(stderr, "The input parameter is empty\n");
        return;
    }

    head_ptr->pid = pid;
    head_ptr->list = NULL;
    head_ptr->quantity = 0;
}

int insert_breakpoint_node(struct breakpoint_head *head_ptr, unsigned int code, addr_t address)
{
    head_ptr->quantity++;

    if(!head_ptr->list)
    {
        head_ptr->list = create_breakpoint_node(1, code, address);
        return 0;
    }

    breakpoint_t list = head_ptr->list;
    while(list->next)
        list = list->next;

    list->next = create_breakpoint_node(list->breakpoint_number + 1, code, address);
    if(!list->next)
    {
        fprintf(stderr, "create breakpoint node fail\n");
        return -1;
    }

    return 0;
}

int get_mm_port(pid_t pid, addr_t address)
{
    uint8_t r, w, x, auth;
    auth = get_auth(pid, address);

    r = ACCESS_READ(auth) ? PROT_READ : 0;
    w = ACCESS_WRITE(auth) ? PROT_WRITE : 0;
    x = ACCESS_EXEC(auth) ? PROT_EXEC : 0;

    return r | w | x;
}

uint32_t get_code(pid_t pid, addr_t address)
{
    uint32_t code = 0;
    int old_auth = get_mm_port(pid, address);

    call_process_mprotect(pid, address&(~0xfff), 0x1000, PROT_READ);
    preadv(pid, address, &code, 4);
    call_process_mprotect(pid, address&(~0xfff), 0x1000, old_auth);

    return code;
}

int set_code(pid_t pid, addr_t address, uint32_t code)
{
    int old_auth = get_mm_port(pid, address);
    int ret = 1;

    call_process_mprotect(pid, address&(~0xfff), 0x1000, PROT_WRITE);
    if(pwritev(pid, address, &code, 4) < 0)
        ret = 0;
    call_process_mprotect(pid, address&(~0xfff), 0x1000, old_auth);

    return ret;
}

int create_breakpoint(struct breakpoint_head *head_ptr, addr_t address)
{
    uint32_t brk_code = 0xd4200000;
    uint32_t old_code;

    old_code = get_code(head_ptr->pid, address);
    insert_breakpoint_node(head_ptr, old_code, address);
    set_code(head_ptr->pid, address, brk_code);

    return 0;
}

int delete_breakpoint_num(struct breakpoint_head *head_ptr, uint8_t num)
{
    breakpoint_t list = head_ptr->list, pre, head;
    int ret = -1;

    pre = NULL;
    head = list;
    while(list)
    {
        if(list->breakpoint_number == num)
        {
            set_code(head_ptr->pid, list->address, list->old_code);
            ret = 0;
            breakpoint_t tmp = list->next;
            free(list);
            list = tmp;
            if(pre == NULL)
                head = tmp;
            else
                pre->next = tmp;
            continue;
        }

        pre = list;
        list = list->next;
    }

    head_ptr->list = head;
    return ret;
}

int delete_breakpoint_address(struct breakpoint_head *head_ptr, addr_t address)
{
    breakpoint_t pre, list = head_ptr->list, head;
    int ret = -1;

    pre = NULL;
    head = list;
    while(list)
    {
        if(list->address == address)
        {
            set_code(head_ptr->pid, list->address, list->old_code);
            ret = 0;
            breakpoint_t tmp = list->next;
            free(list);
            list = tmp;
            if(pre == NULL)
                head = tmp;
            else
                pre->next = tmp;
            continue;
        }

        pre = list;
        list = list->next;
    }

    head_ptr->list = head;
    return ret;
}

int delete_breakpoint(struct breakpoint_head *head_ptr, uint8_t num, addr_t address)
{
    int ret;

    waitpid(head_ptr->pid, NULL, WUNTRACED);
    head_ptr->quantity--;
    if(!address)
        ret = delete_breakpoint_num(head_ptr, num);
    else
        ret = delete_breakpoint_address(head_ptr, address);

    return ret;
}

breakpoint_t find_breakpoint(struct breakpoint_head *head_ptr, addr_t address)
{
    breakpoint_t list = head_ptr->list;

    while(list)
    {
        if(list->address == address)
            return list;

        list = list->next;
    }

    return NULL;
}

int wait_breakpoint(struct breakpoint_head *head_ptr)
{
    int status = 0;
    int signal;
    uint32_t old_post_code;
    unsigned int brk_code = 0xd4200000;
    struct user_pt_regs regs;

    waitpid(head_ptr->pid, &status, WUNTRACED);
    signal = WSTOPSIG(status);

    if(signal != 5 || get_regs(head_ptr->pid, &regs) < 0)
        return -1;

    breakpoint_t bp = find_breakpoint(head_ptr, regs.pc);
    if(bp == NULL)
    {
        fprintf(stderr, "find breakpoint fail\n");
        return -1;
    }

    set_code(head_ptr->pid, regs.pc, bp->old_code);
    if(process_step(head_ptr->pid) < 0)
	return -1;

    set_code(head_ptr->pid, regs.pc, brk_code);

    return 0;
}
