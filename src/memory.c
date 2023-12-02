//
// Created by 32319 on 2023/11/25.
//

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syscall.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/uio.h>
#include "memory.h"
#include "tool.h"

ssize_t preadv(pid_t pid, addr_t address, void *buf, size_t size)
{
    struct iovec writeBuffer, writeOffset;

    writeBuffer.iov_base = buf;
    writeBuffer.iov_len = size;
    writeOffset.iov_base = (void *)address;
    writeOffset.iov_len = size;
    ssize_t ret = syscall(SYS_process_vm_readv, pid, &writeBuffer, 1, &writeOffset, 1, 0);
    if(ret < 0)
    {
	fprintf(stderr, "read 0x%lx fail\n", address);
        perror("preadv");
    }
    return ret;
}

int read_mem(pid_t pid, addr_t address, void *buf, size_t size)
{
    char mem_path[26] = {0};
    sprintf(mem_path, "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if(mem_fd < 0)
    {
	fprintf(stderr, "open %s fail\n", mem_path);
	return -1;
    }

    if(pread64(mem_fd, buf, size, address) < 0)
    {
	close(mem_fd);
	fprintf(stderr, "read data fail\n");
	perror("read_mem");
	return -1;
    }

    close(mem_fd);
    return 0;
}

ssize_t pwritev(pid_t pid, addr_t address, void *buf, size_t size)
{
    struct iovec writeBuffer, writeOffset;

    writeBuffer.iov_base = buf;
    writeBuffer.iov_len = size;
    writeOffset.iov_base = (void *)address;
    writeOffset.iov_len = size;
    ssize_t ret = syscall(SYS_process_vm_writev, pid, &writeBuffer, 1, &writeOffset, 1, 0);
    if(ret < 0)
    {
	fprintf(stderr, "write 0x%lx fail\n", address);
        perror("pwritev");
    }
    return ret;
}

int write_mem(pid_t pid, addr_t address, void *buf, size_t size)
{
    char mem_path[26] = {0};
    sprintf(mem_path, "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_WRONLY);
    if(mem_fd < 0)
    {
        fprintf(stderr, "open %s fail\n", mem_path);
        return -1;
    }

    if(pwrite64(mem_fd, buf, size, address) < 0)
    {
        close(mem_fd);
        fprintf(stderr, "write data fail\n");
        perror("write_mem");
        return -1;
    }

    close(mem_fd);
    return 0;
}

int get_mem_type(char *str)
{
    if(strlen(str) == 0 || str[0] == ' ')
        return Mem_A;
    if(str[0] == '\0')
        return Mem_A;
    if(strstr(str, "/data/app") != NULL || strstr(str, ".so") != NULL)
        return Mem_Xa;
    if(strstr(str, "/system/framework") != NULL)
        return Mem_Xs;
    if(strstr(str, "[anon:libc_malloc]") != NULL)
        return Mem_Ca;
    if(strstr(str, ":.bss") != NULL)
        return Mem_Cb;
    if(strstr(str, "/data/data") != NULL)
        return Mem_Cd;
    if(strstr(str, "[anon:dalvik") != NULL)
        return Mem_J;
    if(strstr(str, "[stack]") != NULL)
        return Mem_S;
    return Mem_O;
}

size_t judg_size(int type)
{
    switch(type)
    {
        case BYTE:
            return sizeof(char);
        case WORD:
            return sizeof(short);
        case DWORD:
            return sizeof(int);
        case FLOAT:
            return sizeof(float);
        case QWORD:
            return sizeof(long);
        case DOUBLE:
            return sizeof(double);
        default:
            return 4;
    }
}

memInfo_ptr memInfo_alloc_node()
{
    memInfo_ptr ret = calloc(1, sizeof(memInfo_t));

    ret->type = Mem_O;

    return ret;
}

uint8_t parse_auth(const char *authStr)
{
    uint8_t r, w, x, y;
    r = authStr[0] == 'r' ? 8 : 0;
    w = authStr[1] == 'w' ? 4 : 0;
    x = authStr[2] == 'x' ? 2 : 0;
    y = authStr[4] == 'x' ? 1 : 0;

    return r | w | x | y;
}

int process_mem_classify(pid_t pid, struct memHead *head)
{
    char maps_path[18] = {0};
    char line[1024] = {0};
    memInfo_ptr types[9] = {0};
    memcpy(types, head->types, 9*sizeof(memInfo_ptr));
    head->pid = pid;
    snprintf(maps_path, 18, "/proc/%d/maps", pid);
    FILE *maps_fp = fopen(maps_path, "r");
    if(!maps_fp)
        return -1;
    for (int i = 0; i < 9; i++)
    {
        while(types[i] && types[i]->next != NULL)
            types[i] = types[i]->next;
    }

    while(!feof(maps_fp))
    {
        memset(line, 0, 1023);
        if(!fgets(line, 1023, maps_fp))
            continue;
        char auth[5] = {0};
        char *end_ptr;

        remove_line_break(line, 1023);
        memInfo_ptr node = memInfo_alloc_node();
        memcpy(node->segmentName, line + 73, strlen(line + 73));
        memcpy(auth, line + 22, 4);

        node->start = strtoul(line, &end_ptr, 16);
        node->end = strtoul(line + 11, &end_ptr, 16);
        node->type = get_mem_type(node->segmentName);
        node->auth = parse_auth(auth);

        if(!types[node->type])
            head->types[node->type] = types[node->type] = node;
        else
        {
            types[node->type]->next = node;
            types[node->type] = node;
        }

    }

    fclose(maps_fp);
    return 0;
}

void release_list(memInfo_ptr node)
{
    if(!node)
        return;
    memInfo_ptr tmp = NULL;

    while(node->next != NULL)
    {
        tmp = node->next;
        free(node);
        node = tmp;
    }

    free(node);
}

void release_mem_classify(struct memHead *head)
{
    for(int i = 0; i < 9; i++)
        release_list(head->types[i]);
    memset(head, 0, sizeof(struct memHead));
}

int init_hit_list(struct hitList *vec, size_t size)
{
    if(!vec)
        return -1;

    vec->size = 100;
    vec->current = 0;
    vec->hitList = calloc(size, sizeof(addr_t));

    return 0;
}

int hit_list_insert(struct  hitList *vec, addr_t addr)
{
    if(!vec || !vec->hitList)
        return -1;

    if(vec->size == 0)
        init_hit_list(vec, 100);

    if(vec->current >= (size_t)((double)vec->size * 0.7))
    {
        vec->size += 100;
        vec->hitList = realloc(vec->hitList, vec->size * sizeof(addr_t));
        if(!vec->hitList)
            return -1;
    }

    vec->hitList[vec->current++] = addr;

    return 0;
}

int hit_list_delete(struct  hitList *vec, addr_t addr)
{
    if(!vec || !vec->hitList)
        return -1;

    for(int i = 0; i < vec->current; i++)
    {
        if(vec->hitList[i] == addr)
            vec->hitList[i] = 0;
    }

    return 0;
}

int hit_list_free(struct hitList *vec)
{
    if(!vec || !vec->hitList)
        return -1;

    vec->size = 0;
    vec->current = 0;
    free(vec->hitList);
    vec->hitList = NULL;

    return 0;
}

bool mem_cmp(void *a, void *b, size_t size)
{
    if(!a || !b)
        return false;
    uint8_t *x = a, *y = b;
    bool ret = true;

    for(size_t i = 0; i < size; i++)
    {
        if(x[i] != y[i])
        {
            ret = false;
            break;
        }
    }

    return ret;
}

int search(struct memHead *head, void *data, int dataType, struct hitList *hits, int memType)
{
    size_t size = judg_size(dataType);
    memInfo_ptr mem_info = head->types[memType];
    if(mem_info == NULL)
    {
        fprintf(stderr, "mem type %d is null\n", memType);
        return -1;
    }
    size_t mem_size = mem_info->end - mem_info->start;
    uint8_t *buf = calloc(mem_size, 1);

    while(mem_info)
    {
        if(ACCESS_READ(mem_info->auth))
        {
            if(preadv(head->pid, mem_info->start, buf, mem_size) == -1)
            {
                fprintf(stderr, "read process memory fail\n");
                free(buf);
                return -1;
            }
            for(size_t i = 0; i < mem_size; i+=size)
            {
                if(mem_cmp(data, buf+i, size))
                    hit_list_insert(hits, mem_info->start + i);
            }
        }
        mem_info = mem_info->next;
    }

    free(buf);
    return 0;
}

memInfo_ptr get_memInfo_node(pid_t pid, addr_t address)
{
    memInfo_t *node = calloc(1, sizeof(memInfo_t));
    memset(node, 0, sizeof(memInfo_t));
    char maps_path[18] = {0};
    char line[1024] = {0};
    snprintf(maps_path, 18, "/proc/%d/maps", pid);
    FILE *maps_fp = fopen(maps_path, "r");
    if(!maps_fp)
        return NULL;

    while(!feof(maps_fp))
    {
        memset(line, 0, 1023);
        if (!fgets(line, 1023, maps_fp))
            continue;
        char auth[5] = {0};
        char *end_ptr;

        remove_line_break(line, 1023);
        addr_t start = strtoul(line, &end_ptr, 16);
        addr_t end = strtoul(line + 11, &end_ptr, 16);
        if(address >= start && address <= end)
        {
            node->start = start;
            node->end = end;
            node->type = get_mem_type(node->segmentName);
            memcpy(auth, line + 22, 4);
            node->auth = parse_auth(auth);
            return node;
        }
    }

    return NULL;
}

unsigned char get_auth(pid_t pid, addr_t address)
{
    memInfo_ptr node = get_memInfo_node(pid, address);
    if(!node)
        return 0xff;
    unsigned char auth = node->auth;
    free(node);

    return auth;
}
