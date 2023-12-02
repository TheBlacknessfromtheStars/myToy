#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include "breakpoint.h"
#include "inject.h"
#include "memory.h"

#define VERSION "0.1"

void print_help()
{
    printf("ace %s\n\n", VERSION);
    printf("Usage: ace [pid]\n");
}

void test_breakpoint(pid_t pid);

int main(int argc, char *argv[])
{
    pid_t pid = 0;

    if(argc < 2)
    {
        print_help();
        return 0;
    }

    for(int i = 1; i < argc; i++)
    {
        int ch = argv[i][0];
        if(pid == 0)
        {
            if (ch >= '0' && ch <= '9')
            {
                char *end_ptr;
                pid = (pid_t) strtol(argv[i], &end_ptr, 0);
                break;
            } else
	    {
                pid = get_process_pid(argv[i]);
		break;
	    }
        }
    }

    printf("pid=%d\n", pid);
    if(pid < 1)
    {
        fprintf(stderr, "input not valid\n");
        return -1;
    }

    /*process_attach(pid);

    char so_path[1024] = {0};
    char cmd[1536] = {0};
    sprintf(so_path, "/data/data/%s/files/%s", argv[1], argv[2]);
    sprintf(cmd, "cp %s %s", argv[2], so_path);
    system(cmd);
    sprintf(cmd, "chmod 777 %s", so_path);
    system(cmd);

    
    if(call_process_dlopen(pid, so_path, RTLD_LAZY) == NULL)
    {
	uint64_t arg[7] = {0};
	struct user_pt_regs regs;
	char msg[128] = {0};
	call_process_fun(pid, "libdl.so", (addr_t)dlerror, arg, &regs);
	printf("0x%llx\n", regs.regs[0]);
	if(regs.regs[0] != 0)
	{
	    preadv(pid, regs.regs[0], msg, 128);
	    printf("%s\n", msg);
	}
    }

    process_detach(pid);*/
    test_breakpoint(pid);
    return 0;
}

void test_breakpoint(pid_t pid)
{
    struct user_pt_regs regs;
    struct breakpoint_head head;
    init_head(pid, &head);
    process_attach(pid);
    int status, signal;

    addr_t s = get_process_fun_addr(pid, "libc.so", (addr_t)sleep);
    create_breakpoint(&head, s);
    process_cont(pid);

    for(int i = 0; i < 10; i++)
    {
        if (wait_breakpoint(&head) < 0)
        {
            printf("wait_breakpoint fail\n");
            return;
        }
        get_regs(pid, &regs);
        printf("0x%llx\n", regs.pc);
	getchar();
        process_cont(pid);
    }

    delete_breakpoint(&head, 0, s);
    process_detach(pid);
}
