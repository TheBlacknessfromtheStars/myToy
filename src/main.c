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

    test_breakpoint(pid);

    return 0;
}

void test_breakpoint(pid_t pid)
{
    struct user_pt_regs regs;
    struct breakpoint_head head;
    init_head(pid, &head);
    process_attach(pid);
    int status;

    addr_t s;
    //s = get_process_fun_addr(pid, "libc.so", (addr_t)sleep);
    s = get_module_base(pid, "libil2cpp.so");
    if(!s)
    {
	printf("get libil2cpp.so base address.fail\n");
	return;
    }
    s += 0xb7bd80;
    printf("0x%lx\n", s);
    /*create_breakpoint(&head, s, 0);
    process_cont(pid);

    if(wait_breakpoint(&head) < 0)
    {
        printf("wait_breakpoint fail\n");
        return;
    }

    waitpid(pid, &status, WUNTRACED);
    printf("signal: %d\n", WTERMSIG(status));
    delete_breakpoint(&head, 0, s);

    get_regs(pid, &regs);
    printf("Player class addr: 0x%llx\n", regs.regs[0]);
    getchar();*/

    /*for(int i = 0; i < 10; i++)
    {
        if (wait_breakpoint(&head) < 0)
        {
            printf("wait_breakpoint fail\n");
            return;
        }

        process_cont(pid);
    }*/

    process_detach(pid);
}
