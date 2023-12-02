//
// Created by 32319 on 2023/11/21.
//

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "inject.h"
#include "tool.h"
#include "memory.h"

int process_attach(pid_t pid)
{
    if(ptrace(PT_ATTACH, pid) < 0)
    {
        perror("process_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

int process_detach(pid_t pid)
{
    if(ptrace(PT_DETACH, pid, NULL, 0) < 0)
    {
        perror("process_detach");
        return -1;
    }

    return 0;
}

int process_syscall(pid_t pid)
{
    if(ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0)
    {
	perror("process_syscall");
	return -1;
    }

    return 0;
}

int process_cont(pid_t pid)
{
    if(ptrace(PT_CONT, pid, NULL, 0) < 0)
    {
        perror("process_cont");
        return -1;
    }

    return 0;
}

int process_step(pid_t pid)
{
    if(ptrace(PTRACE_SINGLESTEP, pid, NULL, 0) < 0)
    {
	perror("process_step");
	return -1;
    }
    
    int status;
    waitpid(pid, &status, WUNTRACED);
    if(WSTOPSIG(status) != 5)
	return -1;

    return 0;
}

int get_regs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec iov;
    u_long getRegs = NT_PRSTATUS;

    iov.iov_base = regs;
    iov.iov_len = sizeof(struct user_pt_regs);
    if(ptrace(PTRACE_GETREGSET, pid, (void *)getRegs, &iov) < 0)
    {
        perror("get_regs");
        return -1;
    }

    return 0;
}

int set_regs(pid_t pid, const struct user_pt_regs *regs)
{
    struct iovec iov;
    u_long setRegs = NT_PRSTATUS;

    iov.iov_base = (void *)regs;
    iov.iov_len = sizeof(struct user_pt_regs);
    if(ptrace(PTRACE_SETREGSET, pid, (void *)setRegs, &iov) < 0)
    {
        perror("set_regs");
        return -1;
    }

    return 0;
}

addr_t get_module_base(pid_t pid, const char *moduleName)
{
    if(!moduleName)
        return 0;

    addr_t base_start = 0;
    char maps_path[24] = {0};
    char *line = NULL;

    if(pid > 0)
        sprintf(maps_path, "/proc/%d/maps", pid);
    else
        sprintf(maps_path, "/proc/self/maps");
    FILE *maps = fopen(maps_path, "r");
    if(!maps)
    {
        fprintf(stderr, "open %s fail\n", maps_path);
        perror("get_module_base");
        return 0;
    }

    line = calloc(4096, sizeof(char));
    size_t len;
    char *tmp;

    while(!feof(maps))
    {
        if(!fgets(line, 4095, maps))
            continue;
        len = strlen(line);
        tmp = line + (len - 1);
        while(*(tmp - 1) != ' ' && *(tmp - 1) != '/')
            tmp--;
        if(strncmp(tmp, moduleName, strlen(moduleName)) == 0)
        {
            char *end_ptr = NULL;
            base_start = strtoul(line, &end_ptr, 16);
            break;
        }
    }

    free(line);
    fclose(maps);
    return base_start;
}

addr_t get_module_bss(pid_t pid, const char *moduleName)
{
    if(!moduleName)
        return 0;

    addr_t bss_start = 0;
    char maps_path[24] = {0};
    char *line = NULL;

    if(pid > 0)
        sprintf(maps_path, "/proc/%d/maps", pid);
    else
        sprintf(maps_path, "/proc/self/maps");
    FILE *maps = fopen(maps_path, "r");
    if(!maps)
    {
        fprintf(stderr, "open %s fail\n", maps_path);
        perror("get_module_base");
        return 0;
    }

    line = calloc(4096, sizeof(char));
    size_t len;
    char *tmp;

    while(!feof(maps))
    {
        if(!fgets(line, 4095, maps))
            continue;
        len = strlen(line);
        tmp = line + (len - 1);
        while(*(tmp - 1) != ' ' && *(tmp - 1) != '/')
            tmp--;
        if(strncmp(tmp, moduleName, strlen(moduleName)) == 0)
        {
            while(!feof(maps))
            {
                if(!fgets(line, 4095, maps))
                    continue;
                if(strstr(line, moduleName) != NULL)
                    continue;
                else
                {
                    if (strstr(line, "[anon:.bss]") != NULL)
                    {
                        char *end_ptr = NULL;
                        bss_start = strtoul(line, &end_ptr, 16);
                        break;
                    } else
                        break;
                }
            }
            break;
        }
    }

    free(line);
    fclose(maps);
    return bss_start;
}

pid_t get_process_pid(const char *comm)
{
    if(!comm)
        return -1;
    pid_t pid = -1;
    DIR *proc = opendir("/proc");
    if(!proc)
    {
        fprintf(stderr, "open /proc fail\n");
        perror("get_process_pid");
        return -1;
    }
    struct dirent *proc_content;

    FILE *fp = fopen("d.log", "w");
    while((proc_content = readdir(proc)) != NULL)
    {
        if(proc_content->d_type != DT_DIR)
            continue;
        char ch = proc_content->d_name[0];
        if(ch >= '1' && ch <= '9')
        {
            char cmdline_path[21] = {0};
            char process_name[256] = {0};
            sprintf(cmdline_path, "/proc/%s/cmdline", proc_content->d_name);
            FILE *cmdline_fp = fopen(cmdline_path, "r");
            if(!cmdline_fp)
            {
                fprintf(stderr, "open %s fail\n", cmdline_path);
                perror("get_process_pid");
                break;
            }
            fgets(process_name, 255, cmdline_fp);
            fclose(cmdline_fp);
            remove_line_break(process_name, 255);
            fprintf(fp, "%s | %s\n", proc_content->d_name, process_name);

            if(strncmp(process_name, comm, 15) == 0)
            {
                char *end_ptr = NULL;
                pid = (pid_t)strtol(proc_content->d_name, &end_ptr, 10);
                if(*end_ptr != '\0')
                {
                    perror("strtol");
                    fprintf(stderr, "%s\n", end_ptr);
                }
                break;
            }
        }
    }

    if(pid == -1)
    {
        fprintf(stderr, "find %s fail\n", comm);
    }

    closedir(proc);
    fclose(fp);
    return pid;
}

addr_t get_process_fun_addr(pid_t pid, const char *moduleName, addr_t selfFunAddr)
{
    addr_t processModuleBase = get_module_base(pid, moduleName);
    addr_t selfModuleBase = get_module_base(-1, moduleName);
    return selfFunAddr - selfModuleBase + processModuleBase;
}

int call_process_fun(pid_t pid,
                     const char *moduleName,
                     addr_t selfFunAddr,
                     const uint64_t arg[7],
                     struct user_pt_regs *ret)
{
    addr_t processFunAddr = get_process_fun_addr(pid, moduleName, selfFunAddr);
    struct user_pt_regs old_regs, new_regs;

    if(get_regs(pid, &old_regs) < 0)
        return -1;
    memcpy(&new_regs, &old_regs, sizeof(struct user_pt_regs));
    for(int i = 0; i < 7; i++)
        new_regs.regs[i] = arg[i];
    new_regs.regs[30] = 0x0;
    new_regs.pc = processFunAddr;
    if(set_regs(pid, &new_regs) < 0)
        return -1;
    int status = 0;
    do{
        if(process_cont(pid) < 0)
            return -1;
        waitpid(pid, &status, WUNTRACED);
    }while(status != 0xb7f);

    if(ret)
    {
        if (get_regs(pid, ret) < 0)
            return -1;
    }
    if(set_regs(pid, &old_regs) < 0)
        return -1;

    return 0;
}

int call_process_libc_fun(pid_t pid,
                          addr_t selfFunAddr,
                          const uint64_t arg[7],
                          struct user_pt_regs *ret)
{
    return call_process_fun(pid, "libc.so", selfFunAddr, arg, ret);
}

addr_t call_process_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
    uint64_t arg[7] = {0};
    struct user_pt_regs regs;
    
    arg[0] = (uint64_t)start;
    arg[1] = (uint64_t)length;
    arg[2] = (uint64_t)prot;
    arg[3] = (uint64_t)flags;
    arg[4] = (uint64_t)fd;
    arg[5] = (uint64_t)offset;
    if(call_process_libc_fun(pid, (uint64_t)mmap, arg, &regs) < 0)
    {
        fprintf(stderr, "call process function mmap fail\n");
        return 0;
    }
    
    return regs.regs[0];
}

void call_process_munmap(pid_t pid, addr_t start, size_t length)
{
    struct user_pt_regs regs;
    uint64_t arg[7] = {0};

    arg[0] = (uint64_t)start;
    arg[1] = (uint64_t)length;

    if(call_process_libc_fun(pid, (uint64_t)munmap, arg, &regs) < 0)
    {
        fprintf(stderr, "call process function munmap fail\n");
	return -1;
    }

    return (int)regs.regs[0];
}

int call_process_mprotect(pid_t pid, addr_t address, size_t size, int prot)
{
    uint64_t arg[7] = {0};
    struct user_pt_regs regs;

    arg[0] = address;
    arg[1] = size;
    arg[2] = prot;
    call_process_libc_fun(pid, (addr_t)mprotect, arg, &regs);

    return (int)regs.regs[0];
}

void* call_process_dlopen(pid_t pid, const char *filename, int flags)
{
    uint64_t arg[7] = {0};
    struct user_pt_regs regs;
    int flag;

    addr_t buf = call_process_mmap(pid, 0, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
    if(buf == 0)
    {
	fprintf(stderr, "call mmap fail\n");
	return NULL;
    }

    pwritev(pid, buf, (void *)filename, strlen(filename));

    arg[0] = (uint64_t)buf;
    arg[1] = (uint64_t)flags;
    flag = call_process_fun(pid, "libdl.so", (uint64_t)dlopen, arg, &regs);
    call_process_munmap(pid, buf, 0x1000);
    if(flag < 0)
    {
        fprintf(stderr, "call process function dlopen fail\n");
        return 0;
    }

    if(regs.regs[0] == arg[0])
        return 0;

    return (void *)regs.regs[0];
}

addr_t call_process_dlsym(pid_t pid, void *handle, const char *symbol)
{
    uint64_t arg[7] = {0};
    struct user_pt_regs regs;
    int flag;

    arg[0] = (uint64_t)handle;
    arg[1] = (uint64_t)symbol;
    addr_t buf = call_process_mmap(pid, 0, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
    if(buf == 0)
    {
        fprintf(stderr, "call mmap fail\n");
	return 0;
    }
	
    pwritev(pid, buf, (void *)symbol, strlen(symbol));
    flag = call_process_fun(pid, "libdl.so", (uint64_t)dlsym, arg, &regs);
    call_process_munmap(pid, buf, 0x1000);

    if(flag < 0)
    {
        fprintf(stderr, "call process function dlopen fail\n");
        return 0;
    }

    if(regs.regs[0] == arg[0])
        return 0;

    return regs.regs[0];
}
