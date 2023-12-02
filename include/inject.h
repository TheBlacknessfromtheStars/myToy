//
// Created by 32319 on 2023/11/21.
//

#ifndef ACE_INJECT_H
#define ACE_INJECT_H

#include <stdio.h>
#include <sys/ptrace.h>

#define NT_PRSTATUS 1

typedef uint64_t addr_t;

int process_attach(pid_t pid);
int process_detach(pid_t pid);
int process_cont(pid_t pid);
int process_syscall(pid_t pid);
int process_step(pid_t pid);
int get_regs(pid_t pid, struct user_pt_regs *regs);
int set_regs(pid_t pid, const struct user_pt_regs *regs);
int call_process_fun(pid_t pid, const char *moduleName, addr_t selfFunAddr, const uint64_t arg[7], struct user_pt_regs *ret);
int call_process_libc_fun(pid_t pid, addr_t selfFunAddr, const uint64_t arg[7], struct user_pt_regs *ret);
addr_t call_process_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, off_t offset);
int call_process_munmap(pid_t pid, addr_t start, size_t length);
int call_process_mprotect(pid_t pid, addr_t address, size_t size, int prot);
void* call_process_dlopen(pid_t pid, const char *filename, int flags);
addr_t call_process_dlsym(pid_t pid, void *handle, const char *symbol);
addr_t get_module_base(pid_t pid, const char *moduleName);
addr_t get_module_bss(pid_t pid, const char *moduleName);
pid_t get_process_pid(const char *comm);
addr_t get_process_fun_addr(pid_t pid, const char *moduleName, addr_t selfFunAddr);

#endif //ACE_INJECT_H
