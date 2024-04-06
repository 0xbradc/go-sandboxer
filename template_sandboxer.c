/**
 * CS263 Pset3 on Sandboxing
 * Spring 2024
 * Brad Campbell
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];
static const uint8_t MAX_PROCESSES = 3;
static const int PTRACE_OPTIONS = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL;
static const char IP_PREFIX[] = "127.0.0.";
static const size_t IP_PREFIX_LEN = sizeof(IP_PREFIX) - 1;

struct ChildArgs
{
    char *directory_path;
    int user_id;
};

enum status_modes
{
    UNK_MODE = (int)-1,
    KERNEL_MODE = (int)0,
    SYSCALL_BLOCKED_MODE = (int)1,
    USER_MODE = (int)4,
};

struct ProcessEntry
{
    pid_t pid;
    int mode; // Dictated by `status_modes` enum, but this isn't a hard invariant
};

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <directory_path> <user_id>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Construct arguments
    struct ChildArgs child_args;
    child_args.directory_path = argv[1];
    char *user_id_str = argv[2];
    if ((child_args.user_id = str_to_int_safe(user_id_str)) < 0)
    {
        fprintf(stderr, "Error: <user_id> arg is not a valid integer, or it is not within range\n");
        return EXIT_FAILURE;
    }

    // Clone a new process with a new PID namespace
    pid_t child_pid = clone(child_function, child_stack + STACK_SIZE, CLONE_NEWPID | SIGCHLD, &child_args);
    if (child_pid == -1)
    {
        fprintf(stderr, "Error: `clone()` failed\n");
        return EXIT_FAILURE;
    }
    sleep(1); // Sleep to ensure child process is created by the OS

    // Construct process table (with first process already accounted for)
    struct ProcessEntry proc_table[MAX_PROCESSES];
    setup_proc_table(proc_table, child_pid);
    int live_proc_count = 1; // Indicates number of active guest processess

    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_OPTIONS); // Set ptrace options

    // Wait for the initial `exec` call
    if (wait(NULL) == -1)
    {
        fprintf(stderr, "Error: `wait()` failed\n");
        return EXIT_FAILURE;
    }

    int status;
    int signal;
    while (0 < live_proc_count)
    {
        // Enter/exit syscall
        ptrace(PTRACE_SYSCALL, child_pid, NULL, signal);
        signal = 0; // Clear previous signal
        child_pid = waitpid(-1, &status, __WALL);
        if (child_pid == -1)
        {
            break; // Exit loop if no children need to execute
        }

        // Ensure this process is accounted for
        int tab_index = -1;
        for (int i = 0; i < MAX_PROCESSES; ++i)
        {
            if (proc_table[i].pid == child_pid)
            {
                tab_index = i;
                break;
            }
        }
        // Check if there is room for this process and create table entry if so
        if (tab_index == -1)
        {
            for (int i = 0; i < MAX_PROCESSES; ++i)
            {
                if (proc_table[i].pid == -1)
                {
                    proc_table[i] = (struct ProcessEntry){child_pid, USER_MODE};
                    ++live_proc_count;
                    tab_index = i;
                    break;
                }
            }
        }
        // If there is no room for this process, kill it and repeat loop
        if (tab_index == -1)
        {
            kill(child_pid, SIGKILL);
            continue;
        }

        // If child exited, remove from process table and move onto another process
        if (WIFEXITED(status))
        {
            // Remove killed process from the table and decrement counter
            proc_table[tab_index] = (struct ProcessEntry){-1, UNK_MODE};
            --live_proc_count;

            // If we have another process to be executing, repeat loop
            if (0 < live_proc_count)
            {
                continue;
            }
            // Else, break out of loop and end program
            else
            {
                break;
            }
        }
        // Else-if child is stopped due to a system call, take necessary steps
        else if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGTRAP))
        {
            // Get current registers
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs); 

            // If the process is accounted for and in the syscall entry stage, we need to filter invalid `connect` calls
            if (proc_table[tab_index].mode == USER_MODE)
            {
                proc_table[tab_index].mode = KERNEL_MODE; // Since this is a syscall entry, we set to `KERNEL_MODE`

                // Block `connect` syscalls with certain IP addressess
                if (regs.orig_rax == SYS_connect)
                {
                    // Read data at %rsi
                    in_addr_t ip_addr; // Part of `struct in_addr`, which is part of `struct sockaddr_in`
                    ip_addr = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsi + sizeof(sa_family_t) + sizeof(in_port_t), NULL);

                    // Convert `s_addr` to string representation
                    char ip_buffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip_addr, ip_buffer, INET_ADDRSTRLEN);

                    // IP Address is (1) not long enough or (2) not the correct "127.0.0." prefix
                    if ((strlen(ip_buffer) < IP_PREFIX_LEN) || (strncmp(IP_PREFIX, ip_buffer, IP_PREFIX_LEN) != 0))
                    {
                        regs.orig_rax = -1; // Set to invalid syscall
                        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                        proc_table[tab_index].mode = SYSCALL_BLOCKED_MODE;
                    }
                }
            }
            // Else-if we blocked previous `connect` call, handle graceful exit
            else if (proc_table[tab_index].mode == SYSCALL_BLOCKED_MODE)
            {
                regs.rax = -EPERM; // Indicates previous operation was not permitted
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                proc_table[tab_index].mode = USER_MODE; // Since this is a syscall exit, we set to `USER_MODE`
            }
            // Else, the process is in a syscall exit stage (from a valid syscall)
            else
            {
                proc_table[tab_index].mode = USER_MODE; // Since this is a syscall exit, we set to `USER_MODE`
            }
            signal = 0; // Clear SIGTRAP signal
        }
        // Else-if stopped for a reason other than a syscall, we pass that on signal on
        else if (WIFSTOPPED(status) && (WSTOPSIG(status) != SIGTRAP))
        {
            signal = WSTOPSIG(status);
        }
    }
    return EXIT_SUCCESS;
}

int child_function(void *arg)
{
    ptrace(PTRACE_TRACEME, 0, NULL, NULL); // Ensure this child is tracked by ptrace

    struct ChildArgs *child_args = (struct ChildArgs *)arg;

    // Change directory to the specified one
    if (chdir(child_args->directory_path) == -1)
    {
        fprintf(stderr, "Error: `chdir()` failed\n");
        exit(EXIT_FAILURE);
    }

    // Set the effective user ID (EUID) to the specified `user_id`
    if (seteuid(child_args->user_id) == -1)
    {
        fprintf(stderr, "Error: setting effective user ID failed\n");
        return EXIT_FAILURE;
    }

    // Execute guest.pyc using python3
    char *args[] = {"python3", "guest.pyc", NULL};
    execvp("python3", args);

    // `execvp` only returns if an error occurs
    fprintf(stderr, "Error: `execvp()` failed\n");
    exit(EXIT_FAILURE);
}

static int str_to_int_safe(const char *str)
{
    char *endptr;
    errno = 0;
    long int placeholder = strtol(str, &endptr, 10);

    // Check for conversion errors
    if ((errno == ERANGE && (placeholder == LONG_MAX || placeholder == LONG_MIN)) || (errno != 0 && placeholder == 0))
    {
        fprintf(stderr, "Error: error encounted in `strtol`\n");
        return -1;
    }

    // Check for out-of-range input
    if (placeholder < 0 || placeholder > INT_MAX)
    {
        fprintf(stderr, "Error: provided integer is out of range\n");
        return -1;
    }

    return (int)placeholder;
}

void setup_proc_table(struct ProcessEntry proc_table[], const pid_t child_pid)
{
    proc_table[0] = (struct ProcessEntry){child_pid, USER_MODE};
    for (int i = 1; i < MAX_PROCESSES; ++i)
    {
        proc_table[i] = (struct ProcessEntry){-1, UNK_MODE};
    }
}
