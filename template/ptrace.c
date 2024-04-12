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

// See https://pkg.go.dev/cmd/cgo for information on using C functions in Go
// To use this file directly in Go as a C library, put the following into the top of the Go file
/*
#cgo CFLAGS: -g -Wall
#include "ptrace.c"
*/
// import "C"

int generic_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data)
{
    return ptrace(_request, _pid, _addr, _data);
}
