/**
 * Sandboxer in Go
 * Brad Campbell
 */

package main

/*
#cgo CFLAGS: -g -Wall
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

const (
	STACK_SIZE     = 1024 * 1024
	MAX_PROCESSES  = 3
	IP_PREFIX      = "127.0.0."
	IP_PREFIX_LEN  = len(IP_PREFIX)
	PTRACE_OPTIONS = syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK
)

const (
	UNK_MODE            = -1
	KERN_MODE           = 0
	HALTED_SYSCALL_MODE = 1
	USER_MODE           = 3
)

type ProcessEntry struct {
	Pid  int
	Mode int
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <directory_path> <user_id>\n", os.Args[0])
		os.Exit(1)
	}

	directoryPath := os.Args[1]
	userID, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: <user_id> arg is not a valid integer: %v\n", err)
		os.Exit(1)
	}

	// Clone a new process with a new PID namespace
	childPid, _, _ := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	if childPid == 0 {
		fmt.Println("In child: ", childPid)

		// `exec` call
		execGuestPython(directoryPath, userID)
	} else {
		fmt.Println("In parent: ", childPid)

		// Sleep for a second to ensure child process is created by the OS
		time.Sleep(1)

		// Construct process table (with first process already accounted for)
		// Go maps: https://go.dev/blog/maps
		procTable := make(map[int]int)
		procTable[int(childPid)] = USER_MODE

		syscall.PtraceSetOptions(int(childPid), PTRACE_OPTIONS)

		// Wait for the initial `exec` call
		var status syscall.WaitStatus
		syscall.Wait4(-1, &status, 0, nil)
		if syscall.WaitStatus.Exited(status) {
			fmt.Fprintf(os.Stderr, "Error: `wait()` failed: %v\n", err)
			os.Exit(1)
		}

		var signal int
		for len(procTable) > 0 {
			// Enter/exit syscall
			syscall.PtraceSyscall(int(childPid), signal)
			signal = 0 // Clear previous signal
			childPid, _ := syscall.Wait4(-1, &status, 0, nil)
			if childPid == -1 {
				break // Exit loop if no children need to execute
			}

			// Ensure this process is accounted for
			_, ok := procTable[int(childPid)]
			if !ok && (len(procTable) < MAX_PROCESSES) {
				procTable[int(childPid)] = USER_MODE
			}
			if !ok {
				syscall.Kill(int(childPid), syscall.SIGKILL)
				continue
			}

			if status.Exited() {
				delete(procTable, int(childPid))
				if len(procTable) > 0 {
					continue
				} else {
					break
				}
			} else if status.Stopped() && (status.StopSignal() == syscall.SIGTRAP) {
				// Get current registers
				regs := &syscall.PtraceRegs{}
				err := syscall.PtraceGetRegs(int(childPid), regs)
				if err != nil {
					return
				}

				if procTable[int(childPid)] == USER_MODE {
					procTable[int(childPid)] = KERN_MODE

					// Block `connect` syscalls with certain IP addressess
					if regs.Orig_rax == syscall.SYS_connect {
						// Read data at %rsi
						// `ip_addr` is part of `struct in_addr`, which is part of `struct sockaddr_in`
						ip_addr := syscall.PtracePeekData(int(child_pid), regs.Rsi+sizeof(C.sa_family_t)+sizeof(C.in_port_t), nil)

						// Convert `s_addr` to string representation
						// char ip_buffer[INET_ADDRSTRLEN];
						// inet_ntop(AF_INET, &ip_addr, ip_buffer, INET_ADDRSTRLEN);

						// // IP Address is (1) not long enough or (2) not the correct "127.0.0." prefix
						// if ((strlen(ip_buffer) < IP_PREFIX_LEN) || (strncmp(IP_PREFIX, ip_buffer, IP_PREFIX_LEN) != 0))
						// {
						// 	regs.orig_rax = -1; // Set to invalid syscall
						// 	ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
						// 	proc_table[tab_index].mode = SYSCALL_BLOCKED_MODE;
						// }
					}
				} else if procTable[int(childPid)] == HALTED_SYSCALL_MODE {
					procTable[int(childPid)] = USER_MODE // Since this is a syscall exit, we set back to `USER_MODE`
					regs.Rax = -EPERM                    // Indicates previous operation was not permitted
					syscall.PtraceSetRegs(int(childPid), regs)
				} else {
					procTable[int(childPid)] = USER_MODE // Since this is a syscall exit, we set back to `USER_MODE`
				}
				signal = 0 // Clear SIGTRAP signal

			} else if status.Stopped() && (status.StopSignal() != syscall.SIGTRAP) {
				signal = int(status.StopSignal())
			}
		}
	}
	return
}

func strToIntSafe(str string) (int, error) {
	placeholder, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error encountered in `strtol`: %v", err)
	}

	if placeholder < 0 || placeholder > int64(math.MaxInt64) {
		return 0, errors.New("provided integer is out of range")
	}

	return int(placeholder), nil
}

func execGuestPython(directoryPath string, userID int) error {
	if err := os.Chdir(directoryPath); err != nil {
		return fmt.Errorf("error: `chdir()` failed: %v", err)
	}

	if err := syscall.Setuid(userID); err != nil {
		return fmt.Errorf("error: setting effective user ID failed: %v", err)
	}

	cmd := exec.Command("python3", "guest.pyc")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error: `execvp()` failed: %v", err)
	}

	return nil
}
