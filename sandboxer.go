/**
 * Sandboxer in Go
 * Brad Campbell
 */

package main

/*
#cgo CFLAGS: -g -Wall
#include <sys/user.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
*/
import "C"

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
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
	childPid, _, err := syscall.Syscall(syscall.SYS_CLONE, 0, 0, 0)
	if childPid < 0 {
		fmt.Fprintf(os.Stderr, "Error: `clone` failure: %v\n", err)
	} else if childPid == 0 {
		fmt.Println("In child: ", childPid)

		// `exec` call
		err := execGuestPython(directoryPath, userID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: `execGuestPython` failure: %v\n", err)
		}
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
		_, err := syscall.Wait4(-1, &status, 0, nil)
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
					fmt.Fprintf(os.Stderr, "Error: `PtraceGetRegs()` failed: %v\n", err)
					return
				}

				if procTable[int(childPid)] == USER_MODE {
					procTable[int(childPid)] = KERN_MODE

					// Block `connect` syscalls with certain IP addressess
					if regs.Orig_rax == syscall.SYS_CONNECT {
						// Read data at %rsi
						// `ip_addr` is part of `struct in_addr`, which is part of `struct sockaddr_in`
						var ip_addr []byte
						bytesRead, err := syscall.PtracePeekData(int(childPid), uintptr(regs.Rsi+uint64(unsafe.Sizeof(C.sa_family_t(0)))+uint64(unsafe.Sizeof(C.in_port_t(0)))), ip_addr)
						if err != nil || bytesRead == 0 {
							fmt.Fprintf(os.Stderr, "Error: `PtracePeekData()` failed: %v\n", err)
							return
						}

						// Convert `s_addr` to string representation
						ipBuffer := net.ParseIP(string(ip_addr))
						if ipBuffer == nil {
							fmt.Fprintf(os.Stderr, "Error: Invalid IP address")
							return
						}

						// IP Address is (1) not long enough or (2) not the correct "127.0.0." prefix
						if len(ipBuffer) < IP_PREFIX_LEN || strings.Compare(IP_PREFIX, ipBuffer[:IP_PREFIX_LEN].String()) != 0 {
							regs.Orig_rax = math.MaxInt // Set to invalid syscall
							syscall.PtraceSetRegs(int(childPid), regs)
							procTable[int(childPid)] = HALTED_SYSCALL_MODE
						}
					}
				} else if procTable[int(childPid)] == HALTED_SYSCALL_MODE {
					procTable[int(childPid)] = USER_MODE // Since this is a syscall exit, we set back to `USER_MODE`
					regs.Rax = uint64(syscall.EPERM)     // Indicates previous operation was not permitted
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
		return 0, fmt.Errorf("provided integer is out of range")
	}

	return int(placeholder), nil
}

func execGuestPython(directoryPath string, userID int) error {
	_, _, errno := syscall.Syscall(syscall.PTRACE_TRACEME, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("error: PTRACE_TRACEME failed: %s", errno.Error())
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error: `os.Getwd()` failed: %v", err)
	}

	if err := os.Chdir(dir + directoryPath); err != nil {
		return fmt.Errorf("error: `os.Chdir()` failed: %v", err)
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
