#include "trace_monitor.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
  long val = ptrace(PTRACE_PEEKUSER, child, off);
  assert(errno == 0);
  return val;
}

long get_syscall_arg(pid_t child, int which) {
  switch (which) {
#ifdef __amd64__
    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);
#else
    case 0: return get_reg(child, ebx);
    case 1: return get_reg(child, ecx);
    case 2: return get_reg(child, edx);
    case 3: return get_reg(child, esi);
    case 4: return get_reg(child, edi);
    case 5: return get_reg(child, ebp);
#endif
    default: return -1L;
  }
}

char *read_string(pid_t child, unsigned long addr) {
  char *val = (char*)malloc(4096);
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  while (1) {
    if (read + sizeof tmp > allocated) {
      allocated *= 2;
      val = (char*)realloc(val, allocated);
    }
    tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
    if(errno != 0) {
      val[read] = 0;
      break;
    }
    memcpy(val + read, &tmp, sizeof tmp);
    if (memchr(&tmp, 0, sizeof tmp) != NULL)
      break;
    read += sizeof tmp;
  }
  return val;
}

int dump_open_file(pid_t child) {
  // open system call
  long arg0 = get_syscall_arg(child, 0);
  char* strval = read_string(child, arg0);
  fprintf(stderr, " file: %s", strval);
  free(strval);
}

void TraceMonitor::BlockSysCall(std::set<int>& syscalls)
{
  m_blockSyscalls = syscalls;
}

void TraceMonitor::StartTrace()
{
  pipe(m_pipefd);
  m_child = fork();
  if (m_child == 0) {
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    // child process, just return to let main program keep process
  } else {
    DoTrace();
    exit(0);
  }
}

void TraceMonitor::EndTrace()
{
  // should only be invoked on child process
  assert(!m_child);
  char buf = 'a';
  close(m_pipefd[0]);
  write(m_pipefd[1], &buf, 1);
  close(m_pipefd[1]);
}

void TraceMonitor::DoTrace()
{
  int status, syscall, retval;
  waitpid(m_child, &status, 0);
  // this keep to monitor SIGTRAP | 0x80 (syscall)
  ptrace(PTRACE_SETOPTIONS, m_child, 0, PTRACE_O_TRACESYSGOOD);
  while(1) {
    if (CheckEndTrace()) {
      fprintf(stderr, "monitor stop\n");
      break;
    }
    if (WaitForSysCall(m_child))
      break;

    syscall = get_reg(m_child, orig_eax);
    // fprintf(stderr, "syscall(%d) ", syscall);
    // Reference syscall number from https://filippo.io/linux-syscall-table/
    if (m_blockSyscalls.find(syscall) != m_blockSyscalls.end()) {
      //dump_open_file(m_child);
      fprintf(stderr, "block system call %d is invoked\n", syscall);
      kill(m_child, SIGKILL);
      break;
    }

    if (WaitForSysCall(m_child)) break;

    retval = get_reg(m_child, eax);
    // fprintf(stderr, " ret: %d\n", retval);
  }
}

bool TraceMonitor::WaitForSysCall(pid_t child)
{
  int status;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
      return false;
    if (WIFEXITED(status)) {
      fprintf(stderr, "child exit");
      return true;
    }
  }
}

bool TraceMonitor::CheckEndTrace()
{
  fd_set readFDs;
  timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  FD_ZERO(&readFDs);
  FD_SET(m_pipefd[0], &readFDs);
  int maxFD = m_pipefd[0] + 1;
  int ret = select(maxFD, &readFDs, NULL, NULL, &timeout);
  // fprintf(stderr, "select fd=%d ret=%d\n", m_pipefd[0], ret);
  if (ret == 0)
    return false;
  else if (ret == 1) {
    close(m_pipefd[0]);
    close(m_pipefd[1]);
    return true;
  } else {
    // should not happened
    assert(false);
  }
}
