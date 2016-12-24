// copy from strace source tree
// defs.h
typedef struct sysent {
	unsigned nargs;
	int	sys_flags;
	int	(*handler)();
	const char *sys_name;
} struct_sysent;

#define TRACE_FILE	001	/* Trace file-related syscalls. */
#define TRACE_IPC	002	/* Trace IPC-related syscalls. */
#define TRACE_NETWORK	004	/* Trace network-related syscalls. */
#define TRACE_PROCESS	010	/* Trace process-related syscalls. */
#define TRACE_SIGNAL	020	/* Trace signal-related syscalls. */
#define TRACE_DESC	040	/* Trace file descriptor-related syscalls. */
#define TRACE_MEMORY	0100	/* Trace memory mapping-related syscalls. */
#define SYSCALL_NEVER_FAILS	0200	/* Syscall is always successful. */

// copy from strace source tree
// syscall.c
/* Define these shorthand notations to simplify the syscallent files. */
#define TD TRACE_DESC
#define TF TRACE_FILE
#define TI TRACE_IPC
#define TN TRACE_NETWORK
#define TP TRACE_PROCESS
#define TS TRACE_SIGNAL
#define TM TRACE_MEMORY
#define NF SYSCALL_NEVER_FAILS
#define MA MAX_ARGS

// copy from strace source tree
// linux/x86_64/syscallent.h
struct_sysent sysent0[] = {
  { 3,	TD,	NULL,		"read"		},  /* 0 */
	{ 3,	TD,	NULL,		"write"		},  /* 1 */
	{ 3,	TD|TF,	NULL,		"open"		},  /* 2 */
	{ 1,	TD,	NULL,		"close"		},  /* 3 */
	{ 2,	TF,	NULL,		"stat"		},  /* 4 */
	{ 2,	TD,	NULL,		"fstat"		},  /* 5 */
	{ 2,	TF,	NULL,		"lstat"		},  /* 6 */
	{ 3,	TD,	NULL,		"poll"		},  /* 7 */
	{ 3,	TD,	NULL,		"lseek"		},  /* 8 */
	{ 6,	TD|TM,	NULL,		"mmap"		},  /* 9 */
	{ 3,	TM,	NULL,		"mprotect"	},  /* 10 */
	{ 2,	TM,	NULL,		"munmap"	},  /* 11 */
	{ 1,	TM,	NULL,		"brk"		},  /* 12 */
	{ 4,	TS,	NULL,	"rt_sigaction"	},  /* 13 */
	{ 4,	TS,	NULL,	"rt_sigprocmask"},  /* 14 */
	{ 0,	TS,	NULL,	"rt_sigreturn"	},  /* 15 */
	{ 3,	TD,	NULL,		"ioctl"		},  /* 16 */
	{ 4,	TD,	NULL,		"pread"		},  /* 17 */
	{ 4,	TD,	NULL,		"pwrite"	},  /* 18 */
	{ 3,	TD,	NULL,		"readv"		},  /* 19 */
	{ 3,	TD,	NULL,		"writev"	},  /* 20 */
	{ 2,	TF,	NULL,		"access"	},  /* 21 */
	{ 1,	TD,	NULL,		"pipe"		},  /* 22 */
	{ 5,	TD,	NULL,		"select"	},  /* 23 */
	{ 0,	0,	NULL,	"sched_yield"	},  /* 24 */
	{ 5,	TM,	NULL,		"mremap"	},  /* 25 */
	{ 3,	TM,	NULL,		"msync"		},  /* 26 */
	{ 3,	TM,	NULL,		"mincore"	},  /* 27 */
	{ 3,	TM,	NULL,		"madvise"	},  /* 28 */
	{ 4,	TI,	NULL,		"shmget"	},  /* 29 */
	{ 4,	TI,	NULL,		"shmat"		},  /* 30 */
	{ 4,	TI,	NULL,		"shmctl"	},  /* 31 */
	{ 1,	TD,	NULL,		"dup"		},  /* 32 */
	{ 2,	TD,	NULL,		"dup2"		},  /* 33 */
	{ 0,	TS,	NULL,		"pause"		},  /* 34 */
	{ 2,	0,	NULL,		"nanosleep"	},  /* 35 */
	{ 2,	0,	NULL,		"getitimer"	},  /* 36 */
	{ 1,	0,	NULL,		"alarm"		},  /* 37 */
	{ 3,	0,	NULL,		"setitimer"	},  /* 38 */
	{ 0,	0,	NULL,		"getpid"	},  /* 39 */
	{ 4,	TD|TN,	NULL,		"sendfile"	},  /* 40 */
	{ 3,	TN,	NULL,		"socket"	},  /* 41 */
	{ 3,	TN,	NULL,		"connect"	},  /* 42 */
	{ 3,	TN,	NULL,		"accept"	},  /* 43 */
	{ 6,	TN,	NULL,		"sendto"	},  /* 44 */
	{ 6,	TN,	NULL,		"recvfrom"	},  /* 45 */
	{ 3,	TN,	NULL,		"sendmsg"	},  /* 46 */
	{ 3,	TN,	NULL,		"recvmsg"	},  /* 47 */
	{ 2,	TN,	NULL,		"shutdown"	},  /* 48 */
	{ 3,	TN,	NULL,		"bind"		},  /* 49 */
	{ 2,	TN,	NULL,		"listen"	},  /* 50 */
	{ 3,	TN,	NULL,	"getsockname"	},  /* 51 */
	{ 3,	TN,	NULL,	"getpeername"	},  /* 52 */
	{ 4,	TN,	NULL,		"socketpair"	},  /* 53 */
	{ 5,	TN,	NULL,		"setsockopt"	},  /* 54 */
	{ 5,	TN,	NULL,		"getsockopt"	},  /* 55 */
	{ 5,	TP,	NULL,		"clone"		},  /* 56 */
	{ 0,	TP,	NULL,		"fork"		},  /* 57 */
	{ 0,	TP,	NULL,		"vfork"		},  /* 58 */
	{ 3,	TF|TP,	NULL,		"execve"	},  /* 59 */
	{ 1,	TP,	NULL,		"_exit"		},  /* 60 */
	{ 4,	TP,	NULL,		"wait4"		},  /* 61 */
	{ 2,	TS,	NULL,		"kill"		},  /* 62 */
	{ 1,	0,	NULL,		"uname"		},  /* 63 */
	{ 4,	TI,	NULL,		"semget"	},  /* 64 */
	{ 4,	TI,	NULL,		"semop"		},  /* 65 */
	{ 4,	TI,	NULL,		"semctl"	},  /* 66 */
	{ 4,	TI,	NULL,		"shmdt"		},  /* 67 */
	{ 4,	TI,	NULL,		"msgget"	},  /* 68 */
	{ 4,	TI,	NULL,		"msgsnd"	},  /* 69 */
	{ 5,	TI,	NULL,		"msgrcv"	},  /* 70 */
	{ 3,	TI,	NULL,		"msgctl"	},  /* 71 */
	{ 3,	TD,	NULL,		"fcntl"		},  /* 72 */
	{ 2,	TD,	NULL,		"flock"		},  /* 73 */
	{ 1,	TD,	NULL,		"fsync"		},  /* 74 */
	{ 1,	TD,	NULL,		"fdatasync"	},  /* 75 */
	{ 2,	TF,	NULL,		"truncate"	},  /* 76 */
	{ 2,	TD,	NULL,		"ftruncate"	},  /* 77 */
	{ 3,	TD,	NULL,		"getdents"	},  /* 78 */
	{ 2,	TF,	NULL,		"getcwd"	},  /* 79 */
	{ 1,	TF,	NULL,		"chdir"		},  /* 80 */
	{ 1,	TD,	NULL,		"fchdir"	},  /* 81 */
	{ 2,	TF,	NULL,		"rename"	},  /* 82 */
	{ 2,	TF,	NULL,		"mkdir"		},  /* 83 */
	{ 1,	TF,	NULL,		"rmdir"		},  /* 84 */
	{ 2,	TD|TF,	NULL,		"creat"		},  /* 85 */
	{ 2,	TF,	NULL,		"link"		},  /* 86 */
	{ 1,	TF,	NULL,		"unlink"	},  /* 87 */
	{ 2,	TF,	NULL,		"symlink"	},  /* 88 */
	{ 3,	TF,	NULL,		"readlink"	},  /* 89 */
	{ 2,	TF,	NULL,		"chmod"		},  /* 90 */
	{ 2,	TD,	NULL,		"fchmod"	},  /* 91 */
	{ 3,	TF,	NULL,		"chown"		},  /* 92 */
	{ 3,	TD,	NULL,		"fchown"	},  /* 93 */
	{ 3,	TF,	NULL,		"lchown"	},  /* 94 */
	{ 1,	0,	NULL,		"umask"		},  /* 95 */
	{ 2,	0,	NULL,	"gettimeofday"	},  /* 96 */
	{ 2,	0,	NULL,		"getrlimit"	},  /* 97 */
	{ 2,	0,	NULL,		"getrusage"	},  /* 98 */
	{ 1,	0,	NULL,		"sysinfo"	},  /* 99 */
	{ 1,	0,	NULL,		"times"		},  /* 100 */
	{ 4,	0,	NULL,		"ptrace"	},  /* 101 */
	{ 0,	NF,	NULL,		"getuid"	},  /* 102 */
	{ 3,	0,	NULL,		"syslog"	},  /* 103 */
	{ 0,	NF,	NULL,		"getgid"	},  /* 104 */
	{ 1,	0,	NULL,		"setuid"	},  /* 105 */
	{ 1,	0,	NULL,		"setgid"	},  /* 106 */
	{ 0,	NF,	NULL,		"geteuid"	},  /* 107 */
	{ 0,	NF,	NULL,		"getegid"	},  /* 108 */
	{ 2,	0,	NULL,		"setpgid"	},  /* 109 */
	{ 0,	0,	NULL,		"getppid"	},  /* 110 */
	{ 0,	0,	NULL,		"getpgrp"	},  /* 111 */
	{ 0,	0,	NULL,		"setsid"	},  /* 112 */
	{ 2,	0,	NULL,		"setreuid"	},  /* 113 */
	{ 2,	0,	NULL,		"setregid"	},  /* 114 */
	{ 2,	0,	NULL,		"getgroups"	},  /* 115 */
	{ 2,	0,	NULL,		"setgroups"	},  /* 116 */
	{ 3,	0,	NULL,		"setresuid"	},  /* 117 */
	{ 3,	0,	NULL,		"getresuid"	},  /* 118 */
	{ 3,	0,	NULL,		"setresgid"	},  /* 119 */
	{ 3,	0,	NULL,		"getresgid"	},  /* 120 */
	{ 1,	0,	NULL,		"getpgid"	},  /* 121 */
	{ 1,	NF,	NULL,		"setfsuid"	},  /* 122 */
	{ 1,	NF,	NULL,		"setfsgid"	},  /* 123 */
	{ 1,	0,	NULL,		"getsid"	},  /* 124 */
	{ 2,	0,	NULL,		"capget"	},  /* 125 */
	{ 2,	0,	NULL,		"capset"	},  /* 126 */
	{ 2,	TS,	NULL,	"rt_sigpending"	},  /* 127 */
	{ 4,	TS,	NULL,	"rt_sigtimedwait"	},  /* 128 */
	{ 3,	TS,	NULL,    "rt_sigqueueinfo"	},  /* 129 */
	{ 2,	TS,	NULL,	"rt_sigsuspend"	},  /* 130 */
	{ 2,	TS,	NULL,	"sigaltstack"	},  /* 131 */
	{ 2,	TF,	NULL,		"utime"		},  /* 132 */
	{ 3,	TF,	NULL,		"mknod"		},  /* 133 */
	{ 1,	TF,	NULL,		"uselib"	},  /* 134 */
	{ 1,	0,	NULL,	"personality"	},  /* 135 */
	{ 2,	0,	NULL,		"ustat"		},  /* 136 */
	{ 2,	TF,	NULL,		"statfs"	},  /* 137 */
	{ 2,	TD,	NULL,		"fstatfs"	},  /* 138 */
	{ 3,	0,	NULL,		"sysfs"		},  /* 139 */
	{ 2,	0,	NULL,	"getpriority"	},  /* 140 */
	{ 3,	0,	NULL,	"setpriority"	},  /* 141 */
	{ 0,	0,	NULL,	"sched_setparam"	},  /* 142 */
	{ 2,	0,	NULL,	"sched_getparam"	},  /* 143 */
	{ 3,	0,	NULL,	"sched_setscheduler"	},  /* 144 */
	{ 1,	0,	NULL,	"sched_getscheduler"	},  /* 145 */
	{ 1,	0,	NULL,	"sched_get_priority_max"	},  /* 146 */
	{ 1,	0,	NULL,	"sched_get_priority_min"	},  /* 147 */
	{ 2,	0,	NULL,	"sched_rr_get_interval"	},  /* 148 */
	{ 2,	TM,	NULL,		"mlock"		},  /* 149 */
	{ 2,	TM,	NULL,		"munlock"	},  /* 150 */
	{ 1,	TM,	NULL,		"mlockall"	},  /* 151 */
	{ 0,	TM,	NULL,		"munlockall"	},  /* 152 */
	{ 0,	0,	NULL,		"vhangup"	},  /* 153 */
	{ 3,	0,	NULL,		"modify_ldt"	},  /* 154 */
	{ 2,	TF,	NULL,		"pivot_root"	},  /* 155 */
	{ 1,	0,	NULL,		"_sysctl"	},  /* 156 */
	{ 5,	0,	NULL,		"prctl"		},  /* 157 */
	{ 2,	TP,	NULL,		"arch_prctl"	},  /* 158 */
	{ 1,	0,	NULL,		"adjtimex"	},  /* 159 */
	{ 2,	0,	NULL,		"setrlimit"	},  /* 160 */
	{ 1,	TF,	NULL,		"chroot"	},  /* 161 */
	{ 0,	0,	NULL,		"sync"		},  /* 162 */
	{ 1,	TF,	NULL,		"acct"		},  /* 163 */
	{ 2,	0,	NULL,	"settimeofday"	},  /* 164 */
	{ 5,	TF,	NULL,		"mount"		},  /* 165 */
	{ 2,	TF,	NULL,		"umount"	}, /* 166 */
	{ 2,	TF,	NULL,		"swapon"	},  /* 167 */
	{ 1,	TF,	NULL,		"swapoff"	},  /* 168 */
	{ 4,	0,	NULL,		"reboot"	},  /* 169 */
	{ 2,	0,	NULL,	"sethostname"	},  /* 170 */
	{ 2,	0,	NULL,	"setdomainname"	},  /* 171 */
	{ 1,	0,	NULL,		"iopl"		},  /* 172 */
	{ 3,	0,	NULL,		"ioperm"	},  /* 173 */
	{ 2,	0,	NULL,	"create_module"	},  /* 174 */
	{ 3,	0,	NULL,	"init_module"	},  /* 175 */
	{ 2,	0,	NULL,	"delete_module"	},  /* 176 */
	{ 1,	0,	NULL,	"get_kernel_syms"},  /* 177 */
	{ 5,	0,	NULL,	"query_module"	},  /* 178 */
	{ 4,	TF,	NULL,		"quotactl"	},  /* 179 */
	{ 3,	0,	NULL,		"nfsservctl"	},  /* 180 */
	{ 5,	0,	NULL,		"getpmsg"	}, /* 181 */
	{ 5,	0,	NULL,		"putpmsg"	}, /* 182 */
	{ 5,	0,	NULL,	"afs_syscall"	},  /* 183 */
	{ 3,	0,	NULL,		"tuxcall"	}, /* 184 */
	{ 3,	0,	NULL,		"security"	}, /* 185 */
	{ 0,	0,	NULL,		"gettid"	}, /* 186 */
	{ 3,	TD,	NULL,		"readahead"	}, /* 187 */
	{ 5,	TF,	NULL,		"setxattr"	}, /* 188 */
	{ 5,	TF,	NULL,		"lsetxattr"	}, /* 189 */
	{ 5,	TD,	NULL,		"fsetxattr"	}, /* 190 */
	{ 4,	TF,	NULL,		"getxattr"	}, /* 191 */
	{ 4,	TF,	NULL,		"lgetxattr"	}, /* 192 */
	{ 4,	TD,	NULL,		"fgetxattr"	}, /* 193 */
	{ 3,	TF,	NULL,		"listxattr"	}, /* 194 */
	{ 3,	TF,	NULL,		"llistxattr"	}, /* 195 */
	{ 3,	TD,	NULL,		"flistxattr"	}, /* 196 */
	{ 2,	TF,	NULL,	"removexattr"	}, /* 197 */
	{ 2,	TF,	NULL,	"lremovexattr"	}, /* 198 */
	{ 2,	TD,	NULL,	"fremovexattr"	}, /* 199 */
	{ 2,	TS,	NULL,		"tkill"		}, /* 200 */
	{ 1,	0,	NULL,		"time"		},  /* 201 */
	{ 6,	0,	NULL,		"futex"		}, /* 202 */
	{ 3,	0,	NULL,	"sched_setaffinity" },/* 203 */
	{ 3,	0,	NULL,	"sched_getaffinity" },/* 204 */
	{ 1,	0,	NULL,	"set_thread_area" }, /* 205 */
	{ 2,	0,	NULL,		"io_setup"	}, /* 206 */
	{ 1,	0,	NULL,		"io_destroy"	}, /* 207 */
	{ 5,	0,	NULL,	"io_getevents"	}, /* 208 */
	{ 3,	0,	NULL,		"io_submit"	}, /* 209 */
	{ 3,	0,	NULL,		"io_cancel"	}, /* 210 */
	{ 1,	0,	NULL,	"get_thread_area" }, /* 211 */
	{ 3,	0,	NULL,	"lookup_dcookie"}, /* 212 */
	{ 1,	TD,	NULL,	"epoll_create"	}, /* 213 */
	{ 4,	0,	NULL,		"epoll_ctl_old"	}, /* 214 */
	{ 4,	0,	NULL,		"epoll_wait_old"}, /* 215 */
	{ 5,	TM,	NULL,	"remap_file_pages"}, /* 216 */
	{ 3,	TD,	NULL,		"getdents64"	}, /* 217 */
	{ 1,	0,	NULL,	"set_tid_address"}, /* 218 */
	{ 0,	0,	NULL,	"restart_syscall"}, /* 219 */
	{ 5,	TI,	NULL,		"semtimedop"	}, /* 220 */
	{ 4,	TD,	NULL,		"fadvise64"	}, /* 221 */
	{ 3,	0,	NULL,	"timer_create"	}, /* 222 */
	{ 4,	0,	NULL,	"timer_settime"	}, /* 223 */
	{ 2,	0,	NULL,	"timer_gettime"	}, /* 224 */
	{ 1,	0,	NULL,	"timer_getoverrun"}, /* 225 */
	{ 1,	0,	NULL,	"timer_delete"	}, /* 226 */
	{ 2,	0,	NULL,	"clock_settime"	}, /* 227 */
	{ 2,	0,	NULL,	"clock_gettime"	}, /* 228 */
	{ 2,	0,	NULL,	"clock_getres"	}, /* 229 */
	{ 4,	0,	NULL,	"clock_nanosleep"}, /* 230 */
	{ 1,	TP,	NULL,		"exit_group"	}, /* 231 */
	{ 4,	TD,	NULL,		"epoll_wait"	}, /* 232 */
	{ 4,	TD,	NULL,		"epoll_ctl"	}, /* 233 */
	{ 3,	TS,	NULL,		"tgkill"	}, /* 234 */
	{ 2,	TF,	NULL,		"utimes"	}, /* 235 */
	{ 5,	0,	NULL,		"vserver"	}, /* 236 */
	{ 6,	TM,	NULL,		"mbind"		}, /* 237 */
	{ 3,	TM,	NULL,	"set_mempolicy"	}, /* 238 */
	{ 5,	TM,	NULL,	"get_mempolicy"	}, /* 239 */
	{ 4,	0,	NULL,		"mq_open"	}, /* 240 */
	{ 1,	0,	NULL,		"mq_unlink"	}, /* 241 */
	{ 5,	0,	NULL,	"mq_timedsend"	}, /* 242 */
	{ 5,	0,	NULL,	"mq_timedreceive" }, /* 243 */
	{ 2,	0,	NULL,		"mq_notify"	}, /* 244 */
	{ 3,	0,	NULL,	"mq_getsetattr"	}, /* 245 */
	{ 4,	0,	NULL,		"kexec_load"	}, /* 246 */
	{ 5,	TP,	NULL,		"waitid"	}, /* 247 */
	{ 5,	0,	NULL,		"add_key"	}, /* 248 */
	{ 4,	0,	NULL,	"request_key"	}, /* 249 */
	{ 5,	0,	NULL,		"keyctl"	}, /* 250 */
	{ 3,	0,	NULL,		"ioprio_set"	}, /* 251 */
	{ 2,	0,	NULL,		"ioprio_get"	}, /* 252 */
	{ 0,	TD,	NULL,	"inotify_init"	}, /* 253 */
	{ 3,	TD,	NULL,	"inotify_add_watch" }, /* 254 */
	{ 2,	TD,	NULL,	"inotify_rm_watch" }, /* 255 */
	{ 4,	TM,	NULL,	"migrate_pages"	}, /* 256 */
	{ 4,	TD|TF,	NULL,		"openat"	}, /* 257 */
	{ 3,	TD|TF,	NULL,		"mkdirat"	}, /* 258 */
	{ 4,	TD|TF,	NULL,		"mknodat"	}, /* 259 */
	{ 5,	TD|TF,	NULL,		"fchownat"	}, /* 260 */
	{ 3,	TD|TF,	NULL,		"futimesat"	}, /* 261 */
	{ 4,	TD|TF,	NULL,		"newfstatat"	}, /* 262 */
	{ 3,	TD|TF,	NULL,		"unlinkat"	}, /* 263 */
	{ 4,	TD|TF,	NULL,		"renameat"	}, /* 264 */
	{ 5,	TD|TF,	NULL,		"linkat"	}, /* 265 */
	{ 3,	TD|TF,	NULL,		"symlinkat"	}, /* 266 */
	{ 4,	TD|TF,	NULL,		"readlinkat"	}, /* 267 */
	{ 3,	TD|TF,	NULL,		"fchmodat"	}, /* 268 */
	{ 3,	TD|TF,	NULL,		"faccessat"	}, /* 269 */
	{ 6,	TD,	NULL,		"pselect6"	}, /* 270 */
	{ 5,	TD,	NULL,		"ppoll"		}, /* 271 */
	{ 1,	TP,	NULL,		"unshare"	}, /* 272 */
	{ 2,	0,	NULL,	"set_robust_list" }, /* 273 */
	{ 3,	0,	NULL,	"get_robust_list" }, /* 274 */
	{ 6,	TD,	NULL,		"splice"	}, /* 275 */
	{ 4,	TD,	NULL,		"tee"		}, /* 276 */
	{ 4,	TD,	NULL,	"sync_file_range" }, /* 277 */
	{ 4,	TD,	NULL,		"vmsplice"	}, /* 278 */
	{ 6,	TM,	NULL,		"move_pages"	}, /* 279 */
	{ 4,	TD|TF,	NULL,		"utimensat"	}, /* 280 */
	{ 6,	TD,	NULL,	"epoll_pwait"	}, /* 281 */
	{ 3,	TD|TS,	NULL,		"signalfd"	}, /* 282 */
	{ 2,	TD,	NULL,	"timerfd_create"}, /* 283 */
	{ 1,	TD,	NULL,		"eventfd"	}, /* 284 */
	{ 4,	TD,	NULL,		"fallocate"	}, /* 285 */
	{ 4,	TD,	NULL,	"timerfd_settime"}, /* 286 */
	{ 2,	TD,	NULL,	"timerfd_gettime"}, /* 287 */
	{ 4,	TN,	NULL,		"accept4"	}, /* 288 */
	{ 4,	TD|TS,	NULL,		"signalfd4"	}, /* 289 */
	{ 2,	TD,	NULL,		"eventfd2"	}, /* 290 */
	{ 1,	TD,	NULL,	"epoll_create1"	}, /* 291 */
	{ 3,	TD,	NULL,		"dup3"		}, /* 292 */
	{ 2,	TD,	NULL,		"pipe2"		}, /* 293 */
	{ 1,	TD,	NULL,	"inotify_init1"	}, /* 294 */
	{ 4,	TD,	NULL,		"preadv"	}, /* 295 */
	{ 4,	TD,	NULL,		"pwritev"	}, /* 296 */
	{ 4,	TP|TS,	NULL,	"rt_tgsigqueueinfo"}, /* 297 */
	{ 5,	TD,	NULL,	"perf_event_open"}, /* 298 */
	{ 5,	TN,	NULL,		"recvmmsg"	}, /* 299 */
	{ 2,	TD,	NULL,	"fanotify_init"	}, /* 300 */
	{ 5,	TD|TF,	NULL,	"fanotify_mark"	}, /* 301 */
	{ 4,	0,	NULL,		"prlimit64"	}, /* 302 */
	{ 5,	TD|TF,	NULL,	"name_to_handle_at"}, /* 303 */
	{ 3,	TD,	NULL,	"open_by_handle_at"}, /* 304 */
	{ 2,	0,	NULL,	"clock_adjtime"	}, /* 305 */
	{ 1,	TD,	NULL,		"syncfs"	}, /* 306 */
	{ 4,	TN,	NULL,		"sendmmsg"	}, /* 307 */
	{ 2,	TD,	NULL,		"setns"		}, /* 308 */
	{ 3,	0,	NULL,		"getcpu"	}, /* 309 */
	{ 6,	0,	NULL,	"process_vm_readv"	}, /* 310 */
	{ 6,	0,	NULL,	"process_vm_writev"	}, /* 311 */
	{ 5,	0,	NULL,		"kcmp"		}, /* 312 */
	{ 3,	TD,	NULL,	"finit_module"	}, /* 313 */
};
