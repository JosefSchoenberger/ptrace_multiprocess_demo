#define _GNU_SOURCE
#include <stdlib.h>
#include <err.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>


// -----------------------------------------------------------------------------
pid_t current_line_pid = -1;
struct __attribute__((packed)) syscall {
	const char* name;
	unsigned short int args_count;
	const char* args_format;
} syscalls[] = {
	// see https://de.wikipedia.org/wiki/Liste_der_Linux-Systemaufrufe
	[0]   = {"read", 3, "%lld, %p, %llu"},
	        {"write", 3, "%lld, %p, %llu"},
	        {"open", 2, "%p, %#llx"},
	        {"close", 1, "%lld"},
	        {"stat", 2, "%p, %#llx"},
	        {"fstat", 2, "%lld, %#llx"},
	        {"lstat", 2, "%p, %#llx"},
			{"poll", 3, "%p, %u, %d"},
	        {"lseek", 3, "%d, %zd, %d"},
	        {"mmap", 6, "%p, %llu, %#llx, %#llx, %lld, %#llx"},
	        {"mprotect", 3, "%p, %llu, %#llx"},
	        {"munmap", 2, "%p, %lld"},
	        {"brk", 1, "%p"},
			{"sigaction", 3, "%d, %p, %p"},
	        {"rt_sigprocmask", 3, "%d, %p, %p"},
			{"rt_sigreturn", 0, "..."},
	        {"ioctl", 6, "%d, %lu, %ld, %ld, %ld, %ld"},
			{"pread64", 4, "%d, %p, %zu, %zd"},
			{"pwrite64", 4, "%d, %p, %zu, %zd"},
	[21]  = {"access", 2, "%p, %#llx"},
			{"pipe", 1, "%p"},
			{"select", 5, "%d, %p, %p, %p, %p"},
			{"sched_yield", 0, ""},
	[28]  = {"madvise", 3, "%p, %zu, %d"},
	[39]  = {"getpid", 0, ""},
	[56]  = {"clone", 6, "%p, %p, %#x, %p, %p, %p"},
	        {"fork", 0, ""},
	        {"vfork", 0, ""},
	        {"execve", 3, "%p, %p, %p"},
	        {"exit", 1, "%d"},
	        {"wait4", 4, "%d, %p, %d, %p"},
			{"kill", 2, "%d, %d"},
	[72]  = {"fcntl", 3, "%d, %d, %#x"},
	[87]  = {"unlink", 1, "%p"},
	[89]  = {"readlink", 3, "%p, %p, %zu"},
	[107] = {"geteuid", 0, ""},
	        {"getegid", 0, ""},
	[157] = {"prctl", 5, "%d, %lu, %lu, %lu, %lu"},
	        {"arch_prctl", 2, "%d %#lx"},
	[165] = {"mount", 5, "%p, %p, %p, %lx, %p"},
	[186] = {"gettid", 0, ""},
	[202] = {"futex", 6, "%p, %d, %d %p %p %d"},
	        {"sched_setaffinity", 3, "%d, %#zx, %p"},
	        {"sched_getaffinity", 3, "%d, %#zx, %p"},
	[217] = {"getdents64", 3, "%d, %p, %u"},
	        {"set_tid_address", 1, "%p"},
	[231] = {"exit_group", 1, "%lld"},
	[257] = {"openat", 3, "%lld, %p, %#llx, %#llx"},
	[262] = {"newfstatat", 4, "%d, %p, %p, %d"},
	[272] = {"unshare", 1, "%#x"},
	        {"set_robust_list",  2, "%p, %zu"},
	        {"get_robust_list",  3, "%d, %p, %zu"},
	[292] = {"dup3", 3, "%d, %d, %x"},
	        {"pipe2", 2, "%p, %x"},
	[302] = {"prlimit64", 4, "%d, %d, %p, %p"},
	[334] = {"rseq", 4, "%p, %u, %d, %u"},
	[435] = {"clone3", 2, "%p, %zu"},
};

void log_syscall_entry(pid_t pid, struct ptrace_syscall_info* info) {
	if (info->entry.nr >= sizeof(syscalls) / sizeof(struct syscall))
		goto backup;
	struct syscall* s = &syscalls[info->entry.nr];
	if (!s->name) {
		goto backup;
	}
	if (current_line_pid != -1) {
		fprintf(stderr, " = ...\n");
	}
	fprintf(stderr, "[%9d] %s(", pid, s->name);
#define a(nr) (info->entry.args[nr])
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	fprintf(stderr, s->args_format, a(0), a(1), a(2), a(3), a(4), a(5));
#pragma GCC diagnostic pop
	fprintf(stderr, ")");
	current_line_pid = pid;
	if (info->entry.nr == /* exit_group */ 231 || info->entry.nr == /* exit */ 60) {
		fprintf(stderr, "\n");
		current_line_pid = -1;
	}
	return;

backup:
	fprintf(stderr, "[%9d] syscall %3lld (%#llx, %#llx, %#llx, %#llx, %#llx, %#llx)", pid, info->entry.nr, a(0), a(1), a(2), a(3),
			a(4), a(5));
#undef a
	current_line_pid = pid;
}

const char* code_to_string(int code, int signo) {
	switch (code) {
		case SI_USER:
			return "killed by process";
		case SI_KERNEL:
			return "killed by kernel";
		case SI_QUEUE:
			return "sent with sigqueue";
		case SI_TIMER:
			return "timer ran out";
		case SI_MESGQ:
			return "POSIX message queue state changed";
		case SI_ASYNCIO:
			return "Async ID completed";
		case SI_TKILL:
			return "sent with tkill/tgkill";
	}
	if (signo == SIGILL)
		switch (code) {
			case ILL_ILLOPC:
				return "illegal opcode";
			case ILL_ILLOPN:
				return "illegal operand";
			case ILL_ILLADR:
				return "illegal addressing mode";
			case ILL_ILLTRP:
				return "illegal trap";
			case ILL_PRVOPC:
				return "privileged opcode";
			case ILL_PRVREG:
				return "privileged register";
			case ILL_COPROC:
				return "co-processor error";
			case ILL_BADSTK:
				return "internal stack error";
		}
	if (signo == SIGFPE)
		switch (code) {
			case FPE_INTDIV:
				return "integer divide by zero";
			case FPE_INTOVF:
				return "integer overflow";
			case FPE_FLTDIV:
				return "floating point divide by zero";
			case FPE_FLTOVF:
				return "floating point overflow";
			case FPE_FLTUND:
				return "floating point underflow";
			case FPE_FLTRES:
				return "floating point inexact result";
			case FPE_FLTINV:
				return "invalid floating point operation";
			case FPE_FLTSUB:
				return "subscript out of range";
		}
	if (signo == SIGSEGV)
		switch (code) {
			case SEGV_MAPERR:
				return "address not mapped to object";
			case SEGV_ACCERR:
				return "invalid permissions for mapped object";
			case SEGV_BNDERR:
				return "failed address bound checks";
			case SEGV_PKUERR:
				return "access denied (protection keys)";
		}
	if (signo == SIGBUS)
		switch (code) {
			case BUS_ADRALN:
				return "invalid address alignment";
			case BUS_ADRERR:
				return "non-existent physical address";
			case BUS_OBJERR:
				return "object specific hardware error";
			case BUS_MCEERR_AR:
				return "hardware mem err on machine check (action required)";
			case BUS_MCEERR_AO:
				return "hardware mem err on machine check (action optional)";
		}
	if (signo == SIGTRAP && (code & 0xFF) == SIGTRAP) {
		switch(code >> 8) {
			case PTRACE_EVENT_VFORK:
				return "ptrace event: vfork";
			case PTRACE_EVENT_FORK:
				return "ptrace event: fork";
			case PTRACE_EVENT_CLONE:
				return "ptrace event: clone";
			case PTRACE_EVENT_VFORK_DONE:
				return "ptrace event: vfork done";
			case PTRACE_EVENT_EXEC:
				return "ptrace event: exec";
			case PTRACE_EVENT_EXIT:
				return "ptrace event: exit";
			case PTRACE_EVENT_STOP:
				return "ptrace event: stop";
			case PTRACE_EVENT_SECCOMP:
				return "ptrace event: seccomp";
		}
	}
	else if (signo == SIGTRAP)
		switch (code) {
			case TRAP_BRKPT:
				return "process breakpoint";
			case TRAP_TRACE:
				return "process trace trap";
			case TRAP_BRANCH:
				return "process taken branch trap";
			case TRAP_HWBKPT:
				return "Hardware breakpoint/watchpoint";
		}
	if (signo == SIGCHLD)
		switch (code) {
			case CLD_EXITED:
				return "child has exited";
			case CLD_KILLED:
				return "child was killed";
			case CLD_DUMPED:
				return "child terminated abnormally";
			case CLD_TRAPPED:
				return "traced child has trapped";
			case CLD_STOPPED:
				return "child has stopped";
			case CLD_CONTINUED:
				return "stopped child had continued";
		}
	if (signo == SIGPOLL)
		switch (code) {
			case POLL_IN:
				return "data input available";
			case POLL_OUT:
				return "output buffers available";
			case POLL_MSG:
				return "input message available";
			case POLL_ERR:
				return "I/O error";
			case POLL_PRI:
				return "high priority input available";
			case POLL_HUP:
				return "device disconnected";
		}
	//if (signo == SIGSYS && code == SYS_SECCOMP)
	//	return "seccomp denied syscall";
	static char buffer[32];
	snprintf(buffer, sizeof(buffer), "code=%d", code);
	return buffer;
}
void log_signal(pid_t pid, siginfo_t *info) {
	if (current_line_pid != -1)
		fprintf(stderr, " = ...\n");
	fprintf(stderr, "----- SIG%s pid %d { %s", sigabbrev_np(info->si_signo), pid, code_to_string(info->si_code, info->si_signo));
	if (info->si_code == SI_USER || info->si_code == SI_QUEUE || info->si_code == SI_MESGQ) {
		fprintf(stderr, ", pid=%d", info->si_pid);
		fprintf(stderr, ", uid=%d", info->si_uid);
	} else if (info->si_signo == SIGCHLD) {
		fprintf(stderr, ", pid=%d", info->si_pid);
		fprintf(stderr, ", uid=%d", info->si_uid);
		if (info->si_code == CLD_STOPPED)
			fprintf(stderr, ", status=SIG%s", sigabbrev_np(info->si_status));
		else
			fprintf(stderr, ", status=%d", info->si_status);
	}
	if (info->si_signo == SIGILL || info->si_signo == SIGFPE || info->si_signo == SIGSEGV || info->si_signo == SIGBUS || info->si_signo == SIGTRAP)
		fprintf(stderr, ", addr=%#zx", (size_t)info->si_addr);
	fprintf(stderr, " } -----\n");
	current_line_pid = -1;
}
// ------------------------------------------------------------------------------

int main(int argc, char** argv) {
	if (argc < 2)
		errx(EXIT_FAILURE, "usage: %s <cmd>...", argv[0] ?: "<argv[0] missing>");

	long r;

	int fds[2];
	r = pipe2(fds, O_CLOEXEC);
	if (r != 0)
		err(EXIT_FAILURE, "Could not pipe");
	
	
	pid_t initial_child_pid = fork();
	if (initial_child_pid < 0)
		err(EXIT_FAILURE, "Could not fork");
	if (initial_child_pid == 0) {
		r = ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (r != 0)
			err(EXIT_FAILURE, "Could not PTRACE_TRACEME");
		
		char buf;
		write(fds[1], &buf, 1);
		execvp(argv[1], argv + 1);
		err(EXIT_FAILURE, "Could not exec");
	}

	char buf;
	read(fds[0], &buf, 1);
	close(fds[0]);
	close(fds[1]);

	int wstatus;
	pid_t pid = waitpid(initial_child_pid, &wstatus, 0);
	if (pid < 0)
		err(EXIT_FAILURE, "waitpid(%d, ...) failed", initial_child_pid);
	
	if (!(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP))
		errx(EXIT_FAILURE, "Child did not stop with SIGTRAP");

	r = ptrace(PTRACE_SETOPTIONS, initial_child_pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL);
	if (r != 0)
		err(EXIT_FAILURE, "Could not PTRACE_SETOPTIONS to child (pid %d)", initial_child_pid);

	r = ptrace(PTRACE_SYSCALL, initial_child_pid, 0, 0);
	if (r != 0)
		err(EXIT_FAILURE, "Could not PTRACE_SYSCALL (child pid %d)", initial_child_pid);

	unsigned process_count = 1;
	while(process_count) {
		int wstatus;
		pid_t pid = waitpid(-1, &wstatus, 0);
		if (pid < 0)
			err(EXIT_FAILURE, "Could not waitpid");
		if (WIFEXITED(wstatus)) {
			if (WEXITSTATUS(wstatus) && pid == initial_child_pid)
				fprintf(stderr, "Child exited with exit status %d", WEXITSTATUS(wstatus));
			process_count --;
			continue;
		}
		if (WIFSIGNALED(wstatus)) {
			if (current_line_pid != -1)
				fprintf(stderr, " = ...\n");
			fprintf(stderr, "Process %d was killed by SIG%s (%s)%s\n", pid, sigabbrev_np(WTERMSIG(wstatus)), sigdescr_np(WTERMSIG(wstatus)),
					WCOREDUMP(wstatus) ? " Core dumped." : "");
			current_line_pid = -1;
			continue;
		}
		if (!WIFSTOPPED(wstatus))
			errx(EXIT_FAILURE, "Child was not terminated, signaled or stopped, yet waitpid returned?!?");

		int signo_to_continue = 0;
		int stopsig = WSTOPSIG(wstatus);
		if (stopsig & 0x80) {
			struct ptrace_syscall_info info;
			r = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info);
			if (r < 0)
				err(EXIT_FAILURE, "Could not get syscall info");
			if(info.op == PTRACE_SYSCALL_INFO_ENTRY)
				log_syscall_entry(pid, &info);
			else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
				if (current_line_pid == -1)
					fprintf(stderr, "[%9d] ...", pid);
				else if (current_line_pid != pid)
					fprintf(stderr, " = ...\n[%9d] ...", pid);
				fprintf(stderr, " = %lld\n", info.exit.rval);
				current_line_pid = -1;
			}
		} else {
			siginfo_t siginfo;
			r = ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
			if (r < 0)
				err(EXIT_FAILURE, "Could not PTRACE_GETSIGINFO");
			if (siginfo.si_signo == SIGTRAP && ((siginfo.si_code & 0xFF) == SIGTRAP || siginfo.si_pid == pid)) {
				if (siginfo.si_code >> 8 == PTRACE_EVENT_STOP || siginfo.si_code >> 8 == PTRACE_EVENT_EXEC)
					goto continue_syscall;

				unsigned long msg;
				r = ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
				if (r < 0)
					err(EXIT_FAILURE, "Could not PTRACE_GETEVENTMSG");

				current_line_pid = -1;
				switch (siginfo.si_code >> 8) {
					case PTRACE_EVENT_EXIT:
						fprintf(stderr, "process %d exited with exit code %lu\n", pid, msg);
						break;
					case PTRACE_EVENT_VFORK:
					case PTRACE_EVENT_FORK:
					case PTRACE_EVENT_CLONE:
						fprintf(stderr, "  (process %d forked off into PID %lu)", pid, msg);
						current_line_pid = pid;
						
						r = ptrace(PTRACE_SYSCALL, msg, 0, 0);
						if (r != 0)
							err(EXIT_FAILURE, "Could not PTRACE_SYSCALL new child (pid %lu)", msg);
						process_count++;
				}
				goto continue_syscall;
			} else if (siginfo.si_signo == SIGSTOP && siginfo.si_code == SI_USER && siginfo.si_pid == 0) {
				continue;
			}
			log_signal(pid, &siginfo);
			signo_to_continue = siginfo.si_signo;
		}
continue_syscall:
		r = ptrace(PTRACE_SYSCALL, pid, 0, signo_to_continue);
		if (r != 0)
			err(EXIT_FAILURE, "Could not PTRACE_SYSCALL (child pid %d)", pid);
	}
}
