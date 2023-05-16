// Demo of ptrace's ability to trace multiple processes. Mimics strace.
//
// Copyright © 2023 Josef Schönberger
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

int errno = 0;

typedef unsigned long size_t;
typedef long ssize_t;

// Inspired by musl: https://git.musl-libc.org/cgit/musl/tree/arch/x86_64/syscall_arch.h
__attribute__((used)) static inline long syscall0(int sysno) {
	long r = sysno;
	asm("syscall" : "+a"(r) :: "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall1(int sysno, long arg1) {
	long r = sysno;
	asm("syscall" : "+a"(r) :"D"(arg1): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall2(int sysno, long arg1, long arg2) {
	long r = sysno;
	asm("syscall" : "+a"(r) :"D"(arg1), "S"(arg2): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall3(int sysno, long arg1, long arg2, long arg3) {
	long r = sysno;
	asm("syscall" : "+a"(r) :"D"(arg1), "S"(arg2), "d"(arg3): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall4(int sysno, long arg1, long arg2, long arg3, long arg4) {
	long r = sysno;
	register long a4 asm("r10") = arg4;
	asm("syscall" : "+a"(r) :"D"(arg1), "S"(arg2), "d"(arg3), "r"(a4): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall5(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5) {
	long r = sysno;
	register long a4 asm("r10") = arg4;
	register long a5 asm("r8") = arg5;
	asm("syscall" : "+a"(r) :"D"(arg1), "S"(arg2), "d"(arg3), "r"(a4), "r"(a5): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((used)) static inline long syscall6(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
	long r = sysno;
	register long a4 asm("r10") = arg4;
	register long a5 asm("r8") = arg5;
	register long a6 asm("r9") = arg6;
	asm("syscall" : "+a"(r) :"D"(arg1), "S"(arg2), "d"(arg3), "r"(a4), "r"(a5), "r"(a6): "rcx", "r11", "memory");
	if (r < 0 && r >= ~0xFFFFll) {
		errno = -r;
		return -1;
	}
	return r;
}

__attribute__((noreturn)) void exit(int code) {
	syscall1(60, code);
	__builtin_unreachable();
}

int open(const char* path, int flags, int mode) {
	return syscall3(2, (long) path, flags, mode);
}
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_APPEND 02000
#define O_CREAT 0100

ssize_t read(int fd, char* buf, size_t buf_len) {
	return syscall3(0, fd, (long) buf, (long) buf_len);
}

ssize_t write(int fd, const char* buffer, size_t buffer_len) {
	return syscall3(1, fd, (long) buffer, (long) buffer_len);
}

int close(int fd) {
	return syscall1(3, fd);
}

int fork() {
	return syscall0(57);
}

int waitpid(int pid, int* wstatus, int options) {
	return syscall4(61, pid, (long) wstatus, options, 0);
}

int getpid() {
	return syscall0(39);
}

int kill(int pid, int signo) {
	return syscall2(62, pid, signo);
}

struct clone_args {
	unsigned long flags;
	unsigned long pidfd;
	unsigned long child_tid;
	unsigned long parent_tid;
	unsigned long exit_signal;
	unsigned long stack;
	unsigned long stack_size;
	unsigned long tls;
	unsigned long set_tid;
	unsigned long set_tid_size;
	unsigned long cgroup;
};
long clone3(struct clone_args *args, size_t size) {
	return syscall2(435, (long)args, size);
}

int main(int argc, char** argv) {
	(void) argc, (void) argv;
	int fd = open("./a", O_WRONLY | O_CREAT, 0640);
	write(fd, "Hello\n", 6);
	close(fd);
	int p = fork();
	if (p == 0) {
		int p = fork();
		if (p != 0) {
			waitpid(p, 0, 0);
			return 0;
		}
		write(1, "Grandchild\n", 11);
		kill(getpid(), 9);
	} else
		waitpid(p, 0, 0);

}

__attribute__((naked)) void _start() {
	asm ("mov rdi, [rsp + 8]; mov rsi, [rsp + 8]; call main; mov rdi, rax; mov rax, 60; syscall");
}
