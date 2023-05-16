all: tracer tracee

tracee: tracee.c
	gcc tracee.c -o tracee -Wall -Wextra -static -nolibc -nostdlib -nostdinc -masm=intel -g -Og

tracer: tracer.c
	gcc tracer.c -o tracer -Wall -Wextra

.PHONY: clean
clean:
	rm -f tracer tracee a
