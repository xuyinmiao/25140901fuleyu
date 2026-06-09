CC ?= gcc
CFLAGS ?= -g -O0 -fno-stack-protector

.PHONY: all clean run

all: crackme

crackme: crackme.c
	$(CC) $(CFLAGS) crackme.c -o crackme

run: crackme
	.venv/bin/python agent.py --llm mock --binary ./crackme --log logs/react_run.md

clean:
	rm -f crackme
