all: venv/.ok

	clang -Wall -Wextra -O2 -emit-llvm -c \
		sockmap-proxy-kern.c \
		-S -o - \
		| llc -march=bpf -filetype=obj -o - \
		| ./venv/bin/python3 tbpf-decode-elf.py /dev/stdin \
			prog_parser prog_verdict \
		> sockmap-proxy-ebpf.c

	clang -g -Wall -Wextra -O2 \
		tbpf.c \
		net.c \
		sockmap-proxy-ebpf.c \
		sockmap-proxy.c \
		-l elf \
		-o sockmap-proxy

#		-l elf \#
venv/.ok:
	virtualenv venv --python=python3
	./venv/bin/pip3 install pyelftools
	touch $@

.PHONY: format
format:
	clang-format -i *.c *.h
	@grep -n "TODO" *.[ch] || true
