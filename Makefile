# Whistler: Common Lisp eBPF compiler
# git clone https://github.com/atgreen/whistler.git $(HOME)/git/whistler
WHISTLER := $(HOME)/git/whistler
SBCL     := sbcl

BIN      := block-copyfail
SBCL_SAVE_OPTS := :compression t

.PHONY: help run build elf ubi8-build doctor

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  build    Build standalone binary (./$(BIN))"
	@echo "  run      Load and run directly via SBCL (requires sudo)"
	@echo "  elf      Compile to block-copyfail.bpf.o (loadable by bpftool/libbpf)"
	@echo "  ubi8-build  Build binary in UBI8 ubi8-build (older glibc)"
	@echo "  doctor   Check prerequisites (BTF, BPF LSM, SBCL, Whistler)"

run:
	sudo $(SBCL) --noinform --non-interactive \
	  --eval '(pushnew "$(WHISTLER)/" asdf:*central-registry*)' \
	  --load block-copyfail.lisp

build:
	$(SBCL) --noinform --non-interactive \
	  --eval '(require "asdf")' \
	  --eval '(pushnew "$(WHISTLER)/" asdf:*central-registry*)' \
	  --eval '(push "--build" sb-ext:*posix-argv*)' \
	  --load block-copyfail.lisp \
	  --eval '(sb-ext:save-lisp-and-die "$(BIN)" :toplevel #'"'"'whistler-loader-user::run :executable t $(SBCL_SAVE_OPTS))'

elf:
	$(SBCL) --noinform --non-interactive \
	  --eval '(pushnew "$(WHISTLER)/" asdf:*central-registry*)' \
	  --eval '(asdf:load-system "whistler")' \
	  --eval '(whistler:compile-file* "block-copyfail-elf.lisp" "block-copyfail.bpf.o")'
	@echo "Wrote block-copyfail.bpf.o"

ubi8-build:
	podman build -t block-copyfail-builder -f Containerfile .
	podman create --name bcf-tmp block-copyfail-builder
	podman cp bcf-tmp:/build/block-copyfail .
	podman rm bcf-tmp
	@echo "Built ./block-copyfail (linked against UBI8 glibc)"

doctor:
	@echo "Checking prerequisites..."
	@test -f /sys/kernel/btf/vmlinux && echo "  BTF:     ok" || echo "  BTF:     MISSING"
	@grep -q bpf /sys/kernel/security/lsm 2>/dev/null \
	  && echo "  BPF LSM: ok" \
	  || echo "  BPF LSM: MISSING (need lsm=bpf in boot params)"
	@which $(SBCL) >/dev/null 2>&1 && echo "  SBCL:    ok" || echo "  SBCL:    MISSING"
	@test -f $(WHISTLER)/whistler.asd && echo "  Whistler: ok" || echo "  Whistler: MISSING at $(WHISTLER)"
