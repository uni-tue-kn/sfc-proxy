######################################################################################################
# Use Bash instead of Dash on Debian/Ubuntu:
SHELL := /usr/bin/env bash
######################################################################################################
TARGET_NAME := sfc-proxy
######################################################################################################
KERN_TARGET := $(TARGET_NAME).bpf
KERN_SRC_FILES := $(wildcard src/*kern.c)
KERN_OBJ_FILES := $(KERN_SRC_FILES:.c=.o)
KERN_DEP_FILES := $(KERN_OBJ_FILES:%.o=%.d)
######################################################################################################
USER_TARGET := $(TARGET_NAME)
USER_SRC_FILES := $(wildcard src/*user.c)
USER_OBJ_FILES := $(USER_SRC_FILES:.c=.o)
USER_DEP_FILES := $(USER_OBJ_FILES:%.o=%.d)
######################################################################################################
SRC_FILES := $(wildcard */*.c)
HDR_FILES := $(wildcard */*.h)
OBJ_FILES := $(wildcard */*.o)
DEP_FILES := $(wildcard */*.d)
C_FILES := $(SRC_FILES) $(HDR_FILES)
######################################################################################################
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
# clang is the front-end compiler for various languages and uses LLVM as it's backend
CLANG ?= clang
CLANG_FORMAT ?= clang-format
LLC ?= llc
######################################################################################################
# TODO: Drop some -Wno-* flags when everything's finished (e.g. -Wno-missing-variable-declarations)
CFLAGS := -Weverything -Wno-pedantic -Wno-unused-function -Wno-cast-align -Wno-cast-qual -Wno-missing-declarations -Wno-atomic-implicit-seq-cst -Wno-missing-variable-declarations
BPF_EXTRA_CFLAGS = -fno-stack-protector # Stack protection doesn't work with BPF.
CFLAGS_DEV := -Werror
######################################################################################################

.PHONY: all
all: $(KERN_TARGET) $(USER_TARGET)

.PHONY: format
format:
	@echo "Formating $(C_FILES) according to the Linux kernel coding style"
	$(CLANG_FORMAT) -i $(C_FILES)

$(USER_TARGET) : $(USER_OBJ_FILES)
	$(CLANG) -o $(USER_TARGET) $(USER_OBJ_FILES)
	@chmod +x $(USER_TARGET)

$(USER_OBJ_FILES) : $(USER_SRC_FILES)
	@echo "Building $@ from $<"
	$(CLANG) -MMD -O2 $(CFLAGS) $(CFLAGS_DEV) -c -g -o $@ -x c $<

$(KERN_TARGET): $(KERN_OBJ_FILES)
	@echo "Linking $< to build $@"
	${LLC} -march=bpf -filetype=obj $< -o $@

$(KERN_OBJ_FILES) : $(KERN_SRC_FILES)
	@echo "Building $@ from $<"
	$(CLANG) -D__KERNEL__ -MMD -O2 -target bpf $(CFLAGS) $(CFLAGS_DEV) $(BPF_EXTRA_CFLAGS) -S -emit-llvm -g -o $@ -x c $<

.PHONY: clean
clean:
	@echo "Cleaning the build..."
	rm -f $(DEP_FILES) $(OBJ_FILES) $(KERN_TARGET) $(USER_TARGET)

.PHONY: install
install:
	install -Dt $(BINDIR) $(USER_TARGET)
	install -Dt $(DATADIR)/bpf $(KERN_TARGET)

# MMD generates dependency files in Makefile format
# therefore we have to include the rules.
-include $(KERN_DEP_FILES) $(USER_DEP_FILES)
