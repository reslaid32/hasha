CONFIG = conf.mk
-include $(CONFIG)

MAKEFLAGS += -s

CC ?= cc
LD = $(CC)

ifneq ($(strip $(FOO)),)
	LD += -fuse-ld=$(USELD)
endif

ifeq ("$(strip $(CC))","chibicc")
	EXTRA_CFLAGS += -I./chibicc/include/ 
endif

OPT=-O$(OPT_LEVEL) $(ARCH_FLAGS)
UTL_OPT=-O2

LDFLAGS=-shared
CFLAGS=$(OPT)
UTL_CFALGS=$(BASE_CFLAGS) $(UTL_OPT)

ifeq ($(DEBUG), 1)
	CFLAGS += -g
endif

CFLAGS+=$(EXTRA_CFLAGS)
LDFLAGS+=$(EXTRA_LDLAGS)

CRT=
UTL_LDFLAGS=$(CRT) -lc

ifeq ($(OS),Windows_NT)
  LIBPREFIX=
	LIBEXT=dll
else
  LIBPREFIX=lib
	LIBEXT=so
endif

LIBNAME=hasha

LIB=lib
BIN=bin
SRC=src
INC=include
OBJ=$(BIN)/tmp
TST=tests
UTL=utils

DESTDIR ?= /
PREFIX ?= /usr

BINDIR=$(DESTDIR)$(PREFIX)/bin
ifeq ($(OS),Windows_NT)
  LIBDIR=$(DESTDIR)$(PREFIX)/bin
else
	LIBDIR=$(DESTDIR)$(PREFIX)/lib
endif
INCDIR=$(DESTDIR)$(PREFIX)/include

TARGET=$(LIB)/$(LIBPREFIX)$(LIBNAME).$(LIBEXT)
INST_LIB=$(LIBDIR)/$(LIBPREFIX)$(LIBNAME).$(LIBEXT)
INST_INC=$(INCDIR)/$(LIBNAME)

SRCS=$(wildcard $(SRC)/*.c)
OBJS=$(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS))

TST_SRCS=$(wildcard $(TST)/*.c)
TST_OBJS=$(patsubst $(TST)/%.c,$(OBJ)/%.o,$(TST_SRCS))
TST_EXEC=$(BIN)/unit

UTL_BIN=$(BIN)/utils
UTL_SRCS=$(wildcard $(UTL)/*.c)
UTL_OBJS = $(patsubst $(UTL)/%.c,$(OBJ)/%.o,$(UTL))
UTL_EXEC = $(patsubst $(UTL)/%.c,$(UTL_BIN)/%,$(UTL_SRCS))

lib: $(TARGET)

all: lib tests utils

# library
$(TARGET): $(OBJS)
	@echo "  LD    $@"
	mkdir -p $(LIB) $(BIN)
	$(LD) $(LDFLAGS) -o $@ $^

$(OBJ)/%.o: $(SRC)/%.c
	@echo "  CC    $@"
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -I$(INC) -c $< -o $@

tests: $(TST_EXEC)

# tests
$(OBJ)/%.o: $(TST)/%.c
	@echo "  CC    $@"
	mkdir -p $(OBJ)
	$(CC) -O0 -g -I$(INC) -c $< -o $@

$(TST_EXEC): $(TST_OBJS) $(TARGET)
	@echo "  LD    $@"
	mkdir -p $(BIN)
	$(LD) -o $@ $^ -L$(LIB) -lhasha

utils: $(UTL_EXEC)

# utils
$(UTL_BIN)/%: $(UTL)/%.c $(TARGET)
	@echo "  CCLD  $@"
	mkdir -p $(UTL_BIN)
	$(CC) $(UTL_CFLAGS) -I$(INC) -o $@ $< -L$(LIB) -lhasha

clean:
	@echo "  RM    bin/    lib/"
	rm -rf $(BIN) $(LIB)

install-hdr: $(TARGET)
	install -d $(INST_INC) $(INST_INC)/internal
	find $(INC)/$(LIBNAME) -type f | while read -r file; do \
		target_dir=$(INST_INC)/$$(dirname "$${file#$(INC)/$(LIBNAME)/}"); \
		mkdir -p "$$target_dir"; \
		install -m 644 "$$file" "$$target_dir/"; \
	done
	@echo "  INST  $(INC)/$(LIBNAME)/"

uninstall-hdr:
	rm -rf $(INST_INC)
	@echo "  UNST  $(INC)/$(LIBNAME)/"

install-lib: $(TARGET)
	# Install the shared library
	install -d $(LIBDIR)
	install -m 755 $(TARGET) $(INST_LIB)

	# Install the header file
	# install -d $(INST_INC)

	@echo "  INST  $(TARGET)"

uninstall-lib: uninstall-hdr
	# Remove the shared library
	rm -f $(INST_LIB)

	@echo "  UNST  $(TARGET)"

install-execs: $(UTL_EXEC)
	# Install example executables to the binary directory
	install -d -p $(BINDIR)
	for exec in $(UTL_EXEC); do \
		install -m 755 $$exec $(BINDIR); \
		echo "  INST  $$exec"; \
	done

uninstall-execs:
	# Remove installed example executables
	for exec in $(notdir $(UTL_EXEC)); do \
		rm -f $(BINDIR)/$$exec; \
		echo "  UNST  $$exec"; \
	done

check: $(TST_EXEC)
	@echo "  UNIT  $(TST_EXEC)"
	$(TST_EXEC)

vcheck: $(TST_EXEC)
	@echo "  UNIT  $(TST_EXEC)"
	$(TST_EXEC) -v

bench: $(UTL_BIN)/hashabench
	$(UTL_BIN)/hashabench

autoconfig:
	@echo "# Compiler"                                 >  $(CONFIG)
	@echo "CC             := cc"                       >> $(CONFIG)
	@echo "# Linker [CC -fuse-ld=(USELD)]" >> $(CONFIG)
	@echo "USELD          := # mold"                  >> $(CONFIG)
	@echo "# Optimization level [CC -O(OPT_LEVEL)]" >> $(CONFIG)
	@echo "OPT_LEVEL      := 3"                       >> $(CONFIG)
	@echo "# Enable debug symbols [CC -g]"            >> $(CONFIG)
	@echo "DEBUG          := 0"                       >> $(CONFIG)
	@echo "# Extra flags"                             >> $(CONFIG)
	@echo "ARCH_FLAGS     := -march=native -mtune=native" >> $(CONFIG)
	@echo "EXTRA_CFLAGS   := -fPIC -Wall -Wextra"     >> $(CONFIG)
	@echo "EXTRA_LDFLAGS  := # -flto"                 >> $(CONFIG)

install: install-hdr install-lib install-execs
uninstall: uninstall-hdr uninstall-execs uninstall-lib

.PHONY: autoconfig all install uninstall check vcheck bench
