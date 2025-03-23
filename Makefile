CC=cc
LD=$(CC)

OPT=-O3 -march=native
UTL_OPT=-O2

BASE_CFLAGS=-fPIC
CFLAGS=$(BASE_CFLAGS) $(OPT)
UTL_CFALGS=$(BASE_CFLAGS) $(UTL_OPT)

LDFLAGS=-shared -lc

CRT=
UTL_LDFLAGS=$(CRT) -lc

LIBNAME=hasha

LIB=lib
BIN=bin
SRC=src
INC=include
OBJ=$(BIN)/tmp
TST=tests
UTL=utils

DESTDIR=/usr/
BINDIR=$(DESTDIR)/bin
LIBDIR=$(DESTDIR)/lib
INCDIR=$(DESTDIR)/include

TARGET=$(LIB)/lib$(LIBNAME).so
INST_LIB=$(LIBDIR)/lib$(LIBNAME).so
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

all: lib utils tests

# library
$(TARGET): $(OBJS)
	mkdir -p $(LIB) $(BIN)
	$(LD) $(LDFLAGS) -o $@ $^

$(OBJ)/%.o: $(SRC)/%.c
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -I$(INC) -c $< -o $@

tests: $(TST_EXEC)

# tests
$(OBJ)/%.o: $(TST)/%.c
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -I$(INC) -c $< -o $@ -g

$(TST_EXEC): $(TST_OBJS) $(TARGET)
	mkdir -p $(BIN)
	$(LD) $(UTL_LDFLAGS) -o $@ $^ -L$(LIB) -lhasha

utils: $(UTL_EXEC)

# utils
$(UTL_BIN)/%: $(UTL)/%.c $(TARGET)
	mkdir -p $(UTL_BIN)
	$(CC) $(UTL_CFLAGS) -I$(INC) -o $@ $< -L$(LIB) -lhasha -g

clean:
	rm -rf $(BIN) $(LIB)

install-lib: $(TARGET)
	# Install the shared library
	install -d $(LIBDIR)
	install -m 755 $(TARGET) $(INST_LIB)

	# Install the header file
	# install -d $(INST_INC)

	mkdir -p $(INST_INC) $(INST_INC)/internal
	# install -m 644 $(wildcard $(INC)/$(LIBNAME)/*) $(INST_INC)
	cp -r $(wildcard $(INC)/$(LIBNAME)/*) $(INST_INC)

	@echo "lib$(LIBNAME) installed"

uninstall-lib:
	# Remove the shared library
	rm -f $(INST_LIB)

	# Remove the header file
	rm -rf $(INST_INC)

	@echo "lib$(LIBNAME) uninstalled"

install-execs: $(UTL_EXEC)
	# Install example executables to the binary directory
	install -d $(BINDIR)
	for exec in $(UTL_EXEC); do \
		install -m 755 $$exec $(BINDIR); \
	done

	@echo "$(LIBNAME) utils installed"

uninstall-execs:
	# Remove installed example executables
	for exec in $(notdir $(UTL_EXEC)); do \
		rm -f $(BINDIR)/$$exec; \
	done

	@echo "$(LIBNAME) utils uninstalled"

check: $(TEST_EXEC)
	$(TEST_EXEC)

bench: $(UTL_BIN)/hashabench
	@echo "Running benchmark..."
	$(UTL_BIN)/hashabench

install: install-lib install-execs
uninstall: uninstall-execs uninstall-lib

.PHONY: all install uninstall check bench