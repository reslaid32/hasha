CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -I./include -fPIC -funroll-loops -O2
CXXFLAGS = -Wall -Wextra -I./include -fPIC

LDFLAGS = -shared
LDFLAGS_TEST =

DEFS =
MARCH = -march=native
MARCH_LD =
UTILS_l = 

LIB = lib
BIN = bin
SRC = src
INC = include
OBJ = $(BIN)/tmp

DESTDIR = /usr/
BINDIR = $(DESTDIR)/bin
LIBDIR = $(DESTDIR)/lib
INCLUDEDIR = $(DESTDIR)/include
TEST_SRC = tests

TARGET_LIBHASHA = $(LIB)/libhasha.so
TARGET_LIBHASHAPP = $(LIB)/libhashapp.so

INSTALL_LIBHASHA = $(LIBDIR)/libhasha.so
INSTALL_LIBHASHAPP = $(LIBDIR)/libhashapp.so
INSTALL_INCDIR = $(INCLUDEDIR)/hasha

SRCS 	= $(wildcard $(SRC)/*.c)
SRCSXX 	= $(wildcard $(SRC)/*.cc)

OBJS = $(patsubst $(SRC)/%.c,$(OBJ)/%.c.o,$(SRCS))
OBJSXX = $(patsubst $(SRC)/%.c,$(OBJ)/%.cc.o,$(SRCSXX))

TEST_SRCS = $(wildcard $(TEST_SRC)/*.c)
TEST_SRCSXX = $(wildcard $(TEST_SRC)/*.cc)
TEST_OBJS = $(patsubst $(TEST_SRC)/%.c,$(OBJ)/%.c.o,$(TEST_SRCS))
TEST_OBJSXX = $(patsubst $(TEST_SRC)/%.cc,$(OBJ)/%.cc.o,$(TEST_SRCS))
TEST_EXEC = $(BIN)/unit
TEST_EXECXX = $(BIN)/unitpp

UTILS_SRC = utils
UTILS_BIN = $(BIN)/utils

UTILS_SRCS = $(wildcard $(UTILS_SRC)/*.c)
UTILS_OBJS = $(patsubst $(UTILS_SRC)/%.c,$(OBJ)/%.c.o,$(UTILS_SRCS))
UTILS_EXEC = $(patsubst $(UTILS_SRC)/%.c,$(UTILS_BIN)/%,$(UTILS_SRCS))

all: lib utils tests

lib: $(TARGET_LIBHASHA) $(TARGET_LIBHASHAPP)

$(TARGET_LIBHASHA): $(OBJS)
	mkdir -p $(BIN)
	mkdir -p $(LIB)
	$(CC) $(LDFLAGS) $(MARCH) $(DEFS) -I$(INC) -o $@ $^

$(TARGET_LIBHASHAPP): $(OBJSXX)
	mkdir -p $(BIN)
	mkdir -p $(LIB)
	$(CXX) $(LDFLAGS) $(MARCH) $(DEFS) -I$(INC) -L$(LIB) -lhasha -o $@ $^

$(OBJ)/%.c.o: $(SRC)/%.c
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) $(MARCH) $(DEFS) -I$(INC) -c $< -o $@

$(OBJ)/%.cc.o: $(SRCXX)/%.cc
	mkdir -p $(OBJ)
	$(CXX) $(CXXFLAGS) $(MARCH) $(DEFS) -I$(INC) -c $< -o $@

# Tests
$(OBJ)/%.c.o: $(TEST_SRC)/%.c
	mkdir -p $(OBJ)
	$(CC) $(CFLAGS) $(MARCH) $(DEFS) -I$(INC) -c $< -o $@ -g

$(OBJ)/%.cc.o: $(TEST_SRC)/%.cc
	mkdir -p $(OBJ)
	$(CXX) $(CXXFLAGS) $(MARCH) $(DEFS) -I$(INC) -c $< -o $@ -g

$(TEST_EXEC): $(TEST_OBJS) $(TARGET_LIBHASHA)
	mkdir -p $(BIN)
	$(CC) $(LDFLAGS_TEST) $(MARCH_LD) -I$(INC) -o $@ $^ -L$(LIB) -lhasha -g

$(TEST_EXECXX): $(TEST_OBJSXX) $(TARGET_LIBHASHAPP)
	mkdir -p $(BIN)
	$(CXX) $(LDFLAGS_TEST) $(MARCH_LD) -I$(INC) -o $@ $^ -L$(LIB) -lhasha -lhashapp -g

utils: $(UTILS_EXEC)

$(UTILS_BIN)/%: $(UTILS_SRC)/%.c $(TARGET_LIBHASHA)
	mkdir -p $(UTILS_BIN)
	$(CC) $(CFLAGS) $(MARCH) $(DEFS) -I$(INC) -o $@ $< -L$(LIB) -lhasha $(UTILS_l) -g

clean-garbage:
	rm -rf $(OBJ)

clean:
	rm -rf $(BIN) $(LIB)

clean-all: clean

install-lib: $(TARGET_LIBHASHA) $(TARGET_LIBHASHAPP)
	# Install the shared library
	install -d $(LIBDIR)
	install -m 755 $(TARGET_LIBHASHA) $(INSTALL_LIBHASHA)
	install -m 755 $(TARGET_LIBHASHAPP) $(INSTALL_LIBHASHAPP)

	# Install the header file
	# install -d $(INCLUDEDIR)

	mkdir -p $(INSTALL_INCDIR) $(INSTALL_INCDIR)/internal $(INSTALL_INCDIR)/pp
	# install -m 644 $(wildcard $(INC)/hasha/*) $(INSTALL_INCDIR)
	cp -r $(wildcard $(INC)/hasha/*) $(INSTALL_INCDIR)

	@echo "libhasha installed"

# Uninstall the library and header file
uninstall-lib:
	# Remove the shared library
	rm -f $(INSTALL_LIBHASHA)
	rm -f $(INSTALL_LIBHASHAPP)

	# Remove the header file
	rm -rf $(INSTALL_INCDIR)

	@echo "libhasha uninstalled"

install-execs: $(UTILS_EXEC)
	# Install example executables to the binary directory
	install -d $(BINDIR)
	for exec in $(UTILS_EXEC); do \
		install -m 755 $$exec $(BINDIR); \
	done

	@echo "hasha utils installed"

uninstall-execs:
	# Remove installed example executables
	for exec in $(notdir $(UTILS_EXEC)); do \
		rm -f $(BINDIR)/$$exec; \
	done

	@echo "hasha utils uninstalled"

install: install-lib install-execs
uninstall: uninstall-execs uninstall-lib

tests: $(TEST_EXEC) $(TEST_EXECXX)

check: $(TEST_EXEC)
	$(TEST_EXEC)

checkpp: $(TEST_EXECXX)
	$(TEST_EXECXX)

bench: $(BIN)/utils/hashabench
	@echo "Running benchmark..."
	$(BIN)/utils/hashabench

.PHONY: all tests bench clean clean-all clean-garbage install-lib install-execs install uninstall-execs uninstall-lib uninstall check checkpp