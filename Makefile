# Tricep NIF Makefile

.PHONY: all nif clean

UNAME=$(shell uname)
TARGET_DIR=$(MIX_APP_PATH)/priv
TARGET_NIF=$(TARGET_DIR)/tricep_nif.so

CFLAGS=-Werror -Wfatal-errors -Wall -Wextra -O2 -std=c11 -pedantic -fPIC

ERL_INTERFACE_INCLUDE_DIR ?= $(shell elixir --eval 'IO.puts(Path.join([:code.root_dir(), "usr", "include"]))')

SYMFLAGS=-fvisibility=hidden
ifeq ($(UNAME), Linux)
	SYMFLAGS+=
else ifeq ($(UNAME), Darwin)
	SYMFLAGS+=-undefined dynamic_lookup
else
	$(error "Unsupported platform")
endif

all: nif
	@:

clean:
	rm -f $(TARGET_NIF)

nif: $(TARGET_NIF)

$(TARGET_NIF): c_src/tricep_nif.c
	@mkdir -p $(TARGET_DIR)
	$(CC) $(CFLAGS) -I$(ERL_INTERFACE_INCLUDE_DIR) $(SYMFLAGS) -shared -o $@ $<
