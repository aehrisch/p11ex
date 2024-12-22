PRIV_DIR = $(MIX_APP_PATH)/priv
NIF_SO = $(PRIV_DIR)/p11ex_nif.so

# Detect OS and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Find Erlang NIF header files
ERTS_INCLUDE_DIR = $(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

# For macOS we still need ERL_ROOT for the bundle_loader path
ifeq ($(UNAME_S),Darwin)
    ERL_ROOT = $(shell erl -eval 'io:format("~s~n", [code:root_dir()])' -s init stop -noshell)
endif

# Map architecture names
ifeq ($(UNAME_M),x86_64)
    ARCH := amd64
else ifeq ($(UNAME_M),amd64)
    ARCH := amd64
else ifeq ($(UNAME_M),arm64)
    ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm64
endif

# Base flags for all platforms
CFLAGS = -fPIC -I$(ERTS_INCLUDE_DIR)

# Linux specific flags
ifeq ($(UNAME_S),Linux)
    LDFLAGS = -shared
    
    # Add architecture-specific flags for Linux
    ifeq ($(ARCH),arm64)
        CFLAGS += -march=armv8-a
    else ifeq ($(ARCH),amd64)
        CFLAGS += -march=x86-64
    endif
endif

# macOS specific flags
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -bundle -arch arm64
    LDFLAGS = -bundle_loader $(ERL_ROOT)/erts-*/bin/beam.smp
    
    # Add architecture-specific flags for macOS
    ifeq ($(ARCH),arm64)
        CFLAGS += -arch arm64
    else ifeq ($(ARCH),amd64)
        CFLAGS += -arch x86_64
    endif
endif

# Debug information
debug-info:
	@echo "Operating System: $(UNAME_S)"
	@echo "Architecture: $(ARCH) ($(UNAME_M))"
	@echo "ERTS_INCLUDE_DIR: $(ERTS_INCLUDE_DIR)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"

.PHONY: all clean debug-info

all: debug-info $(NIF_SO)

$(NIF_SO): c_src/p11ex_nif.c
	mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(NIF_SO)
