PRIV_DIR = $(MIX_APP_PATH)/priv
NIF_SO = $(PRIV_DIR)/p11ex_nif.so

ERL_ROOT = /opt/homebrew/Cellar/erlang/27.2/lib/erlang
MACOS_CFLAGS = -bundle -bundle_loader $(ERL_ROOT)/erts-*/bin/beam.smp 

CFLAGS = -fPIC -I$(ERTS_INCLUDE_DIR) $(MACOS_CFLAGS)
#LDFLAGS = -shared

.PHONY: all clean

all: $(NIF_SO)

$(NIF_SO): c_src/p11ex_nif.c
	mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(NIF_SO) 
