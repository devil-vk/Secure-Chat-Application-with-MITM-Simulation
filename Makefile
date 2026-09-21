# Simple Makefile alternative to CMake.
#
#   make            build all four binaries into ./build/bin
#   make certs      generate the certificate chain of trust
#   make clean      remove build artefacts
#
# On macOS, Homebrew OpenSSL is auto-detected. Override with:
#   make OPENSSL_PREFIX=/path/to/openssl

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
else
  OPENSSL_PREFIX ?= /usr
endif

CXX      ?= c++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS  := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lpthread

BIN      := build/bin
COMMON   := src/common/crypto.cpp src/common/net.cpp src/common/tls.cpp

.PHONY: all certs clean dirs

all: dirs $(BIN)/chat_server $(BIN)/chat_client $(BIN)/p2p_chat $(BIN)/mitm_proxy

dirs:
	@mkdir -p $(BIN)

$(BIN)/chat_server: src/server/chat_server.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN)/chat_client: src/client/chat_client.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN)/p2p_chat: src/p2p/p2p_chat.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN)/mitm_proxy: src/mitm/mitm_proxy.cpp $(COMMON)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

certs:
	./certs/generate_certs.sh

clean:
	rm -rf build
