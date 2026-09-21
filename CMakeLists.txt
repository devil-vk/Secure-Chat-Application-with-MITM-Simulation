cmake_minimum_required(VERSION 3.16)
project(SecureChatMITM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# --- OpenSSL --------------------------------------------------------------
# On macOS with Homebrew, OpenSSL is keg-only; give CMake a hint if needed.
if(APPLE AND NOT OPENSSL_ROOT_DIR)
  execute_process(COMMAND brew --prefix openssl@3
                  OUTPUT_VARIABLE BREW_OPENSSL
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(BREW_OPENSSL)
    set(OPENSSL_ROOT_DIR ${BREW_OPENSSL})
  endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# --- shared code ----------------------------------------------------------
add_library(sca_common STATIC
  src/common/crypto.cpp
  src/common/net.cpp
  src/common/tls.cpp)
target_link_libraries(sca_common PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# --- executables ----------------------------------------------------------
add_executable(chat_server src/server/chat_server.cpp)
target_link_libraries(chat_server PRIVATE sca_common)

add_executable(chat_client src/client/chat_client.cpp)
target_link_libraries(chat_client PRIVATE sca_common)

add_executable(p2p_chat src/p2p/p2p_chat.cpp)
target_link_libraries(p2p_chat PRIVATE sca_common)

add_executable(mitm_proxy src/mitm/mitm_proxy.cpp)
target_link_libraries(mitm_proxy PRIVATE sca_common)
