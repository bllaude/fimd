cmake_minimum_required(VERSION 3.16)
project(fimd VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL 3.0 REQUIRED)

add_executable(fimd
  src/main.cpp
  src/util.cpp
  src/crypto.cpp
  src/baseline.cpp
  src/chainlog.cpp
  src/monitor.cpp
)

target_compile_options(fimd PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
)
target_link_options(fimd PRIVATE -pie -Wl,-z,relro,-z,now)
target_link_libraries(fimd PRIVATE OpenSSL::Crypto)

install(TARGETS fimd RUNTIME DESTINATION sbin)

# ---------------------------------------------------------------------------
# Unit tests (self-contained framework in tests/test_framework.hpp).
# ---------------------------------------------------------------------------
enable_testing()

add_executable(unit_tests
  tests/test_main.cpp
  tests/test_util.cpp
  tests/test_crypto.cpp
  tests/test_baseline.cpp
  tests/test_chainlog.cpp
  tests/test_monitor.cpp
  src/util.cpp
  src/crypto.cpp
  src/baseline.cpp
  src/chainlog.cpp
  src/monitor.cpp
)

target_include_directories(unit_tests PRIVATE src tests)
target_compile_options(unit_tests PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
target_link_libraries(unit_tests PRIVATE OpenSSL::Crypto)

add_test(NAME unit_tests COMMAND unit_tests)
