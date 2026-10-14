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
