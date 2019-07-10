cmake_minimum_required(VERSION 2.6)
project(BEE2 C)

set(BEE2_VERSION_MAJOR "2")
set(BEE2_VERSION_MINOR "0")
set(BEE2_VERSION_PATCH "5")
set(BEE2_VERSION 
  "${BEE2_VERSION_MAJOR}.${BEE2_VERSION_MINOR}.${BEE2_VERSION_PATCH}")

option(BUILD_SHARED_LIBS "Build shared libraries." ON)
option(BUILD_FAST "Build with the SAFE_FAST directive." OFF)
option(BUILD_APPS "Build apps." ON)
option(BUILD_TESTS "Build tests." ON)
option(BUILD_DOC "Build documentation (doxygen required)." OFF)
option(INSTALL_HEADERS "Install headers." ON)
#option(BASH_32 "Optimize Bash for 32-bit platforms." OFF)
#option(BASH_AVX2 "Optimize Bash for AVX2 instructions." OFF)
#option(BASH_AVX512 "Optimize Bash for AVX512 instructions." OFF)

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")

if(CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
      CACHE STRING 
      "Choose the type of build: Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
      FORCE)
else()
  set(CMAKE_BUILD_TYPE Release
      CACHE STRING 
      "Choose the type of build: Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
      FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")

if (BASH_PLATFORM)
  if(${BASH_PLATFORM} STREQUAL BASH_32)
    set(BASH_32 ON BOOL)
    add_definitions(-DBASH_32)
  elseif(${BASH_PLATFORM} STREQUAL BASH_AVX2)
    set(BASH_AVX2 ON BOOL)
    add_definitions(-DBASH_AVX2)
  elseif(${BASH_PLATFORM} STREQUAL BASH_AVX512)
    set(BASH_AVX512 ON BOOL)
    add_definitions(-DBASH_AVX512)
  elseif(NOT ${BASH_PLATFORM} STREQUAL BASH_64)
    message(WARNING "Unknown BASH_PLATFORM (${BASH_PLATFORM}). This option will be ignored") 
    unset(BASH_PLATFORM CACHE)
  endif()
endif()

if (BASH_PLATFORM)
  message(STATUS "Requested BASH_PLATFORM: ${BASH_PLATFORM}")
endif()

set(CMAKE_C_WARNINGS
  "-Wall -Wextra -W -Wdeclaration-after-statement -Wwrite-strings -Wlogical-op -Wno-parentheses -Wno-logical-op-parentheses -Wno-bitwise-op-parentheses -Wno-unused-parameter -Wno-strict-aliasing")

if(${CMAKE_C_COMPILER_ID} STREQUAL GNU)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_WARNINGS}")
  if(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f -fno-asynchronous-unwind-tables")
  endif()
  set(CMAKE_C_FLAGS_RELEASE     "-O2")
  set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 -coverage")
  set(CMAKE_C_FLAGS_ASAN        "-Werror -fsanitize=address -fno-common -O3")
  set(CMAKE_C_FLAGS_ASANDBG     "-Werror -fsanitize=address -fno-common -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls ")
  set(CMAKE_C_FLAGS_CHECK       "-Werror -O1 -Wcast-qual")
endif(${CMAKE_C_COMPILER_ID} STREQUAL GNU)

if(${CMAKE_C_COMPILER_ID} STREQUAL CLANG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_WARNINGS}")
  if(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f -fno-asynchronous-unwind-tables")
  endif()
  set(CMAKE_C_FLAGS_RELEASE     "-O2")
  set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 -coverage")
  set(CMAKE_C_FLAGS_ASAN        "-Werror -fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover -O3")
  set(CMAKE_C_FLAGS_ASANDBG     "-Werror -fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_C_FLAGS_MEMSAN      "-Werror -fsanitize=memory -O3")
  set(CMAKE_C_FLAGS_MEMSANDBG   "-Werror -fsanitize=memory -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2")
  set(CMAKE_C_FLAGS_CHECK       "-Werror -O1")
endif(${CMAKE_C_COMPILER_ID} STREQUAL CLANG)

if(${CMAKE_C_COMPILER_ID} STREQUAL MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  if(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX512")
  endif()
endif(${CMAKE_C_COMPILER_ID} STREQUAL MSVC)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_SHARED_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
  endif(CMAKE_COMPILER_IS_GNUCC)
  if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_SHARED_LINKER_FLAGS "-fprofile-arcs -ftest-coverage")
  endif(CMAKE_COMPILER_IS_CLANG)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

if(BUILD_FAST)
  add_definitions(-DSAFE_FAST)
endif()

if(NOT LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR lib)
endif()

if(NOT BIN_INSTALL_DIR)
  set(BIN_INSTALL_DIR bin)
endif()

include_directories(include/)
include_directories(src/)

add_subdirectory(include)
add_subdirectory(src)

if(BUILD_APPS)
  add_subdirectory(apps)
endif()

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

if(BUILD_DOC)
  add_subdirectory(doc)
endif()
