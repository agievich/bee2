cmake_minimum_required(VERSION 3.5)
project(BEE2 C)

set(BEE2_VERSION_MAJOR "2")
set(BEE2_VERSION_MINOR "1")
set(BEE2_VERSION_PATCH "5")
set(BEE2_VERSION 
  "${BEE2_VERSION_MAJOR}.${BEE2_VERSION_MINOR}.${BEE2_VERSION_PATCH}")

option(BUILD_SHARED_LIBS "Build shared libraries." ON)
option(BUILD_FAST "Build with the SAFE_FAST directive." OFF)
option(BUILD_CMD "Build bee2cmd." ON)
option(BUILD_TESTS "Build tests." ON)
option(BUILD_DOC "Build documentation (doxygen required)." OFF)
option(INSTALL_HEADERS "Install headers." ON)

if(CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build: \
      Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
    FORCE)
else()
  set(CMAKE_BUILD_TYPE Release
     CACHE STRING "Choose the type of build: \
       Release Debug Coverage ASan ASanDbg MemSan MemSanDbg Check"
     FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")

string(COMPARE EQUAL "GNU" "${CMAKE_C_COMPILER_ID}" CMAKE_COMPILER_IS_GNUCC)
string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(COMPARE EQUAL "MSVC" "${CMAKE_C_COMPILER_ID}" CMAKE_COMPILER_IS_MSVC)

if (BASH_PLATFORM)
  if(BASH_PLATFORM STREQUAL "BASH_32")
    set(BASH_32 ON BOOL)
    add_definitions(-DBASH_32)
  elseif(BASH_PLATFORM STREQUAL "BASH_SSE2")
    set(BASH_SSE2 ON BOOL)
    add_definitions(-DBASH_SSE2)
  elseif(BASH_PLATFORM STREQUAL "BASH_AVX2")
    set(BASH_AVX2 ON BOOL)
    add_definitions(-DBASH_AVX2)
  elseif(BASH_PLATFORM STREQUAL "BASH_AVX512")
    set(BASH_AVX512 ON BOOL)
    add_definitions(-DBASH_AVX512)
  elseif(BASH_PLATFORM STREQUAL "BASH_NEON")
    set(BASH_NEON ON BOOL)
    add_definitions(-DBASH_NEON)
  elseif(NOT BASH_PLATFORM STREQUAL "BASH_64")
    message(WARNING "Unknown BASH_PLATFORM (${BASH_PLATFORM}). \
      This option will be ignored")
    unset(BASH_PLATFORM CACHE)
  endif()
endif()

if (BASH_PLATFORM)
  message(STATUS "Requested BASH_PLATFORM: ${BASH_PLATFORM}")
endif()

# Lists of warnings and command-line flags:
# * https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
# * https://clang.llvm.org/docs/ClangCommandLineReference.html
# * https://clang.llvm.org/docs/DiagnosticsReference.html

set(CMAKE_C_WARNINGS "-Wall -Wextra -W -Wdeclaration-after-statement \
  -Wwrite-strings -Wno-parentheses -Wno-unused-parameter -Wno-strict-aliasing \
  -Wno-xor-used-as-pow")

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_WARNINGS "${CMAKE_C_WARNINGS} -Wno-maybe-uninitialized")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_WARNINGS}")
  if(BASH_SSE2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2")
  elseif(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f \
      -fno-asynchronous-unwind-tables")
  elseif(BASH_NEON)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  endif()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 \
    -fno-strict-aliasing")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS_COVERAGE} -O0 -g3 -coverage")
  set(CMAKE_C_FLAGS_ASAN "${CMAKE_C_FLAGS_ASAN} -fsanitize=address \
    -fno-common -O3 -fno-strict-aliasing")
  set(CMAKE_C_FLAGS_ASANDBG "${CMAKE_C_FLAGS_ASANDBG} -fsanitize=address \
    -fno-common -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_C_FLAGS_CHECK "${CMAKE_C_FLAGS_CHECK} -Werror -O1 \
    -Wcast-qual -fanalyzer")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
  set(CMAKE_C_WARNINGS "${CMAKE_C_WARNINGS} -Wno-parentheses-equality \
    -Wno-logical-op-parentheses -Wno-bitwise-op-parentheses")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_WARNINGS}")
  if(BASH_SSE2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2")
  elseif(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
      -mavx512f -fno-asynchronous-unwind-tables")
  elseif(BASH_NEON)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  endif()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 \
    -fno-strict-aliasing")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3")
  set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS_COVERAGE} -O0 -g3 -coverage")
  set(CMAKE_C_FLAGS_ASAN "${CMAKE_C_FLAGS_ASAN} -fsanitize=address \
    -fno-common -fsanitize=undefined -fno-sanitize-recover -O3 \
    -fno-strict-aliasing")
  set(CMAKE_C_FLAGS_ASANDBG "${CMAKE_C_FLAGS_ASANDBG} -fsanitize=address \
    -fno-common -fsanitize=undefined -fno-sanitize-recover -O1 -g3 \
    -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_C_FLAGS_MEMSAN "${CMAKE_C_FLAGS_MEMSAN} -fsanitize=memory -O3 \
    -fno-strict-aliasing")
  set(CMAKE_C_FLAGS_MEMSANDBG "${CMAKE_C_FLAGS_MEMSANDBG} -fsanitize=memory \
    -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls \
    -fsanitize-memory-track-origins=2")
  set(CMAKE_C_FLAGS_CHECK "${CMAKE_C_FLAGS_CHECK} -Werror -O1 -Wcast-qual")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
  # disable security warnings for sprintf()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D _CRT_SECURE_NO_WARNINGS")
  if(BASH_SSE2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:SSE2")
  elseif(BASH_AVX2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2")
  elseif(BASH_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX512")
  endif()
endif(CMAKE_COMPILER_IS_MSVC)

if(BUILD_FAST)
  add_definitions(-DSAFE_FAST)
endif()

if(NOT LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR lib)
endif()

if(NOT BIN_INSTALL_DIR)
  set(BIN_INSTALL_DIR bin)
endif()

include_directories(include)
include_directories(src)

add_subdirectory(include)
add_subdirectory(src)

if(BUILD_CMD)
  add_subdirectory(cmd)
endif()

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

if(BUILD_DOC)
  add_subdirectory(doc)
endif()
