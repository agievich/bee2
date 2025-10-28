/*
*******************************************************************************
\file ver.c
\brief Version and build information
\project bee2/cmd 
\created 2022.06.22
\version 2025.10.28
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Утилита ver

Функционал:
- печать версии Bee2 и даты сборки;
- печать информации о платформе;
- печать информации об инструментах сборки;
- печать опций сборки.
*******************************************************************************
*/

static const char _name[] = "ver";
static const char _descr[] = "print version and build information";

static int verUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  ver\n"
		"    print version and build information\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Печать информации

\thanks https://blog.kowalczyk.info/article/j/
	guide-to-predefined-macros-in-c-compilers-gcc-clang-msvc-etc..html

\warning Порядок проверки директив в функции verCompiler() важен:
- Clang кроме __clang__ может определять также
  __GNUC__ / __GNUC_MINOR__ / __GNUC_PATCHLEVEL__, указывая
  тем самым на версию GCC, с которой обеспечивается совместимость
  (см. https://stackoverflow.com/questions/38499462/
  how-to-tell-clang-to-stop-pretending-to-be-other-compilers);
- Clang кроме __clang__ может определять также _MSC_VER;
- MinGW64 кроме __MINGW64__ определяет также __MINGW32__;
- MinGW32 и MinGW64 определяют __GNUC__.

\todo Emscripten:
\code
	#elif defined(__EMSCRIPTEN__)
		sprintf(str, "emscripten (%d.%d)",
			__EMSCRIPTEN_major__, __EMSCRIPTEN_minor__);
\endcode
*******************************************************************************
*/

static const char* verArch()
{
#if defined(__M_IX86) || defined(_X86_) || defined(i386) ||\
	defined(__i386__) || defined(_M_I86) || defined(_M_IX86)
	return "x86";
#elif defined(_M_IA64) || defined(__ia64__) || defined(_M_X64) ||\
	defined(_M_AMD64) || defined(__amd64__) || defined(__amd64) ||\
	defined(__x86_64__)
	return "x64";
#elif defined(_MIPSEL) || defined (__MIPSEL) || defined (__MIPSEL__) ||\
	defined(_MIPSEB) || defined (__MIPSEB) || defined (__MIPSEB__)
	return "MIPS";
#elif defined(__arm__) || defined(__ARMEL__) || defined(__ARMEB__) ||\
	defined(_M_ARM)
	return "ARM";
#elif defined(__AARCH64EL__) || defined(__AARCH64EB__) || defined(_M_ARM64)
	return "ARM64";
#elif defined(_M_ALPHA) || defined(__alpha__) || defined(__alpha)
	return "ALPHA";
#elif defined(__EMSCRIPTEN__)
	return "EMSCRIPTEN";
#elif defined(__s390__)
	return "s390";
#elif defined(__s390x__)
	return "s390x";
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
	return "POWERPC";
#elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__)
	return "POWERPC64";
#elif defined(sparc) || defined(__sparc)
	return "SPARC";
#else
	return "unknown";
#endif
}

static const char* verOS()
{
#if defined(OS_WIN)
	return "Windows";
#elif defined(OS_UNIX)
	#if defined(OS_ANDROID)
		return "Android";
	#elif defined(OS_LINUX)
		return "Linux";
	#elif defined(OS_IPHONE)
		return "Apple/iPhone";
	#elif defined(OS_APPLE)
		return "Apple";
	#else
		return "UNIX";
	#endif
#else 
	return "unknown";
#endif
}

static const char* verEndianness()
{
#if defined(LITTLE_ENDIAN)
	return "LE";
#else
	return "BE";
#endif
}

static const char* verCompiler()
{
	static char str[128];
#if defined(__clang__)
	#if defined(_MSC_VER)
		sprintf(str,
			"clang (%d.%d.%d)\n"
			"      compatibility: Visual Studio (%d)",
			__clang_major__, __clang_minor__, __clang_patchlevel__,
			_MSC_FULL_VER);
	#elif defined(__GNUC__)
		sprintf(str,
			"clang (%d.%d.%d)\n"
			"      compatibility: gcc (%d.%d.%d)",
			__clang_major__, __clang_minor__, __clang_patchlevel__,
			__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
	#else
		sprintf(str,
			"clang (%d.%d.%d)\n",
			__clang_major__, __clang_minor__, __clang_patchlevel__);
	#endif
#elif defined(_MSC_VER)
	sprintf(str,
		"Visual Studio (%d)", _MSC_FULL_VER);
#elif defined(__MINGW64__)
	sprintf(str,
		"MinGW64 (%d.%d)\n"
		"      using: gcc (%d.%d.%d)",
		__MINGW64_VERSION_MAJOR, __MINGW64_VERSION_MINOR,
		__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__MINGW32__)
	sprintf(str,
		"MinGW32 (%d.%d)\n"
		"      using: gcc (%d.%d.%d)",
		__MINGW64_VERSION_MAJOR, __MINGW64_VERSION_MINOR,
		__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__GNUC__)
	sprintf(str,
		"gcc (%d.%d.%d)",
		__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else 
	return "unknown";
#endif
	return str;
}

static const char* verNDebug()
{
#ifdef NDEBUG
	return "ON";
#else
	return "OFF";
#endif
}

static const char* verSafe()
{
#ifdef SAFE_FAST
	return "OFF";
#else
	return "ON";
#endif
}

/*
*******************************************************************************
Печать информации
*******************************************************************************
*/

extern const char bash_platform[];

static void verPrint()
{
	printf(
		"Bee2: a cryptographic library\n"
		"  version: %s [%s]\n"
		"  platform:\n"
		"    arch: %s\n"
		"    os: %s\n"
		"    B_PER_S: %u\n"
		"    B_PER_W: %u\n"
		"    endianness: %s\n"
		"    freq: %u kHz\n"
		"  build tools:\n"
		"    compiler: %s\n"
		"  build options:\n"
		"    NDEBUG: %s\n"
		"    safe (constant-time): %s\n"
		"    bash_platform: %s\n",
		utilVersion(), __DATE__,
		verArch(),
		verOS(),
		(unsigned)B_PER_S,
		(unsigned)B_PER_W,
		verEndianness(),
		(unsigned)(tmFreq() / 1000u),
		verCompiler(),
		verNDebug(),
		verSafe(),
		bash_platform
	);
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int verMain(int argc, char* argv[])
{
	if (argc != 1)
		return verUsage();
	verPrint();
	return 0;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t verInit()
{
	return cmdReg(_name, _descr, verMain);
}
