/*
*******************************************************************************
\file ver.c
\brief Version and build information
\project bee2/cmd 
\created 2022.06.22
\version 2023.10.16
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита ver

Функционал:
- печать версии Bee2 и даты сборки;
- печать опций сборки:
  - SAFE_FAST vs SAFE_SAFE;
  - bash_platform.
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
*******************************************************************************
*/

static const char* verEndianness()
{
#if defined(LITTLE_ENDIAN)
	return "LE";
#else
	return "BE";
#endif
}

static const char* verOS()
{
#if defined(OS_WIN)
	return "Windows";
#elif defined(OS_UNIX)
	#if defined(OS_LINUX)	
		return "Linux";
	#elif defined(OS_APPLE)
		return "Apple";
	#else
		return "UNIX";
	#endif
#else 
	return "unknown";
#endif
}

static const char* verIsSafe()
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
		"  platform\n"
		"    os: %s\n"
		"    B_PER_S: %u\n"
		"    B_PER_W: %u\n"
		"    endianness: %s\n"
		"  build options\n"
		"    safe (constant-time): %s\n"
		"    bash_platform: %s\n",
		utilVersion(), __DATE__,
		verOS(),
		(unsigned)B_PER_S, (unsigned)B_PER_W, 
		verEndianness(),
		verIsSafe(),
		bash_platform
	);
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int verMain(int argc, char* argv[])
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
