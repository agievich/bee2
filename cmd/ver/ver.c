/*
*******************************************************************************
\file ver.c
\brief Version and build information
\project bee2/cmd 
\created 2022.06.22
\version 2023.06.08
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

extern const char bash_platform[];

static void verPrint()
{
	printf(
		"Bee2: a cryptographic library\n"
		"  version: %s [%s]\n"
		"  build options\n"
		"    safe (constant-time): %s\n"
		"    bash_platform: %s\n",
		utilVersion(), __DATE__,
#ifdef SAFE_SAFE
		"ON",
#else
		"OFF",
#endif
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
