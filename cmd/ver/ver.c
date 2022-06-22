/*
*******************************************************************************
\file ver.c
\brief Version and build information
\project bee2/cmd 
\created 2022.06.22
\version 2022.06.22
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита ver

Функционал:
- печать версии bee2;
- печать опций SAFE_FAST vs SAFE_SAFE;
- печать опции bash_platform.
*******************************************************************************
*/

static const char _name[] = "ver";
static const char _descr[] = "print version and build information";

int verUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  ver\n"
		"    print version and build information",
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

void verPrint()
{
	printf(
		"Bee2 [v%s]\n"
		"  build options\n"
		"    safe (constant-time): %s\n"
		"    bash_platform: %s\n",
		utilVersion(),
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
