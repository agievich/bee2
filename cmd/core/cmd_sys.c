/*
*******************************************************************************
\file cmd_sys.c
\brief Command-line interface to Bee2: system environment
\project bee2/cmd 
\created 2025.04.20
\version 2025.04.21
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include "whereami.h"

/*
*******************************************************************************
Пути к исполняемым файлам / модулям

\thanks Gregory Pakosz [https://github.com/gpakosz/whereami]
*******************************************************************************
*/

err_t cmdSysExePath(char* path, size_t* count)
{
	int len;
	// pre
	ASSERT(memIsValid(count, O_PER_S));
	// определить длину пути
	if (!path)
	{
		len = wai_getExecutablePath(path, 0, 0);
		if (len < 0)
			return ERR_SYS;
		if (++len <= 0 || (int)(size_t)len != len)
			return ERR_OVERFLOW;
		*count = (size_t)len;
	}
	// определить путь
	else
	{
		ASSERT(memIsValid(path, *count));
		if (*count < 1)
			return ERR_OUTOFMEMORY;
		len = wai_getExecutablePath(path, (int)(*count - 1), 0);
		if (len < 0)
			return ERR_SYS;
		*count = (size_t)(len + 1);
	}
	return ERR_OK;
}

err_t cmdSysModulePath(char* path, size_t* count)
{
	int len;
	// pre
	ASSERT(memIsValid(count, O_PER_S));
	// определить длину пути
	if (!path)
	{
		len = wai_getModulePath(path, 0, 0);
		if (len < 0)
			return ERR_SYS;
		if (++len <= 0 || (int)(size_t)len != len)
			return ERR_OVERFLOW;
		*count = (size_t)len;
	}
	// определить путь
	else
	{
		ASSERT(memIsValid(path, *count));
		if (*count < 1)
			return ERR_OUTOFMEMORY;
		len = wai_getModulePath(path, (int)(*count - 1), 0);
		if (len < 0)
			return ERR_SYS;
		*count = (size_t)(len + 1);
	}
	return ERR_OK;
}
