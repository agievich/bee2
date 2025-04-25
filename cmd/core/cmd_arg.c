/*
*******************************************************************************
\file cmd_arg.c
\brief Command-line interface to Bee2: parsing arguments
\project bee2/cmd 
\created 2022.06.08
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "../cmd.h"

/*
*******************************************************************************
Командная строка
*******************************************************************************
*/

#ifdef OS_UNIX

#include <wordexp.h>

err_t cmdArgCreate(int* argc, char*** argv, const char* args)
{
	wordexp_t we[1];
	size_t count;
	int pos;
	// входной контроль
	ASSERT(strIsValid(args));
	ASSERT(memIsDisjoint2(argc, sizeof(int), argv, sizeof(char**)));
	// разбить args на строки широких символов
	switch (wordexp(args, we, 0))
	{
	case 0:
		break;
	case WRDE_NOSPACE:
		return ERR_OUTOFMEMORY;
	default:
		return ERR_CMD_PARAMS;
	}
	*argv = 0, *argc = we->we_wordc;
	// обработать отсутствие аргументов
	if (*argc == 0)
	{
		wordfree(we);
		return ERR_OK;
	}
	// перенести аргументы в блоб
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
		count += strLen(we->we_wordv[pos]) + 1;
	if (!(*argv = blobCreate(count)))
	{
		wordfree(we);
		return ERR_OUTOFMEMORY;
	}
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		(*argv)[pos] = (char*)*argv + count;
		strCopy((*argv)[pos], we->we_wordv[pos]);
		count += strLen((*argv)[pos]) + 1;
	}
	// завершить
	wordfree(we);
	return ERR_OK;
}

#elif defined OS_WIN

#include <windows.h>

err_t cmdArgCreate(int* argc, char*** argv, const char* args)
{
	wchar_t* argsw = 0;
	wchar_t** argvw = 0;
	size_t count;
	int pos;
	// pre
	ASSERT(strIsValid(args));
	ASSERT(memIsDisjoint2(argc, sizeof(int), argv, sizeof(char**)));
	// разбить args на строки широких символов
	if (!(argsw = memAlloc((strLen(args) + 1) * sizeof(wchar_t))))
		return ERR_OUTOFMEMORY;
	if (!MultiByteToWideChar(CP_ACP, 0, args, -1, argsw, (int)strLen(args) + 1) ||
		!(argvw = CommandLineToArgvW(argsw, argc)))
	{
		memFree(argsw);
		return ERR_CMD_PARAMS;
	}
	memFree(argsw);
	ASSERT(*argc >= 0);
	// обработать отсутствие аргументов
	*argv = 0;
	if (*argc == 0)
		return ERR_OK;
	// перенести аргументы в блоб
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		int len = WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1,
			NULL, 0, NULL, NULL);
		if (!len)
		{
			LocalFree(argvw);
			return ERR_CMD_PARAMS;
		}
		count += (size_t)len;
	}
	if (!(*argv = blobCreate(count)))
	{
		LocalFree(argvw);
		return ERR_OUTOFMEMORY;
	}
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		int len;
		(*argv)[pos] = (char*)*argv + count;
		len = WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1, NULL, 0,
			NULL, NULL);
		ASSERT(len);
		WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1, (*argv)[pos], len,
			NULL, NULL);
		count += (size_t)len;
	}
	// завершить
	LocalFree(argvw);
	return ERR_OK;
}

#else

#error "Not implemented"

#endif

void cmdArgClose(char** argv)
{
	blobClose(argv);
}

