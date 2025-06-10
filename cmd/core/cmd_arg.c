/*
*******************************************************************************
\file cmd_arg.c
\brief Command-line interface to Bee2: parsing arguments
\project bee2/cmd 
\created 2022.06.08
\version 2025.06.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Командная строка
*******************************************************************************
*/

static size_t argWsDec(const char* args)
{
	size_t c = 0;
	while (args[c] == ' ' || args[c] == '\t')
		++c;
	return c;
}

static size_t argArgDec(char* arg, size_t* size, const char* args)
{
	size_t c;
	size_t s;
	bool_t quotes;	
	// pre
	ASSERT(strIsValid(args));
	ASSERT(memIsNullOrValid(size, O_PER_S));
	ASSERT(argWsDec(args) == 0);
	// просмотреть символы args
	for (c = s = 0, quotes = FALSE; args[c] != '\0';)
	{
		// разделитель?
		if (!quotes && (args[c] == ' ' || args[c] == '\t'))
			break;
		// кавычка?
		if (args[c] == '"')
		{
			// открывающая?
			if (!quotes)
				++c, quotes = TRUE;
			// двойная?
			else if (args[c + 1] == '"')	
			{
				if (arg)
					arg[s] = '"';
				++s, c += 2;
			}
			// закрывающая?
			else
				++c, quotes = FALSE;
			continue;
		}
		// обратный слэш?
		if (args[c] == '\\')
		{
			size_t c1;
			// c1 <- число слэшей
			for (c1 = 1; args[c + c1] == '\\'; ++c1);
			// кавычка после c1 слэшей?
			if (args[c + c1] == '"')
			{
				if (arg)
					memCopy(arg + s, args + c, c1 / 2);
				s += c1 / 2, c += c1;
				// кавычка-литерал?
				if (c1 % 2)
				{
					if (arg)
						arg[s] = '"';
					++s, ++c;
				}
			}
			// без кавычки
			else
			{
				if (arg)
					memCopy(arg + s, args + c, c1);
				s += c1, c += c1;
			}	
			continue;
		}
		// регулярный символ
		if (arg)
			arg[s] = args[c];
		++s, ++c;
	}
	// незакрытая кавычка? значит строка args исчерпана
	ASSERT(!quotes || args[c] == '\0');
	// завершить
	if (arg)
		arg[s] = '\0';
	if (size)
		*size = s + 1;
	return c + argWsDec(args + c);
}

err_t cmdArgCreate(int* argc, char*** argv, const char* args)
{
	size_t count;
	size_t size;
	int pos;
	void* state;
	char* strs;
	// входной контроль
	ASSERT(strIsValid(args));
	ASSERT(memIsDisjoint2(argc, sizeof(int), argv, sizeof(char**)));
	// определить число и длины аргументов
	for (*argc = 0, size = 0, count = argWsDec(args); args[count] != '\0';)
	{
		size_t c;
		size_t s;
		c = argArgDec(0, &s, args + count);
		*argc += 1, count += c, size += s;
	}
	// выделить и разметить память
	if (!(state = blobCreate(*argc * sizeof(char*) + size)))
		return ERR_OUTOFMEMORY;
	*argv = (char**)state;
	strs = (char*)(*argv + *argc);
	// разобрать аргументы
	for (size = 0, pos = 0, count = argWsDec(args); args[count] != '\0';)
	{
		size_t c;
		size_t s;
		(*argv)[pos] = strs + size;
		c = argArgDec((*argv)[pos], &s, args + count);
		count += c, size += s, ++pos;
	}
	ASSERT(pos == *argc);
	return ERR_OK;
}

void cmdArgClose(char** argv)
{
	blobClose(argv);
}
