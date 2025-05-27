/*
*******************************************************************************
\file es.c
\brief Dealing with entropy sources
\project bee2/cmd 
\created 2021.04.20
\version 2025.05.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/dec.h>
#include <bee2/core/err.h>
#include <bee2/core/file.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/mt.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/core/word.h>
#include "../cmd.h"

/*
*******************************************************************************
Утилита es

Функционал:
- перечень доступных источников энтропии;
- проверка работоспосбности источников энтропии;
- выгрузка данных от стандартных источников энтропии;
- эксперименты с источником timer.

Пример:
  bee2cmd es print
  bee2cmd es read trng2 128 file
*******************************************************************************
*/

static const char _name[] = "es";
static const char _descr[] = "monitor entropy sources";

static int esUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  es print\n"
		"    list available entropy sources and determine their health\n"
		"  es read <source> <count> <file>\n"
		"    read <count> Kbytes from <source> and store them in <file>\n"
		"  <source> in {trng, trng2, sys, sys2, timer, timerNN}\n"
		"    timerNNN -- use NNN sleep delays to produce one output bit\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Информация об источниках энтропии

print
*******************************************************************************
*/

static err_t esPrint(int argc, char* argv[])
{
	const char* sources[] = { "trng", "trng2", "sys", "sys2", "timer" };
	size_t pos;
	size_t count;
	size_t read;
	// проверить параметры
	if (argc != 0)
		return ERR_CMD_PARAMS;
	// опрос источников
	printf("Sources:");
	for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
		if (rngESRead(&read, 0, 0, sources[pos]) == ERR_OK)
		{
			printf(" %s%c", sources[pos], 
				rngESTest(sources[pos]) == ERR_OK ? '+' : '-');
			++count;
		}
	printf(count ? "\n" : " none\n");
	// общая работоспособность
	printf("Health (at least two healthy sources): %c\n", 
		rngESHealth() == ERR_OK ? '+' : '-');
	printf("Health2 (there is a healthy physical source): %c\n", 
		rngESHealth2() == ERR_OK ? '+' : '-');
	printf("\\warning health is volatile\n");
	return ERR_OK;
}

/*
*******************************************************************************
Чтение данных

es read <source> <count> <file>
*******************************************************************************
*/

static err_t rngReadSourceEx(size_t* read, void* buf, size_t count,
	const char* source_name, size_t par)
{
	if (strEq(source_name, "trng") || strEq(source_name, "trng2") ||
		strEq(source_name, "sys") ||
		strEq(source_name, "timer") && par == 0)
		return rngESRead(read, buf, count, source_name);
	// эксперименты с источником timer
	{
		register tm_ticks_t ticks;
		register tm_ticks_t t;
		register word w;
		size_t i, j, reps;
		// pre
		ASSERT(memIsValid(read, sizeof(size_t)));
		ASSERT(memIsValid(buf, count));
		// генерация
		for (i = 0; i < count; ++i)
		{
			((octet*)buf)[i] = 0;
			ticks = tmTicks();
			for (j = 0; j < 8; ++j)
			{
				w = 0;
				for (reps = 0; reps < par; ++reps)
				{
					mtSleep(0);
					t = tmTicks();
					w ^= (word)(t - ticks);
					ticks = t;
				}
				((octet*)buf)[i] ^= wordParity(w) << j;
			}
		}
		ticks = t = 0, w = 0;
		*read = count;
		return ERR_OK;
	}
	return ERR_OK;
}

static err_t esRead(int argc, char *argv[])
{
	err_t code;
	char source[6];
	size_t par = 0;
	size_t count;
	file_t file;
	octet buf[2048];
	// разбор командной строки: число параметров
	if (argc != 3)
		return ERR_CMD_PARAMS;
	// разбор командной строки: источник энтропии
	if (strEq(argv[0], "trng"))
		strCopy(source, "trng");
	else if (strEq(argv[0], "trng2"))
		strCopy(source, "trng2");
	else if (strEq(argv[0], "sys"))
		strCopy(source, "sys");
	else if (strEq(argv[0], "timer"))
		strCopy(source, "timer");
	else if (strStartsWith(argv[0], "timer"))
	{
		strCopy(source, "timer");
		argv[0]	+= strLen("timer");
		if (!decIsValid(argv[0]) || !strLen(argv[0]) || 
			strLen(argv[0]) > 3 || decCLZ(argv[0]))
			return ERR_CMD_PARAMS;
		par = (size_t)decToU32(argv[0]);
	}
	else
		return ERR_CMD_PARAMS;
	// разбор командной строки: число Кбайтов
	if (!decIsValid(argv[1]) || !strLen(argv[1]) || 
		strLen(argv[1]) > 4 || decCLZ(argv[1]))
		return ERR_CMD_PARAMS;
	count = (size_t)decToU32(argv[1]);
	if (((count << 10) >> 10) != count)
		return ERR_OUTOFRANGE;
	count <<= 10;
	// разбор командной строки: имя выходного файла
	code = cmdFileValNotExist(1, argv + 2);
	ERR_CALL_CHECK(code);
	code = cmdFileOpen(file, argv[2], "wb");
	ERR_CALL_CHECK(code);
	// выгрузка данных
	while (count)
	{
		size_t read;
		// читать
		code = rngReadSourceEx(&read, buf,
			MIN2(sizeof(buf), count), source, par);
		ERR_CALL_HANDLE(code, cmdFileClose(file));
		if (read != MIN2(sizeof(buf), count))
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, cmdFileClose(file));
		// писать
		if (fileWrite2(file, buf, read) != read)
			code = ERR_FILE_WRITE;
		ERR_CALL_HANDLE(code, cmdFileClose(file));
		count -= read;
	}
	// завершение
	return cmdFileClose2(file);
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int esMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return esUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "print"))
		code = esPrint(argc - 1, argv + 1);
	else if (strEq(argv[0], "read"))
		code = esRead(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK)
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return (int)code;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t esInit()
{
	return cmdReg(_name, _descr, esMain);
}
