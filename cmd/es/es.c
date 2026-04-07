/*
*******************************************************************************
\file es.c
\brief Dealing with entropy sources
\project bee2/cmd 
\created 2021.04.20
\version 2026.04.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <math.h>
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
#include "bee2/cmd.h"

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
  bee2cmd es test file
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
		"    <source> in {trng, trng2, sys, sys2, timer, timerNNN, jitter}\n"
		"      timerNNN -- use NNN sleep delays to produce one output bit\n"
		"  es test <file>\n"
		"    statistical testing of <file> (experimental)\n"
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
	const char* sources[] = {
		"trng", "trng2", "sys", "sys2", "timer", "jitter" };
	size_t pos;
	size_t count;
	// проверить параметры
	if (argc != 0)
		return ERR_CMD_PARAMS;
	// опрос источников
	printf("Sources:");
	for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
	{
		size_t read;
		octet o;
		if (rngESRead(&read, &o, 1, sources[pos]) == ERR_OK)
		{
			printf(" %s%c", sources[pos],
				rngESTest(sources[pos]) == ERR_OK ? '+' : '-');
			++count;
		}
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
		strEq(source_name, "timer") && par == 0 ||
		strEq(source_name, "jitter"))
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
		CLEAN3(ticks, t, w);
		*read = count;
		return ERR_OK;
	}
	return ERR_OK;
}

static size_t decToSize(const char* dec)
{
	register size_t num;
	ASSERT(decIsValid(dec));
	for (num = 0; *dec; ++dec)
	{
		register size_t digit;
		if (num > SIZE_MAX / 10)
			return SIZE_MAX;
		num *= 10;
		digit = (size_t)(*dec - '0');
		if (num + digit < num)
			return SIZE_MAX;
		num += digit;
	}
	return num;
}

static err_t esRead(int argc, char *argv[])
{
	err_t code;
	char source[7];
	size_t par = 0;
	size_t count;
	file_t file;
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
	else if (strEq(argv[0], "jitter"))
		strCopy(source, "jitter");
	else if (strStartsWith(argv[0], "timer"))
	{
		strCopy(source, "timer");
		argv[0]	+= strLen("timer");
		if (!decIsValid(argv[0]) || !strLen(argv[0]) || 
			strLen(argv[0]) > 3 || decCLZ(argv[0]))
			return ERR_CMD_PARAMS;
		par = decToSize(argv[0]);
		ASSERT(par > 0 && par != SIZE_MAX);
	}
	else
		return ERR_CMD_PARAMS;
	// разбор командной строки: число Кбайтов
	if (!decIsValid(argv[1]) || !strLen(argv[1]) || decCLZ(argv[1]))
		return ERR_CMD_PARAMS;
	count = decToSize(argv[1]);
	if (count == SIZE_MAX)
		return ERR_OUTOFRANGE;
	// разбор командной строки: имя выходного файла
	code = cmdFileValNotExist(1, argv + 2);
	ERR_CALL_CHECK(code);
	code = cmdFileOpen(file, argv[2], "wb");
	ERR_CALL_CHECK(code);
	// выгрузка данных
	while (count--)
	{
		octet buf[1024];
		size_t read;
		// читать
		code = rngReadSourceEx(&read, buf, 1024, source, par);
		ERR_CALL_HANDLE(code, cmdFileClose(file));
		if (read != 1024)
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, cmdFileClose(file));
		// писать
		if (fileWrite2(file, buf, read) != read)
			code = ERR_FILE_WRITE;
		ERR_CALL_HANDLE(code, cmdFileClose(file));
	}
	// завершение
	return cmdFileClose2(file);
}

/*
*******************************************************************************
Статистическое тестирование

es test <file>
*******************************************************************************
*/

extern size_t rngWhtEnc(i32* wh, const octet* buf, size_t count);
extern u32 rngWhtMax(const i32* wh, size_t count);

static err_t esTest(int argc, char *argv[])
{
	err_t code;
	size_t size;
	size_t count;
	size_t log_count;
	void* state;
	i32* wh;			/* [count * 8] */
	file_t file;
	u32 max;
	double ratio;
	// разбор командной строки: число параметров
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// разбор командной строки: имя входного файла
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// размер файла
	size = cmdFileSize(argv[0]);
	if (size == 0)
		return ERR_FILE_SIZE;
	count = 1, log_count = 0;
	while (count <= size / 2 && count < SIZE_MAX / 8 / 4 / 2)
		count *= 2, ++log_count;
	// выделить и разметить память
	code = cmdBlobCreate2(state,
		count * 8 * 4,
		SIZE_MAX,
		&wh);
	ERR_CALL_CHECK(code);
	// прочитать данные
	code = cmdFileOpen(file, argv[0], "rb");
	ERR_CALL_HANDLE(code, blobClose(state));
	for (size = 0; size < count;)
	{
		octet buf[1024];
		size_t read;
		// прочитать фрагмент данных
		code = fileRead(&read, buf, MIN2(sizeof(buf), count - size), file);
		if (code != ERR_OK)
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, cmdBlobClose(state));
		// кодировать фрагмент
		rngWhtEnc(wh + size * 8, buf, read);
		// к следующему фрагменту
		size += read;
	}
	fileClose(file);
	// статистическое тестирование
	count *= 8, log_count += 3;
	max = rngWhtMax(wh, count);
	ratio = (double)count, ratio = max / sqrt(2 * ratio * log(ratio));
	printf(
		"file = \"%s\" (2^%u bits)\n"
		"max_wht = %lu (%f)\n",
		argv[0], (unsigned)log_count, (unsigned long)max, ratio);
	// завершение
	cmdBlobClose(state);
	return ERR_OK;
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
	else if (strEq(argv[0], "test"))
		code = esTest(argc - 1, argv + 1);
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
