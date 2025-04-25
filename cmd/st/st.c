/*
*******************************************************************************
\file st.c
\brief Self-testing
\project bee2/cmd
\created 2025.04.09
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include "../cmd.h"

/*
*******************************************************************************
Утилита st

Функционал:
- тестирование релизаций криптографических алгоритмов;
- тестирование генератора случайных чисел;
- проверка штампов;
- вычисление контрольных сумм.

Пример:
  bee2cmd st alg
  bee2cmd st rng
  bee2cmd st stamp
  bee2cmd st crc
  bee2cmd st crc 12121212
*******************************************************************************
*/

static const char _name[] = "st";
static const char _descr[] = "self-testing";

static int stUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  st alg\n"
		"    test cryptographic algorithms\n"
		"  st rng\n"
		"    test random number generator\n"
		"  st stamp\n"
		"    validate attached stamp\n"
		"  st crc\n"
		"    print checksum\n"
		"  st crc <prefix>\n"
		"    print checksum calculated using <prefix>\n"
		,
		_name, _descr
	);
	return -1;
}


/*
*******************************************************************************
Тестирование алгоритмов

st alg
*******************************************************************************
*/

static err_t stAlg(int argc, char* argv[])
{
	if (argc != 0)
		return ERR_CMD_PARAMS;
	return cmdStDo(CMD_ST_ALGS);
}

/*
*******************************************************************************
Тестирование ГСЧ

st rng
*******************************************************************************
*/

static err_t stRng(int argc, char* argv[])
{
	err_t code;
	// контроль числа параметров
	if (argc != 0)
		return ERR_CMD_PARAMS;
	// самотестирование
	code = cmdStDo(CMD_ST_BRNG);
	ERR_CALL_CHECK(code);
	// тестирование ГСЧ
	return cmdRngStart(TRUE);
}

/*
*******************************************************************************
Проверка штампа

st stamp
*******************************************************************************
*/

static err_t stStamp(int argc, char* argv[])
{
	err_t code;
	// контроль числа параметров
	if (argc != 0)
		return ERR_CMD_PARAMS;
	// самотестирование
	code = cmdStDo(CMD_ST_BASH);
	ERR_CALL_CHECK(code);
	// проверить штамп
	return cmdStDo(CMD_ST_STAMP);
}

/*
*******************************************************************************
Контрольная сумма

st crc
st crc <prefix>
*******************************************************************************
*/

static err_t stCrc(int argc, char* argv[])
{
	err_t code;
	octet crc[32];
	char str[65];
	// контроль числа параметров
	if (argc > 1)
		return ERR_CMD_PARAMS;
	// самотестирование
	code = cmdStDo(CMD_ST_BELT);
	ERR_CALL_CHECK(code);
	// вычислить контрольную сумму
	code = cmdStCrc(crc, argc == 0 ? 0 : argv[0]);
	ERR_CALL_CHECK(code);
	// печатать контрольную сумму
	hexFrom(str, crc, 32);
	hexLower(str);
	if (printf("%s\n", str) < 0)
		code = ERR_SYS;
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int stMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return stUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "alg"))
		code = stAlg(argc - 1, argv + 1);
	else if (strEq(argv[0], "rng"))
		code = stRng(argc - 1, argv + 1);
	else if (strEq(argv[0], "stamp"))
		code = stStamp(argc - 1, argv + 1);
	else if (strEq(argv[0], "crc"))
		code = stCrc(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "alg") || strEq(argv[0], "stamp"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t stInit()
{
	return cmdReg(_name, _descr, stMain);
}
