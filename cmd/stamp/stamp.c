/*
*******************************************************************************
\file stamp.c
\brief Generate and validate file checksums
\project bee2/cmd
\created 2025.04.08
\version 2025.04.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита stamp

Функционал:
- добавление контрольных сумм к файлам;
- проверка файлов с контрольными суммами;
- удаление контрольных сумм.

Штамп либо присоединяется к файлу, либо сохранится в отдельном файле.

Пример:
  bee2cmd stamp gen file
  bee2cmd stamp val file
  bee2cmd stamp gen file stamp
  bee2cmd stamp val file stamp
*******************************************************************************
*/

static const char _name[] = "stamp";
static const char _descr[] = "file stamps";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/

static int stampUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  stamp gen <file>\n"
		"    generate stamp of <file> and attach it\n"
		"  stamp gen <file> <stamp>\n"
		"    generate stamp of <file> and store it in <stamp>\n"
		"  stamp val <file>\n"
		"    validate stamp attached to <file>\n"
		"  stamp val <file> <stamp>\n"
		"    validate stamp of <file> stored in <stamp>\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Добавление

stamp gen <file>
stamp gen <file> <stamp>
*******************************************************************************
*/

static err_t stampGen(int argc, char* argv[])
{
	err_t code;
	// входной контроль
	if (argc < 1 || argc > 2)
		return ERR_CMD_PARAMS;
	if (argc == 2 && cmdFileAreSame(argv[0], argv[1]))
		return ERR_FILE_SAME;
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	if (argc == 2)
	{
		code = cmdFileValNotExist(1, argv + 1);
		ERR_CALL_CHECK(code);
	}
	// самотестирование
	code = cmdStDo(CMD_ST_BASH);
	ERR_CALL_CHECK(code);
	// сгенерировать штамп
	code = cmdStampGen(argc == 1 ? argv[0] : argv[1], argv[0]);
	return code;
}

/*
*******************************************************************************
Проверка

stamp val <file>
stamp val <file> <stamp>
*******************************************************************************
*/

static err_t stampVal(int argc, char* argv[])
{
	err_t code;
	// входной контроль
	if (argc < 1 || argc > 2)
		return ERR_CMD_PARAMS;
	if (argc == 2 && cmdFileAreSame(argv[0], argv[1]))
		return ERR_FILE_SAME;
	// проверить наличие файлов
	code = cmdFileValExist(argc, argv);
	ERR_CALL_CHECK(code);
	// самотестирование
	code = cmdStDo(CMD_ST_BASH);
	// проверить штамп
	code = cmdStampVal(argv[0], argc == 1 ? argv[0] : argv[1]);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int stampMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return stampUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "gen"))
		code = stampGen(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = stampVal(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "val"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t stampInit()
{
	return cmdReg(_name, _descr, stampMain);
}
