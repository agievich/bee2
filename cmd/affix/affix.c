/*
*******************************************************************************
\file affix.c
\brief Managing file prefixes and suffixes
\project bee2/cmd
\created 2025.04.15
\version 2025.04.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/dec.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита affix

Функционал:
- добавление префиксов и суффиксов;
- печать информации о префиксах и суффиксах;
- управление префиксах и суффиксах;

Пример:
  bee2cmd affix prepend file prefix
  bee2cmd affix prepend file prefix
  bee2cmd affix prepend file prefix
  bee2cmd affix append file suffix
  bee2cmd affix append file suffix
  bee2cmd affix print file
  bee2cmd affix extr -p2 file p2
  bee2cmd affix extr -s1 file s1
  bee2cmd affix behead file
  bee2cmd affix drop file  
*******************************************************************************
*/

static const char _name[] = "affix";
static const char _descr[] = "file prefixes and suffixes";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/

static int affixUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  affix prepend <file> <prefix>\n"
		"    prepend <prefix> to <file>\n"
		"  affix append <file> <suffix>\n"
		"    append <suffix> to <file>\n"
		"  affix behead <file>\n"
		"    delete prefix of <file>\n"
		"  affix drop <file>\n"
		"    delete suffix of <file>\n"
		"  affix extr {-p<n>|-s<n>} <file> <affix>\n"
		"    extract object from <file> and store it in <affix>\n"
		"      -p<nnn> -- <n>th prefix\n"
		"      -s<nnn> -- <n>th suffix\n"
		"      \\remark p0 goes first, s0 goes last\n"
		"  affix print [field] <file>\n"
		"    print <file> info: full info or a specific field\n"
		"      full info: lengths and total number of prefixes / suffixes\n"
		"      field: {-pc|-sc}\n"
		"        -pc -- number of prefixes\n"
		"        -sc -- number of suffixes\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Добавление префикса

affix prepend <file> <prefix>
*******************************************************************************
*/

static err_t affixPrepend(int argc, char* argv[])
{
	err_t code;
	size_t count;
	void* prefix;
	// входной контроль
	if (argc != 2)
		return ERR_CMD_PARAMS;
	// проверить наличие файлов
	code = cmdFileValExist(2, argv);
	ERR_CALL_CHECK(code);
	// определить размер префикса
	code = cmdFilePrefixRead(0, &count, argv[1], 0);
	ERR_CALL_CHECK(code);
	if (count != cmdFileSize(argv[1]))
		return ERR_BAD_FORMAT;
	// прочитать префикс
	code = cmdBlobCreate(prefix, count);
	ERR_CALL_CHECK(code);
	code = cmdFilePrefixRead(prefix, &count, argv[1], 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(prefix));
	// записать префикс
	code = cmdFilePrepend(argv[0], prefix, count);
	// завершить
	cmdBlobClose(prefix);
	return code;
}

/*
*******************************************************************************
Добавление суффикса

affix append <file> <suffix>
*******************************************************************************
*/

static err_t affixAppend(int argc, char* argv[])
{
	err_t code;
	size_t count;
	void* suffix;
	// входной контроль
	if (argc != 2)
		return ERR_CMD_PARAMS;
	// проверить наличие файлов
	code = cmdFileValExist(2, argv);
	ERR_CALL_CHECK(code);
	// определить размер суффикса
	code = cmdFileSuffixRead(0, &count, argv[1], 0);
	ERR_CALL_CHECK(code);
	if (count != cmdFileSize(argv[1]))
		return ERR_BAD_FORMAT;
	// прочитать суффикс
	code = cmdBlobCreate(suffix, count);
	ERR_CALL_CHECK(code);
	code = cmdFileSuffixRead(suffix, &count, argv[1], 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(suffix));
	// записать суффикс
	code = cmdFileAppend(argv[0], suffix, count);
	// завершить
	cmdBlobClose(suffix);
	return code;
}

/*
*******************************************************************************
Удаление префикса

affix behead <file>
*******************************************************************************
*/

static err_t affixBehead(int argc, char* argv[])
{
	err_t code;
	size_t count;
	// входной контроль
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// проверить наличие файла
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить размер префикса
	code = cmdFilePrefixRead(0, &count, argv[0], 0);
	ERR_CALL_CHECK(code);
	// удалить префикс
	code = cmdFileBehead(argv[0], count);
	// завершить
	return code;
}

/*
*******************************************************************************
Удаление суффикса

affix drop <file>
*******************************************************************************
*/

static err_t affixDrop(int argc, char* argv[])
{
	err_t code;
	size_t count;
	// входной контроль
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// проверить наличие файла
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить размер суффикса
	code = cmdFileSuffixRead(0, &count, argv[0], 0);
	ERR_CALL_CHECK(code);
	// удалить суффикс
	code = cmdFileDrop(argv[0], count);
	// завершить
	return code;
}

/*
*******************************************************************************
Извлечение префикса или суффикса

affix extr {-p<n>|-s<n>} <file> <affix>
*******************************************************************************
*/

static err_t cmdAffixExtr(const char* affix_name, const char* name,
	const char* scope)
{
	err_t code;
	size_t offset;
	size_t count;
	size_t num;
	void* buf;
	// разобрать опции
	if (!strStartsWith(scope, "p") && !strStartsWith(scope, "s") ||
		!decIsValid(scope + 1) || strLen(scope + 1) - decCLZ(scope + 1) >= 10)
		return ERR_CMD_PARAMS;
	num = decToU32(scope + 1);
	// выделить префикс
	if (strStartsWith(scope, "p"))
	{
		for (offset = count = 0; num != SIZE_MAX; --num)
		{
			code = cmdFilePrefixRead(0, &count, name, offset += count);
			ERR_CALL_CHECK(code);
		}
		code = cmdBlobCreate(buf, count);
		ERR_CALL_CHECK(code);
		code = cmdFilePrefixRead(buf, &count, name, offset);
		ERR_CALL_HANDLE(code, cmdBlobClose(buf));
		code = cmdFileWrite(affix_name, buf, count);
		cmdBlobClose(buf);
	}
	// выделить суффикс
	else
	{
		for (offset = count = 0; num != SIZE_MAX; --num)
		{
			code = cmdFileSuffixRead(0, &count, name, offset += count);
			ERR_CALL_CHECK(code);
		}
		code = cmdBlobCreate(buf, count);
		ERR_CALL_CHECK(code);
		code = cmdFileSuffixRead(buf, &count, name, offset);
		ERR_CALL_HANDLE(code, cmdBlobClose(buf));
		code = cmdFileWrite(affix_name, buf, count);
		cmdBlobClose(buf);
	}
	return code;
}

static err_t affixExtr(int argc, char* argv[])
{
	err_t code;
	const char* scope;
	// обработать опции
	if (argc != 3)
		return ERR_CMD_PARAMS;
	scope = argv[0];
	if (strLen(scope) < 1 || scope[0] != '-')
		return ERR_CMD_PARAMS;
	++scope, --argc, ++argv;
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 1);
	ERR_CALL_CHECK(code);
	// извлечь объект
	code = cmdAffixExtr(argv[1], argv[0], scope);
	// завершить
	return code;
}

/*
*******************************************************************************
Печать

affix print [field] <file>
*******************************************************************************
*/

static err_t cmdAffixPrint(const char* name, const char* scope)
{
	size_t offset;
	size_t count;
	size_t pc;
	size_t sc;
	// полная информация
	if (scope == 0)
	{
		printf("prefixes\n");
		for (offset = pc = 0; 1; offset += count, ++pc)
		{
			if (cmdFilePrefixRead(0, &count, name, offset) != ERR_OK)
				break;
			printf(pc ? "+%u" : "  length: %u", (unsigned)count);
		}
		printf(pc ? "\n  count:  %u\n" : "  count:  %u\n", (unsigned)pc);
		printf("suffixes\n");
		for (offset = sc = 0; 1; offset += count, ++sc)
		{
			if (cmdFileSuffixRead(0, &count, name, offset) != ERR_OK)
				break;
			printf(sc ? "+%u" : "  length: %u", (unsigned)count);
		}
		printf(sc ? "\n  count:  %u\n" : "  count:  %u\n", (unsigned)sc);
		if (pc || sc)
			printf("\\warning false positives are possible\n");
	}
	// число префиксов
	else if (strEq(scope, "pc"))
	{
		for (offset = pc = 0; 1; offset += count, ++pc)
			if (cmdFilePrefixRead(0, &count, name, offset) != ERR_OK)
				break;
		printf("%u\n", (unsigned)pc);
	}
	// число суффиксов
	else if (strEq(scope, "sc"))
	{
		for (offset = sc = 0; 1; offset += count, ++sc)
			if (cmdFileSuffixRead(0, &count, name, offset) != ERR_OK)
				break;
		printf("%u\n", (unsigned)sc);
	}
	else
		return ERR_CMD_PARAMS;
	return ERR_OK;
}

static err_t affixPrint(int argc, char* argv[])
{
	err_t code;
	const char* scope = 0;
	// обработать опции
	if (argc < 1 || argc > 2)
		return ERR_CMD_PARAMS;
	if (argc == 2)
	{
		scope = argv[0];
		if (strLen(scope) < 1 || scope[0] != '-')
			return ERR_CMD_PARAMS;
		++scope, --argc, ++argv;
	}
	// проверить наличие файла
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// печатать
	return cmdAffixPrint(argv[0], scope);
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int affixMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return affixUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "prepend"))
		code = affixPrepend(argc - 1, argv + 1);
	else if (strEq(argv[0], "append"))
		code = affixAppend(argc - 1, argv + 1);
	else if (strEq(argv[0], "behead"))
		code = affixBehead(argc - 1, argv + 1);
	else if (strEq(argv[0], "drop"))
		code = affixDrop(argc - 1, argv + 1);
	else if (strEq(argv[0], "extr"))
		code = affixExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = affixPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK)
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t affixInit()
{
	return cmdReg(_name, _descr, affixMain);
}
