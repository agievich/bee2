/*
*******************************************************************************
\file fmt.c
\brief Format-preserving encryption
\project bee2/cmd 
\created 2025.06.12
\version 2025.09.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/dec.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Утилита fmt

Функционал:
- шифрование с сохранением формата;
- секретные итераторы по строкам формата.

Пример:
  bee2cmd fmt enc -b10 -pass pass:zed 123456
  bee2cmd fmt next -b10 -pass pass:zed 123456
*******************************************************************************
*/

static const char _name[] = "fmt";
static const char _descr[] = "format-preserving encryption";

static int fmtUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  fmt enc -b<nnn> -pass <schema> <str>\n"
		"    encrypt <str>\n"
		"  fmt dec -b<nnn> -pass <schema> <str>\n"
		"    decrypt <str>\n"
		"  fmt next -b<nnn> -pass <schema> <str>\n"
		"    next to <str>\n"
		"  fmt prev -b<nnn> -pass <schema> <str>\n"
		"    prev to <str>\n"
		"  options:\n"
		"    -b<nnn> -- format of <str>:\n"
		"       -b10 -- decimal\n"
		"    -pass <schema> -- password for operation\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

static bool_t fmtBaseIsValid(size_t base)
{
	return base == 10;
}

static bool_t fmtStrIsValid(const char* str, size_t base)
{
	ASSERT(fmtBaseIsValid(base));
	return decIsValid(str);
}

static err_t fmtStrEnc(char* str, size_t base, const cmd_pwd_t pwd)
{
	return ERR_NOT_IMPLEMENTED;
}

static err_t fmtStrPrint(const char* str)
{
	(void)printf("%s\n", str);	
	return ERR_OK;
}

/*
*******************************************************************************
Зашифрование

fmt enc -b<nnn> -pass <schema> <str>
*******************************************************************************
*/

static err_t fmtEnc(int argc, char* argv[])
{
	err_t code = ERR_OK;
	size_t base = 0;
	cmd_pwd_t pwd = 0;
	void* state = 0;
	char* str;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT | CMD_ST_BRNG);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strStartsWith(*argv, "-b"))
		{
			char* str = *argv + strLen("-b");
			if (base)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) > 5 ||
				!fmtBaseIsValid(base = (size_t)decToU32(str)))
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			++argv, --argc;
		}
		else if (strEq(*argv, "-pass"))
		{
			if (pwd)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			++argv, --argc;
			if (!argc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			code = cmdPwdRead(&pwd, *argv);
			if (code != ERR_OK)
				break;
			ASSERT(cmdPwdIsValid(pwd));
			++argv, --argc;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	if (code == ERR_OK && (!pwd || argc != 1))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить формат
	if (!fmtStrIsValid(argv[0], base))	
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// выделить и разметить память
	code = cmdBlobCreate2(state, 
		strLen(argv[0]) + 1,
		SIZE_MAX,
		&str);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	strCopy(str, argv[0]);
	// зашифровать
	code = fmtStrEnc(str, base, pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// напечатать
	code = fmtStrPrint(str);
	// завершить
	cmdBlobClose(state);
	return code;
}

/*
*******************************************************************************
Расшифрование

fmt dec -b<nnn> -pass <schema> <str>
*******************************************************************************
*/

static err_t fmtDec(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Следующая строка

fmt next -b<nnn> -pass <schema> <str>
*******************************************************************************
*/

static err_t fmtNext(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Предыдущая строка

fmt prev -b<nnn> -pass <schema> <str>
*******************************************************************************
*/

static err_t fmtPrev(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int fmtMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc != 5)
		return fmtUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "enc"))
		code = fmtEnc(argc - 1, argv + 1);
	else if (strEq(argv[0], "dec"))
		code = fmtDec(argc - 1, argv + 1);
	else if (strEq(argv[0], "next"))
		code = fmtNext(argc - 1, argv + 1);
	else if (strEq(argv[0], "prev"))
		code = fmtPrev(argc - 1, argv + 1);
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

err_t fmtInit()
{
	return cmdReg(_name, _descr, fmtMain);
}
