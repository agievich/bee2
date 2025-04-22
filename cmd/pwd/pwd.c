/*
*******************************************************************************
\file pwd.c
\brief Generate and manage passwords
\project bee2/cmd 
\created 2022.06.23
\version 2025.04.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/dec.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита pwd

Функционал:
- построение пароля по заданной схеме;
- проверочное определение ранее построенного пароля;
- печать ранее построенного пароля.

Допустимые схемы построения паролей определены в модуле cmd.h при описании 
функций cmdPwdGen(), cmdPwdRead().

Пример:
  bee2cmd pwd gen share:"-l256 -t3 -crc -pass pass:zed s1 s2 s3 s4 s5"
  bee2cmd pwd gen \
    share:"-l192 -pass share:\"-crc -pass pass:zed s1 s2 s3\" ss1 ss2 ss3"
  bee2cmd pwd val share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1"
  bee2cmd pwd print share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1"
*******************************************************************************
*/

static const char _name[] = "pwd";
static const char _descr[] = "generate and manage passwords";

static int pwdUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  pwd gen <schema>\n"
		"    generate a password according to <schema>\n"
		"  pwd val <schema>\n"
		"    validate a password built by <schema>\n"
		"  pwd print <schema>\n"
		"    print a password built by <schema>\n"
		"  schemas:\n"
		"    pass:<pwd> -- direct password\n"
		"    env:<name> -- password in environment variable <name>\n"
		"    share:\"[options] <share1> <share2> ...\" -- shared password\n"
		"      options:\n"
		"        -t<nn> --- threshold (2 <= <nn> <= 16, 2 by default)\n"
		"        -l<mmm> --- password bitlen: 128, 192 or 256 (by default)\n"
		"        -crc --- the password contains 64-bit crc (<mmm> != 128)\n"
		"        -pass <schema> --- password to protect shares\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Генерация пароля

pwd gen <schema>
*******************************************************************************
*/

static err_t pwdGen(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// верное число параметров?
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT | CMD_ST_BRNG);
	ERR_CALL_CHECK(code);
	// генерировать пароль
	code = cmdPwdGen(&pwd, *argv);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Проверка пароля

pwd val <schema>
*******************************************************************************
*/

static err_t pwdVal(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// верное число параметров?
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT);
	ERR_CALL_CHECK(code);
	// определить пароль (с одновременной проверкой)
	code = cmdPwdRead(&pwd, *argv);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Печать пароля

pwd print <schema>
*******************************************************************************
*/

static err_t pwdPrint(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// верное число параметров?
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// определить пароль
	code = cmdPwdRead(&pwd, *argv);
	ERR_CALL_CHECK(code);
	// печатать пароль
	printf("%s\n", pwd);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int pwdMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 3)
		return pwdUsage();
	// разбор
	++argv, --argc;
	if (strEq(argv[0], "gen"))
		code = pwdGen(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = pwdVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = pwdPrint(argc - 1, argv + 1);
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

err_t pwdInit()
{
	return cmdReg(_name, _descr, pwdMain);
}
