/*
*******************************************************************************
\file sig.c
\brief Sign files and verify signatures
\project bee2/cmd
\created 2022.08.01
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
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита sig

Функционал:
- выработка ЭЦП;
- проверка ЭЦП;
- печать ЭЦП.

Пример (после примера в cvc.c):
  # внешняя подпись
  bee2cmd sig sign -certs "cert0 cert1 cert2" -pass pass:alice privkey2 \
    cert0 sig_file
  bee2cmd sig val -anchor cert0 cert0 sig_file
  bee2cmd sig val -pubkey pubkey2 cert0 sig_file
  bee2cmd sig print sig_file
  # встроенная подпись
  bee2cmd sig sign -certs "cert0 cert1 cert2" -date 230526 -pass pass:alice \
    privkey2 sig_file
  bee2cmd sig val -anchor cert0 sig_file
  bee2cmd sig val -pubkey pubkey2 sig_file
  bee2cmd sig print sig_file
  bee2cmd sig print -certc sig_file
  bee2cmd sig print -date sig_file
  # извлечение частей
  bee2cmd sig extr -body sig_file body
  bee2cmd sig extr -sig sig_file sig
  bee2cmd sig extr -body sig_file body
  bee2cmd sig extr -cert0 sig_file cert01
*******************************************************************************
*/

static const char _name[] = "sig";
static const char _descr[] = "sign files and verify signatures";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/

static int sigUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  sig sign [options] <privkey> <file>\n"
		"    sign <file> using <privkey> and attach signature\n"
		"  sig sign [options] <privkey> <file> <sig>\n"
		"    sign <file> using <privkey> and store signature in <sig>\n"
		"  sig val {-pubkey <pubkey>|-anchor <anchor>} <file>\n"
		"    verify signature attached to <file> using <pubkey> or <anchor>\n"
		"  sig val {-pubkey <pubkey>|-anchor <anchor>} <file> <sig>\n"
		"    verify <sig> of <file> using <pubkey> or <anchor>\n"
		"  sig extr {-cert<n>|-body|-sig} <sig> <obj_file>\n"
		"    extract object from <sig> and store it in <obj_file>\n"
		"      -cert<n> -- <n>th attached certificate\n"
		"        \\remark certificates are numbered from zero\n"
		"        \\remark signing certificate comes last\n"
		"      -body -- signed body\n"
		"      -sig -- signature itself\n"
		"  sig print [field] <sig>\n"
		"    print <sig> info: all fields or a specific field\n"
		"  .\n"
		"  <privkey>\n"
		"    container with private key\n"
		"  <pubkey>\n"
		"    file with public key\n"
		"  <anchor>\n"
		"    file with trusted certificate\n"
		"  options:\n"
		"    -certs <certs> -- certificate chain (optional)\n"
		"    -date <YYMMDD> -- date of signing (optional)\n"
		"    -pass <schema> -- password description\n"
		"  field:\n"
		"    {-certc|-date|-sig}\n"
		"      -certc -- number of attached certificates\n"
		"      -date -- date of signing\n"
		"      -sig -- base signature\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Выработка подписи

sig sign [options] <privkey> <file>
sig sign [options] <privkey> <file> <sig>

options:
  [-certs <certs>] [-date <YYMMDD>] -pass <schema>
*******************************************************************************
*/

static err_t sigSign(int argc, char* argv[])
{
	err_t code;
	const char* certs = 0;
	octet date[6];
	cmd_pwd_t pwd = 0;
	size_t privkey_len;
	octet* privkey;
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// без даты по умолчанию
	memSetZero(date, 6);
	// разобрать опции
	while (argc && strStartsWith(*argv, "-"))
	{
		if (argc < 2)
		{
			code = ERR_CMD_PARAMS;
			break;
		}
		if (strStartsWith(*argv, "-certs"))
		{
			if (certs)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			++argv, --argc;
			ASSERT(argc > 0);
			certs = *argv;
			++argv, --argc;
		}
		else if (strStartsWith(*argv, "-date"))
		{
			if (!memIsZero(date, 6))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			ASSERT(argc > 0);
			code = cmdDateParse(date, *argv);
			if (code != ERR_OK)
				break;
			--argc, ++argv;
		}
		else if (strStartsWith(*argv, "-pass"))
		{
			if (pwd)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			++argv, --argc;
			ASSERT(argc > 0);
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
	// входной контроль
	if (code == ERR_OK && (!pwd || argc < 2 || argc > 3))
		code = ERR_CMD_PARAMS;
	else if (argc == 3 && cmdFileAreSame(argv[1], argv[2]))
		code = ERR_FILE_SAME;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие <privkey> и <file>
	code = cmdFileValExist(2, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// получить разрешение на перезапись <sig>
	if (argc == 3)
	{
		code = cmdFileValNotExist(1, argv + 2);
		ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	}
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// подписать
	code = cmdSigSign(argc == 3 ? argv[2] : argv[1], argv[1], certs, date,
		privkey, privkey_len);
	// завершить
	cmdBlobClose(privkey);
	return code;
}

/*
*******************************************************************************
Проверка подписи

sig val {-pubkey <pubkey> | -anchor <anchor>} <file>
sig val {-pubkey <pubkey> | -anchor <anchor>} <file> <sig>
*******************************************************************************
*/

static err_t sigVal(int argc, char* argv[])
{
	err_t code;
	size_t count;
	octet* buf;
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// входной контроль
	if (argc < 3 || argc > 4 ||
		!strEq(argv[0], "-pubkey") && !strEq(argv[0], "-anchor"))
		return ERR_CMD_PARAMS;
	if (argc == 4 && cmdFileAreSame(argv[2], argv[3]))
		return ERR_FILE_SAME;
	// проверить наличие {<pubkey> | <anchor>} <file> <sig>
	code = cmdFileValExist(argc - 1, argv + 1);
	ERR_CALL_CHECK(code);
	// прочитать pubkey / anchor
	code = cmdFileReadAll(0, &count, argv[1]);
	ERR_CALL_CHECK(code);
	code = cmdBlobCreate(buf, count);
	ERR_CALL_CHECK(code);
	code = cmdFileReadAll(buf, &count, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// проверить подпись
	code = strEq(argv[0], "-pubkey") ?
		cmdSigVerify(argv[2], argc == 4 ? argv[3] : argv[2], buf, count) :
		cmdSigVerify2(argv[2], argc == 4 ? argv[3] : argv[2], buf, count);
	// завершить
	cmdBlobClose(buf);
	return code;
}

/*
*******************************************************************************
Извлечение из подписи объекта

sig extr {-cert<n>|-body|-sig} <sig> <obj_file>
*******************************************************************************
*/

static err_t sigExtr(int argc, char* argv[])
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
	code = cmdSigExtr(argv[1], argv[0], scope);
	// завершить
	return code;
}

/*
*******************************************************************************
 Печать подписи

 sig print [{-date|-certc|-cert<n>}] <sig>
*******************************************************************************
*/

static err_t sigPrint(int argc, char * argv[])
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
	// проверить наличие файла подписи
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// печатать подпись
	return cmdSigPrint(argv[0], scope);
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int sigMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return sigUsage();
	// разбор команды
	--argc, ++argv;
	if (strEq(argv[0], "sign"))
		code = sigSign(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))	
		code = sigVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "extr"))
		code = sigExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = sigPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "val"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
}

err_t sigInit()
{
	return cmdReg(_name, _descr, sigMain);
}
