/*
*******************************************************************************
\file kg.c
\brief Generate and manage private keys
\project bee2/cmd 
\created 2022.06.08
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
#include <bee2/crypto/bign96.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита kg

Функционал:
- генерация личного ключа bign с сохранением в контейнер СТБ 34.101.78;
- проверочное чтение личного ключа из контейнера с печатью открытого ключа;
- смена пароля защиты контейнера.

Пример:
  bee2cmd pwd gen share:"-l256 -t3 -pass pass:zed s1 s2 s3 s4 s5"
  bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" privkey
  bee2cmd kg val -pass share:"-pass pass:zed s1 s2 s4" privkey
  bee2cmd kg chp -passin share:"-pass pass:zed s3 s1 s4" \
    -passout pass:"1?23&aaA..." privkey
  bee2cmd kg extr -pass pass:"1?23&aaA..." privkey pubkey
  bee2cmd kg print -pass pass:"1?23&aaA..." privkey
*******************************************************************************
*/

static const char _name[] = "kg";
static const char _descr[] = "generate and manage private keys";

static int kgUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  kg gen [-l<nnn>] -pass <schema> <privkey>\n"
		"    generate a private key and store it in <privkey>\n"
		"  kg chp -passin <schema> -passout <schema> <privkey>\n"
		"    change the password used to protect <privkey>\n"
		"  kg val -pass <schema> <privkey>\n"
		"    validate <privkey>\n"
		"  kg extr -pass <schema> <privkey> <pubkey>\n"
		"    calculate and extract <pubkey> from <privkey>\n"
		"  kg print -pass <schema> <privkey>\n"
		"    validate <privkey> and print the corresponding public key\n"
		"  options:\n"
		"    -l<nnn> -- security level: 96, 128 (by default), 192 or 256\n"
		"    -pass <schema> -- password description\n"
		"    -passin <schema> -- input password description\n"
		"    -passout <schema> -- output password description\n"
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

static err_t kgParamsStd(bign_params* params, size_t privkey_len)
{
	switch (privkey_len)
	{
	case 24:
		return bign96ParamsStd(params, "1.2.112.0.2.0.34.101.45.3.0");
	case 32:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1");
	case 48:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2");
	case 64:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.3");
	}
	return ERR_BAD_INPUT;
}

/*
*******************************************************************************
Генерация ключа

gen [-lnnn] -pass <schema> <privkey>
*******************************************************************************
*/

static err_t kgGen(int argc, char* argv[])
{
	err_t code = ERR_OK;
	size_t len = 0;
	cmd_pwd_t pwd = 0;
	bign_params params[1];
	void* stack = 0;
	octet* privkey;
	octet* pubkey;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT | CMD_ST_BIGN | CMD_ST_BRNG);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strStartsWith(*argv, "-l"))
		{
			char* str = *argv + strLen("-l");
			if (len)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) > 3 ||
				(len = (size_t)decToU32(str)) != 96 && len != 128 && 
					len != 192 && len != 256)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			len /= 4, ++argv, --argc;
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
	// проверить файл-контейнер
	code = cmdFileValNotExist(1, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// загрузить параметры
	if (len == 0)
		len = 32;
	code = kgParamsStd(params, len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// запустить ГСЧ
	code = cmdRngStart(TRUE);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// выделить память
	code = cmdBlobCreate(stack, 3 * len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// генерировать ключ
	privkey = (octet*)stack;
	pubkey = privkey + len;
	code = len == 24 ? bign96KeypairGen(privkey, pubkey, params, rngStepR, 0) :
		bignKeypairGen(privkey, pubkey, params, rngStepR, 0);
	ERR_CALL_HANDLE(code, (cmdBlobClose(stack), cmdPwdClose(pwd)));
	// обновить ключ ГСЧ
	rngRekey();
	// сохранить ключ
	code = cmdPrivkeyWrite(privkey, len, argv[0], pwd);
	cmdBlobClose(stack);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Смена пароля защиты

chp -passin <schema> -passout <schema> <privkey>
*******************************************************************************
*/

static err_t kgChp(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwdin = 0;
	cmd_pwd_t pwdout = 0;
	size_t len = 0;
	octet* privkey;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strEq(*argv, "-passin"))
		{
			if (pwdin)
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
			code = cmdPwdRead(&pwdin, *argv);
			if (code != ERR_OK)
				break;
			ASSERT(cmdPwdIsValid(pwdin));
			++argv, --argc;
		}
		else if (strEq(*argv, "-passout"))
		{
			if (pwdout)
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
			code = cmdPwdRead(&pwdout, *argv);
			if (code != ERR_OK)
				break;
			ASSERT(cmdPwdIsValid(pwdout));
			++argv, --argc;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	if (code == ERR_OK && (!pwdin || !pwdout || argc != 1))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, (cmdPwdClose(pwdout), cmdPwdClose(pwdin)));
	// проверить файл-контейнер
	code = cmdFileValExist(1, argv);
	ERR_CALL_HANDLE(code, (cmdPwdClose(pwdout), cmdPwdClose(pwdin)));
	// определить длину личного ключа
	code = cmdPrivkeyRead(0, &len, argv[0], pwdin);
	ERR_CALL_HANDLE(code, (cmdPwdClose(pwdout), cmdPwdClose(pwdin)));
	// выделить память
	code = cmdBlobCreate(privkey, len);
	ERR_CALL_HANDLE(code, (cmdPwdClose(pwdout), cmdPwdClose(pwdin)));
	// читать личный ключ
	code = cmdPrivkeyRead(privkey, &len, argv[0], pwdin);
	cmdPwdClose(pwdin);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkey), cmdPwdClose(pwdout)));
	// сохранить личный ключ
	code = cmdPrivkeyWrite(privkey, len, argv[0], pwdout);
	cmdBlobClose(privkey);
	cmdPwdClose(pwdout);
	return code;
}

/*
*******************************************************************************
Проверка ключа

val -pass <schema> <privkey>
*******************************************************************************
*/

static err_t kgVal(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	size_t len = 0;
	octet* privkey;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strEq(*argv, "-pass"))
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
	// проверить файл-контейнер
	code = cmdFileValExist(1, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину личного ключа
	code = cmdPrivkeyRead(0, &len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// выделить память
	code = cmdBlobCreate(privkey, len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить личный ключ
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdBlobClose(privkey);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Извлечение открытого ключа

extr -pass <schema> <privkey> <pubkey>
*******************************************************************************
*/

static err_t kgExtr(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	bign_params params[1];
	void* stack;
	size_t len = 0;
	octet* privkey;
	octet* pubkey;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT | CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strEq(*argv, "-pass"))
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
	if (code == ERR_OK && (!pwd || argc != 2))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить файл-контейнер
	code = cmdFileValExist(1, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить выходной файл
	code = cmdFileValNotExist(1, argv + 1);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину личного ключа
	code = cmdPrivkeyRead(0, &len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, len + 2 * len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	privkey = (octet*)stack;
	pubkey = privkey + len;
	// определить личный ключ
	code = cmdPrivkeyRead(privkey, &len, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить открытый ключ
	code = kgParamsStd(params, len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = len == 24 ? bign96PubkeyCalc(pubkey, params, privkey) : 
		bignPubkeyCalc(pubkey, params, privkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// записать открытый ключ
	code = cmdFileWrite(argv[1], pubkey, len * 2);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Печать

print -pass <schema> <privkey>
*******************************************************************************
*/

static err_t kgPrint(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	bign_params params[1];
	void* stack;
	size_t len = 0;
	octet* privkey;
	octet* pubkey;
	char* hex;
	// самотестирование
	code = cmdStDo(CMD_ST_BELS | CMD_ST_BELT);
	ERR_CALL_CHECK(code);
	// разбор опций
	while (argc && strStartsWith(*argv, "-"))
	{
		if (strEq(*argv, "-pass"))
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
	// проверить файл-контейнер
	code = cmdFileValExist(1, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину личного ключа
	code = cmdPrivkeyRead(0, &len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, len + 2 * len + 4 * len + 1);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	privkey = (octet*)stack;
	pubkey = privkey + len;
	hex = (char*)(pubkey + 2 * len);
	// определить личный ключ
	code = cmdPrivkeyRead(privkey, &len, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить открытый ключ
	code = kgParamsStd(params, len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = len == 24 ? bign96PubkeyCalc(pubkey, params, privkey) :
		bignPubkeyCalc(pubkey, params, privkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// печатать открытый ключ
	hexFrom(hex, pubkey, len * 2);
	printf("%s\n", hex);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int kgMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 4)
		return kgUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "gen"))
		code = kgGen(argc - 1, argv + 1);
	else if (strEq(argv[0], "chp"))
		code = kgChp(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = kgVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "extr"))
		code = kgExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = kgPrint(argc - 1, argv + 1);
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

err_t kgInit()
{
	return cmdReg(_name, _descr, kgMain);
}
