/*
*******************************************************************************
\file csr.c
\brief Manage certificate signing requests
\project bee2/cmd 
\created 2023.12.19
\version 2025.05.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bpki.h>
#include "../cmd.h"

/*
*******************************************************************************
Утилита csr

Функционал:
- перевыпуск запроса на выпуск сертификата с новой парой ключей;
- проверка запроса на выпуск сертификата.

Пример:
  bee2cmd csr rewrap -pass pass:"1?23&aaA..." privkey req req
  bee2cmd csr val req
*******************************************************************************
*/

static const char _name[] = "csr";
static const char _descr[] = "manage certificate signing requests";

static int csrUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  csr rewrap -pass <schema> <privkey> <csr> <csr1>\n"
		"    rewrap <csr> using <privkey> and store the result in <csr1>\n"
		"  csr val <csr>\n"
		"    validate <csr>\n"
		"  options:\n"
		"    -pass <schema> -- password description\n"
		"\\warning implemented only with bign-curve256v1\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Перевыпуск запроса на выпуск сертификата

rewrap -pass <schema> <privkey> <csr> <csr1>
*******************************************************************************
*/

static err_t csrRewrap(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	size_t privkey_len = 0;
	size_t csr_len;
	void* stack;
	octet* privkey;
	octet* csr;
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
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
	if (code == ERR_OK && (!pwd || argc != 3))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить входные файлы
	code = cmdFileValExist(2, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить выходной файл
	code = cmdFileValNotExist(1, argv + 2);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину личного ключа
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину запроса
	code = cmdFileReadAll(0, &csr_len, argv[1]);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, privkey_len + csr_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	privkey = (octet*)stack;
	csr = privkey + privkey_len;
	// определить личный ключ
	code = cmdPrivkeyRead(privkey, &privkey_len, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать запрос
	code = cmdFileReadAll(csr, &csr_len, argv[1]);
	ERR_CALL_CHECK(code);
	// перевыпустить запрос
	code = bpkiCSRRewrap(csr, csr_len, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// сохранить запрос
	code = cmdFileWrite(argv[2], csr, csr_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка запроса

val <csr>
*******************************************************************************
*/

static err_t csrVal(int argc, char* argv[])
{
	err_t code = ERR_OK;
	size_t csr_len;
	void* stack;
	octet* csr;
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// разбор опций
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// проверить входной файл
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить длину запроса
	code = cmdFileReadAll(0, &csr_len, argv[0]);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, csr_len);
	ERR_CALL_CHECK(code);
	csr = stack;
	// прочитать запрос
	code = cmdFileReadAll(csr, &csr_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить запрос
	code = bpkiCSRUnwrap(0, 0, csr, csr_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int csrMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return csrUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "rewrap"))
		code = csrRewrap(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = csrVal(argc - 1, argv + 1);
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

err_t csrInit()
{
	return cmdReg(_name, _descr, csrMain);
}
