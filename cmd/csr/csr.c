/*
*******************************************************************************
\file csr.c
\brief Manage certificate signing requests
\project bee2/cmd 
\created 2023.12.19
\version 2024.01.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bpki.h>
#include <stdio.h>

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
Самотестирование
*******************************************************************************
*/

static err_t csrSelfTest()
{
	octet state[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet hash[32];
	const octet oid[] = {
		0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
	};
	octet sig[48];
	// bign-genkeypair
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	ASSERT(sizeof(state) >= prngEcho_keep());
	prngEchoStart(state, privkey, 32);
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignKeypairGen(privkey, pubkey, params, prngEchoStepR,
			state) != ERR_OK ||
		!hexEq(pubkey,
			"BD1A5650179D79E03FCEE49D4C2BD5DD"
			"F54CE46D0CF11E4FF87BF7A890857FD0"
			"7AC6A60361E8C8173491686D461B2826"
			"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
	// bign-valpubkey
	if (bignPubkeyVal(params, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	// bign-sign
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return ERR_SELFTEST;
	if (bignSign2(sig, params, oid, sizeof(oid), hash, privkey,
		0, 0) != ERR_OK)
		return ERR_SELFTEST;
	if (!hexEq(sig,
		"19D32B7E01E25BAE4A70EB6BCA42602C"
		"CA6A13944451BCC5D4C54CFD8737619C"
		"328B8A58FB9C68FD17D569F7D06495FB"))
		return ERR_SELFTEST;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	sig[0] ^= 1;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) == ERR_OK)
		return ERR_SELFTEST;
	// все нормально
	return ERR_OK;
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
	code = csrSelfTest();
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
				code = ERR_BAD_PARAMS;
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
	code = csrSelfTest();
	ERR_CALL_CHECK(code);
	// разбор опций
	if (argc != 1)
		code = ERR_CMD_PARAMS;
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
	ERR_CALL_CHECK(code);
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

int csrMain(int argc, char* argv[])
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
