/*
*******************************************************************************
\file kg.c
\brief Generate and manage private keys
\project bee2/cmd 
\created 2022.06.08
\version 2022.10.27
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
Утилита kg

Функционал:
- генерация личного ключа bign с сохранением в контейнер СТБ 34.101.78;
- проверочное чтение личного ключа из контейнера с печатью открытого 
  ключа;
- смена пароля защиты контейнера.

Пример:
  bee2cmd pwd gen share:"-l256 -t3 -pass pass:zed s1 s2 s3 s4 s5"
  bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" privkey
  bee2cmd kg val -pass share:"-pass pass:zed s1 s2 s4" privkey
  bee2cmd kg chp -passin share:"-pass pass:zed s3 s1 s4"
    -passout pass:"1?23&aaA..." privkey
  bee2cmd kg pub -pass pass:"1?23&aaA..." privkey pubkey
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
		"  kg gen [-lnnn] -pass <scheme> <privkey>\n"
		"    generate a private key and store it in <privkey>\n"
		"  kg val -pass <scheme> <privkey>\n"
		"    validate <privkey>\n"
		"  kg pub -pass <scheme> <privkey> <pubkey>\n"
		"    calculate public key from <privkey> and store it in <pubkey>\n"
		"  kg print -pass <scheme> <privkey>\n"
		"    validate <privkey> and print the corresponding public key\n"
		"  kg chp -passin <scheme> -passout <scheme> <privkey>\n"
		"    change the password used to protect <privkey>\n"
		"  options:\n"
		"    -lnnn -- security level: -l128 (by default), -l192 or -l256\n"
		"    -pass <scheme> -- description of a password\n"
		"    -passin <scheme> -- description of an input password\n"
		"    -passout <scheme> -- description of an output password\n",
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

static err_t kgSelfTest()
{
	const char pwd[] = "B194BAC80A08F53B";
	octet stack[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet buf[5 * (32 + 1)];
	octet buf1[32];
	// bign-genkeypair
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	ASSERT(sizeof(stack) >= prngEcho_keep());
	prngEchoStart(stack, privkey, 32);
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignGenKeypair(privkey, pubkey, params, prngEchoStepR,
			stack) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
	// bels-share: разделение и сборка
	if (belsShare3(buf, 5, 3, 32, beltH()) != ERR_OK)
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 1, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 2, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 3, 32, buf) != ERR_OK ||
		!memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	// brng-ctr: тест Б.2
	ASSERT(sizeof(stack) >= brngCTR_keep());
	memCopy(buf, beltH(), 96);
	brngCTRStart(stack, beltH() + 128, beltH() + 128 + 64);
	brngCTRStepR(buf, 96, stack);
	if (!hexEq(buf,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269"
		"4C0E74B2CD5811AD21F23DE7E0FA742C"
		"3ED6EC483C461CE15C33A77AA308B7D2"
		"0F51D91347617C20BD4AB07AEF4F26A1"
		"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"))
		return ERR_SELFTEST;
	// pbkdf2 тест E.5
	beltPBKDF2(buf, (const octet*)"B194BAC80A08F53B", strLen(pwd), 10000,
		beltH() + 128 + 64, 8);
	if (!hexEq(buf,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return FALSE;
	// belt-kwp: тест A.21
	ASSERT(sizeof(stack) >= beltKWP_keep());
	beltKWPStart(stack, beltH() + 128, 32);
	memCopy(buf, beltH(), 32);
	memCopy(buf + 32, beltH() + 32, 16);
	beltKWPStepE(buf, 48, stack);
	if (!hexEq(buf,
		"49A38EE108D6C742E52B774F00A6EF98"
		"B106CBD13EA4FB0680323051BC04DF76"
		"E487B055C69BCF541176169F1DC9F6C8"))
		return FALSE;
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Генерация ключа

gen [-lnnn] -pass <scheme> <privkey>
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
	code = kgSelfTest();
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
			if (!decIsValid(str) || decCLZ(str) || strLen(str) != 3 ||
				(len = (size_t)decToU32(str)) % 64 || len < 128 || len > 256)
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
	if (len == 32)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1");
	else if (len == 48)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2");
	else
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");
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
	code = bignGenKeypair(privkey, pubkey, params, rngStepR, 0);
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
Проверка ключа

val -pass <scheme> <privkey>
*******************************************************************************
*/

static err_t kgVal(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	size_t len = 0;
	octet* privkey;
	// самотестирование
	code = kgSelfTest();
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
Экспорт открытого ключа

print -pass <scheme> <privkey>
*******************************************************************************
*/

static err_t kgPub(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	bign_params params[1];
	void* stack;
	size_t len = 0;
	octet* privkey;
	octet* pubkey;
	// самотестирование
	code = kgSelfTest();
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
	ERR_CALL_HANDLE(code, (cmdBlobClose(stack), cmdPwdClose(pwd)));
	// определить открытый ключ
	if (len == 32)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1");
	else if (len == 48)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2");
	else
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");
	if (code == ERR_OK)
		code = bignCalcPubkey(pubkey, params, privkey);
	ERR_CALL_HANDLE(code, (cmdBlobClose(stack), cmdPwdClose(pwd)));
	// записать открытый ключ
	code = cmdFileWrite(argv[1], pubkey, len * 2);
	cmdBlobClose(stack);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Печать

print -pass <scheme> <privkey>
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
	code = kgSelfTest();
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
	ERR_CALL_HANDLE(code, (cmdBlobClose(stack), cmdPwdClose(pwd)));
	// определить открытый ключ
	if (len == 32)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1");
	else if (len == 48)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2");
	else
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");
	if (code == ERR_OK)
		code = bignCalcPubkey(pubkey, params, privkey);
	ERR_CALL_HANDLE(code, (cmdBlobClose(stack), cmdPwdClose(pwd)));
	// печатать открытый ключ
	hexFrom(hex, pubkey, len * 2);
	printf("%s\n", hex);
	cmdBlobClose(stack);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Смена пароля защиты

chp -passin <scheme> -passout <scheme> <privkey>
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
	code = kgSelfTest();
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
	// запустить ГСЧ
	code = cmdRngStart(TRUE);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkey), cmdPwdClose(pwdout)));
	// сохранить личный ключ
	code = cmdPrivkeyWrite(privkey, len, argv[0], pwdout);
	cmdBlobClose(privkey);
	cmdPwdClose(pwdout);
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
	else if (strEq(argv[0], "val"))
		code = kgVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "pub"))
		code = kgPub(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = kgPrint(argc - 1, argv + 1);
	else if (strEq(argv[0], "chp"))
		code = kgChp(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || code == ERR_OK && strEq(argv[0], "val"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return (int)code;
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
