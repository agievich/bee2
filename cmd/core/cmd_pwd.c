/*
*******************************************************************************
\file cmd_pwd.c
\brief Command-line interface to Bee2: password management
\project bee2/cmd 
\created 2022.06.13
\version 2025.04.09
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
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>
#include <stdlib.h>

/*
*******************************************************************************
Управление паролями: базовые функции
*******************************************************************************
*/

cmd_pwd_t cmdPwdCreate(size_t size)
{
	return (cmd_pwd_t)blobCreate(size + 1);
}

bool_t cmdPwdIsValid(const cmd_pwd_t pwd)
{
	return strIsValid(pwd) && blobIsValid(pwd) &&
		pwd[blobSize(pwd) - 1] == '\0';
}

void cmdPwdClose(cmd_pwd_t pwd)
{
	ASSERT(pwd == 0 || cmdPwdIsValid(pwd));
	blobClose(pwd);
}

/*
*******************************************************************************
Управление паролями: схема pass
*******************************************************************************
*/

static err_t cmdPwdGenPass(cmd_pwd_t* pwd, const char* cmdline)
{
	return ERR_NOT_IMPLEMENTED;
}

static err_t cmdPwdReadPass(cmd_pwd_t* pwd, const char* cmdline)
{
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(strIsValid(cmdline));
	// создать пароль
	if (!(*pwd = cmdPwdCreate(strLen(cmdline))))
		return ERR_OUTOFMEMORY;
	strCopy(*pwd, cmdline);
	return ERR_OK;
}

/*
*******************************************************************************
Управление паролями: схема env
*******************************************************************************
*/

static const char* cmdEnvGet(const char* name)
{
	const char* val;
	val = getenv(name);
	return strIsValid(val) ? val : 0;
}

static err_t cmdPwdGenEnv(cmd_pwd_t* pwd, const char* cmdline)
{
	return ERR_NOT_IMPLEMENTED;
}

static err_t cmdPwdReadEnv(cmd_pwd_t* pwd, const char* cmdline)
{
	const char* val;
	// pre
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(strIsValid(cmdline));
	// читать пароль из переменной окружения
	if (!(val = cmdEnvGet(cmdline)))
		return ERR_BAD_ENV;
	// возвратить пароль
	if (!(*pwd = cmdPwdCreate(strLen(val))))
		return ERR_OUTOFMEMORY;
	strCopy(*pwd, val);
	return ERR_OK;
}

/*
*******************************************************************************
Управление паролями: схема share
*******************************************************************************
*/

static err_t cmdPwdGenShare_internal(cmd_pwd_t* pwd, size_t scount,
	size_t threshold, size_t len, bool_t crc, char* shares[],
	const cmd_pwd_t spwd)
{
	err_t code;
	const size_t iter = 10000;
	size_t epki_len;
	void* stack;
	octet* pwd_bin;
	octet* state;
	octet* share;
	octet* salt;
	octet* epki;
	// pre
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(cmdPwdIsValid(spwd));
	ASSERT(2 <= scount && scount <= 16);
	ASSERT(2 <= threshold && threshold <= scount);
	ASSERT(len % 8 == 0 && len <= 32);
	ASSERT(!crc || len != 16);
	// пароль пока не создан
	*pwd = 0;
	// определить длину пароля
	if (len == 0)
		len = 32;
	// определить длину контейнера с частичным секретом
	code = bpkiShareWrap(0, &epki_len, 0, len + 1, 0, 0, 0, iter);
	ERR_CALL_CHECK(code);
	// запустить ГСЧ
	code = cmdRngStart(TRUE);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, len +
		utilMax(2,
			beltMAC_keep(),
			scount * (len + 1) + epki_len + 8));
	ERR_CALL_CHECK(code);
	pwd_bin = (octet*)stack;
	state = share = pwd_bin + len;
	salt = share + scount * (len + 1);
	epki = salt + 8;
	// генерировать пароль
	if (crc)
	{
		rngStepR(pwd_bin, len - 8, 0);
		beltMACStart(state, pwd_bin, len - 8);
		beltMACStepA(pwd_bin, len - 8, state);
		beltMACStepG(pwd_bin + len - 8, state);
	}
	else
		rngStepR(pwd_bin, len, 0);
	// разделить пароль на частичные секреты
	code = belsShare2(share, scount, threshold, len, pwd_bin, rngStepR, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// обновить ключ ГСЧ
	rngRekey();
	// защитить частичные секреты
	for (; scount--; share += (len + 1), ++shares)
	{
		// установить защиту
		rngStepR(salt, 8, 0);
		code = bpkiShareWrap(epki, 0, share, len + 1, (const octet*)spwd,
			cmdPwdLen(spwd), salt, iter);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// записать в файл
		code = cmdFileWrite(*shares, epki, epki_len);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	}
	// создать выходной (текстовый) пароль
	*pwd = cmdPwdCreate(2 * len);
	code = *pwd ? ERR_OK : ERR_OUTOFMEMORY;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	hexFrom(*pwd, pwd_bin, len);
	cmdBlobClose(stack);
	return code;
}

static err_t cmdPwdReadShare_internal(cmd_pwd_t* pwd, size_t scount,
	size_t len, bool_t crc, char* shares[], const cmd_pwd_t spwd)
{
	err_t code;
	size_t epki_len;
	size_t epki_len_min;
	size_t epki_len_max;
	void* stack;
	octet* share;
	octet* state;
	octet* epki;
	octet* pwd_bin;
	size_t pos;
	// pre
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(cmdPwdIsValid(spwd));
	ASSERT(2 <= scount && scount <= 16);
	ASSERT(len % 8 == 0 && len <= 32);
	ASSERT(!crc || len != 16);
	// пароль пока не создан
	*pwd = 0;
	// определить длину частичного секрета
	if (len == 0)
	{
		// определить размер первого файла с частичным секретом
		if ((epki_len = cmdFileSize(shares[0])) == SIZE_MAX)
			return ERR_FILE_READ;
		// найти подходящую длину
		for (len = 16; len <= 32; len += 8)
		{
			code = bpkiShareWrap(0, &epki_len_min, 0, len + 1, 0, 0, 0, 10000);
			ERR_CALL_CHECK(code);
			code = bpkiShareWrap(0, &epki_len_max, 0, len + 1, 0, 0, 0, 
				SIZE_MAX);
			ERR_CALL_CHECK(code);
			if (epki_len_min <= epki_len && epki_len <= epki_len_max)
				break;
		}
		if (len > 32)
			return ERR_BAD_FORMAT;
	}
	else
	{
		code = bpkiShareWrap(0, &epki_len_min, 0, len + 1, 0, 0, 0, 10000);
		ERR_CALL_CHECK(code);
		code = bpkiShareWrap(0, &epki_len_max, 0, len + 1, 0, 0, 0,	SIZE_MAX);
		ERR_CALL_CHECK(code);
	}
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, scount * (len + 1) + epki_len_max + 1 + len);
	ERR_CALL_HANDLE(code, cmdPwdClose(*pwd));
	share = state = (octet*)stack;
	epki = share + scount * (len + 1);
	pwd_bin = epki + epki_len_max + 1;
	// прочитать частичные секреты
	for (pos = 0; pos < scount; ++pos, ++shares)
	{
		size_t share_len;
		// определить длину контейнера
		code = cmdFileReadAll(0, &epki_len, *shares);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить длину
		code = (epki_len_min <= epki_len && epki_len <= epki_len_max) ?
			ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// читать
		code = cmdFileReadAll(epki, &epki_len, *shares);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// декодировать
		code = bpkiShareUnwrap(share + pos * (len + 1), &share_len,
			epki, epki_len, (const octet*)spwd, cmdPwdLen(spwd));
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		code = (share_len == len + 1) ? ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	}
	// собрать пароль
	code = belsRecover2(pwd_bin, scount, len, share);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить пароль
	if (crc)
	{
		beltMACStart(state, pwd_bin, len - 8);
		beltMACStepA(pwd_bin, len - 8, state);
		if (!beltMACStepV(pwd_bin + len - 8, state))
			code = ERR_BAD_CRC;
	}
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// создать выходной (текстовый) пароль
	*pwd = cmdPwdCreate(2 * len);
	code = *pwd ? ERR_OK : ERR_OUTOFMEMORY;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	hexFrom(*pwd, pwd_bin, len);
	cmdBlobClose(stack);
	return code;
}

static err_t cmdPwdGenShare(cmd_pwd_t* pwd, const char* cmdline)
{
	err_t code;
	int argc;
	char** argv = 0;
	size_t offset = 0;
	size_t threshold = 0;
	size_t len = 0;
	bool_t crc = FALSE;
	cmd_pwd_t spwd = 0;
	// составить список аргументов
	code = cmdArgCreate(&argc, &argv, cmdline);
	ERR_CALL_CHECK(code);
	// обработать опции
	while (argc && strStartsWith(argv[offset], "-"))
	{
		// порог
		if (strStartsWith(argv[offset], "-t"))
		{
			char* str = argv[offset] + strLen("-t");
			if (threshold)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) > 2 ||
				(threshold = (size_t)decToU32(str)) < 2 || threshold > 16)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			++offset, --argc;
		}
		// уровень стойкости
		else if (strStartsWith(argv[offset], "-l"))
		{
			char* str = argv[offset] + strLen("-l");
			if (len)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) != 3 ||
				(len = (size_t)decToU32(str)) % 64 || len < 128 || len > 256)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			len /= 8;
			if (len == 16 && crc)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			++offset, --argc;
		}
		// контрольная сумма
		else if (strStartsWith(argv[offset], "-crc"))
		{
			if (crc)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (len == 16)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			crc = TRUE, ++offset, --argc;
		}
		// пароль защиты частичных секретов
		else if (strEq(argv[offset], "-pass"))
		{
			if (spwd)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			++offset, --argc;
			// определить пароль защиты частичных секретов
			code = cmdPwdRead(&spwd, argv[offset]);
			ERR_CALL_HANDLE(code, cmdArgClose(argv));
			ASSERT(cmdPwdIsValid(spwd));
			++offset, --argc;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			goto final;
		}
	}
	// проверить, что пароль защиты частичных секретов построен
	if (!spwd)
	{
		code = ERR_CMD_PARAMS;
		goto final;
	}
	// настроить порог
	if (!threshold)
		threshold = 2;
	// проверить число файлов с частичными секретами
	if ((size_t)argc < threshold)
	{
		code = ERR_CMD_PARAMS;
		goto final;
	}
	// проверить отсутствие файлов с частичными секретами
	if ((code = cmdFileValNotExist(argc, argv + offset)) != ERR_OK)
		goto final;
	// построить пароль
	code = cmdPwdGenShare_internal(pwd, (size_t)argc, threshold, len, crc,
		argv + offset, spwd);
final:
	cmdPwdClose(spwd);
	cmdArgClose(argv);
	return code;
}

static err_t cmdPwdReadShare(cmd_pwd_t* pwd, const char* cmdline)
{
	err_t code;
	int argc;
	char** argv = 0;
	size_t offset = 0;
	size_t threshold = 0;
	size_t len = 0;
	bool_t crc = FALSE;
	cmd_pwd_t spwd = 0;
	// составить список аргументов
	code = cmdArgCreate(&argc, &argv, cmdline);
	ERR_CALL_CHECK(code);
	// обработать опции
	while (argc && strStartsWith(argv[offset], "-"))
	{
		// порог
		if (strStartsWith(argv[offset], "-t"))
		{
			char* str = argv[offset] + strLen("-t");
			if (threshold)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) > 2 ||
				(threshold = (size_t)decToU32(str)) < 2 || threshold > 16)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			++offset, --argc;
		}
		// уровень стойкости
		else if (strStartsWith(argv[offset], "-l"))
		{
			char* str = argv[offset] + strLen("-l");
			if (len)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (!decIsValid(str) || decCLZ(str) || strLen(str) != 3 ||
				(len = (size_t)decToU32(str)) % 64 || len < 128 || len > 256)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			len /= 8;
			if (len == 16 && crc)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			++offset, --argc;
		}
		// контрольная сумма
		else if (strStartsWith(argv[offset], "-crc"))
		{
			if (crc)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			if (len == 16)
			{
				code = ERR_CMD_PARAMS;
				goto final;
			}
			crc = TRUE, ++offset, --argc;
		}
		// пароль защиты частичных секретов
		else if (strEq(argv[offset], "-pass"))
		{
			if (spwd)
			{
				code = ERR_CMD_DUPLICATE;
				goto final;
			}
			++offset, --argc;
			// определить пароль защиты частичных секретов
			code = cmdPwdRead(&spwd, argv[offset]);
			ERR_CALL_HANDLE(code, cmdArgClose(argv));
			ASSERT(cmdPwdIsValid(spwd));
			++offset, --argc;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			goto final;
		}
	}
	// проверить, что пароль защиты частичных секретов определен
	if (!spwd)
	{
		code = ERR_CMD_PARAMS;
		goto final;
	}
	// настроить порог
	if (!threshold)
		threshold = 2;
	// проверить число файлов с частичными секретами
	if ((size_t)argc < threshold)
	{
		code = ERR_CMD_PARAMS;
		goto final;
	}
	// проверить наличие файлов с частичными секретами
	if ((code = cmdFileValExist(argc, argv + offset)) != ERR_OK)
		goto final;
	// определить пароль
	code = cmdPwdReadShare_internal(pwd, (size_t)argc, len, crc,
		argv + offset, spwd);
final:
	cmdPwdClose(spwd);
	cmdArgClose(argv);
	return code;
}

/*
*******************************************************************************
Управление паролями: построение / определение
*******************************************************************************
*/

err_t cmdPwdGen(cmd_pwd_t* pwd, const char* cmdline)
{
	if (strStartsWith(cmdline, "pass:"))
		return cmdPwdGenPass(pwd, cmdline + strLen("pass:"));
	else if (strStartsWith(cmdline, "env:"))
		return cmdPwdGenEnv(pwd, cmdline + strLen("env:"));
	else if (strStartsWith(cmdline, "share:"))
		return cmdPwdGenShare(pwd, cmdline + strLen("share:"));
	return ERR_CMD_PARAMS;
}

err_t cmdPwdRead(cmd_pwd_t* pwd, const char* cmdline)
{
	if (strStartsWith(cmdline, "pass:"))
		return cmdPwdReadPass(pwd, cmdline + strLen("pass:"));
	else if (strStartsWith(cmdline, "env:"))
		return cmdPwdReadEnv(pwd, cmdline + strLen("env:"));
	else if (strStartsWith(cmdline, "share:"))
		return cmdPwdReadShare(pwd, cmdline + strLen("share:"));
	return ERR_CMD_PARAMS;
}
