/*
*******************************************************************************
\file cmd_pwd.c
\brief Command-line interface to Bee2: password management
\project bee2/cmd 
\created 2022.06.13
\version 2023.03.20
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
	return pwd != 0 && blobIsValid(pwd) && strIsValid(pwd) &&
		pwd[blobSize(pwd) - 1] == '\0';
}

void cmdPwdClose(cmd_pwd_t pwd)
{
	ASSERT(pwd == 0 || cmdPwdIsValid(pwd));
	blobClose(pwd);
}

/*
*******************************************************************************
Управление паролями: самотестирование
*******************************************************************************
*/

err_t pwdSelfTest()
{
	const char pwd[] = "B194BAC80A08F53B";
	octet stack[1024];
	octet buf[5 * (32 + 1)];
	octet buf1[32];
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
Управление паролями: схема pass
*******************************************************************************
*/

static err_t cmdPwdGenPass(cmd_pwd_t* pwd, const char* cmdline)
{
	ASSERT(memIsValid(pwd, sizeof(blob_t*)));
	ASSERT(strIsValid(cmdline));
	// создать пароль
	if (!(*pwd = blobCreate(strLen(cmdline) + 1)))
		return ERR_OUTOFMEMORY;
	strCopy(*pwd, cmdline);
	return ERR_OK;
}

#define cmdPwdReadPass cmdPwdGenPass

/*
*******************************************************************************
Управление паролями: схема share
*******************************************************************************
*/

static err_t cmdPwdGenShare_internal(cmd_pwd_t* pwd, size_t scount,
	size_t threshold, size_t len, char* shares[], const cmd_pwd_t spwd)
{
	err_t code;
	const size_t iter = 10000;
	size_t epki_len;
	void* stack;
	octet* pwd_bin;
	octet* share;
	octet* salt;
	octet* epki;
	// pre
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(cmdPwdIsValid(spwd));
	ASSERT(2 <= scount && scount <= 16);
	ASSERT(2 <= threshold && threshold <= scount);
	ASSERT(len % 8 == 0 && len <= 32);
	// пароль пока не создан
	*pwd = 0;
	// входной контроль
	if (!rngIsValid())
		return ERR_BAD_RNG;
	// определить длину пароля
	if (len == 0)
		len = 32;
	// определить длину контейнера с частичным секретом
	code = bpkiShareWrap(0, &epki_len, 0, len + 1, 0, 0, 0, iter);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, len + scount * (len + 1) + epki_len + 8);
	ERR_CALL_CHECK(code);
	pwd_bin = (octet*)stack;
	share = pwd_bin + len;
	salt = share + scount * (len + 1);
	epki = salt + 8;
	// сгенерировать пароль
	rngStepR(pwd_bin, len, 0);
	// разделить пароль на частичные секреты
	code = belsShare2(share, scount, threshold, len, pwd_bin, rngStepR, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// обновить ключ ГСЧ
	rngRekey();
	// защитить частичные секреты
	for (; scount--; share += (len + 1), ++shares)
	{
		FILE* fp;
		// установить защиту
		rngStepR(salt, 8, 0);
		code = bpkiShareWrap(epki, 0, share, len + 1, (const octet*)spwd,
			cmdPwdLen(spwd), salt, iter);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// открыть файл для записи
		ASSERT(strIsValid(*shares));
		fp = fopen(*shares, "wb");
		code = fp ? ERR_OK : ERR_FILE_CREATE;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// записать
		code = fwrite(epki, 1, epki_len, fp) == epki_len ?
			ERR_OK : ERR_FILE_WRITE;
		fclose(fp);
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
	size_t len, char* shares[], const cmd_pwd_t spwd)
{
	err_t code;
	size_t epki_len;
	size_t epki_len_min;
	size_t epki_len_max;
	void* stack;
	octet* share;
	octet* epki;
	octet* pwd_bin;
	size_t pos;
	// pre
	ASSERT(memIsValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(cmdPwdIsValid(spwd));
	ASSERT(2 <= scount && scount <= 16);
	ASSERT(len % 8 == 0 && len <= 32);
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
	share = (octet*)stack;
	epki = share + scount * (len + 1);
	pwd_bin = epki + epki_len_max + 1;
	// прочитать частичные секреты
	for (pos = 0; pos < scount; ++pos, ++shares)
	{
		FILE* fp;
		size_t share_len;
		// открыть файл для чтения
		ASSERT(strIsValid(*shares));
		code = (fp = fopen(*shares, "rb")) ? ERR_OK : ERR_FILE_OPEN;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// читать
		epki_len = fread(epki, 1, epki_len_max + 1, fp);
		fclose(fp);
		code = (epki_len_min <= epki_len && epki_len <= epki_len_max) ?
			ERR_OK : ERR_BAD_FORMAT;
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
			len /= 8, ++offset, --argc;
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
	code = cmdPwdGenShare_internal(pwd, (size_t)argc, threshold, len,
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
			len /= 8, ++offset, --argc;
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
	code = cmdPwdReadShare_internal(pwd, (size_t)argc, len,
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
	else if (strStartsWith(cmdline, "share:"))
		return cmdPwdGenShare(pwd, cmdline + strLen("share:"));
	return ERR_CMD_PARAMS;
}

err_t cmdPwdRead(cmd_pwd_t* pwd, const char* cmdline)
{
	if (strStartsWith(cmdline, "pass:"))
		return cmdPwdReadPass(pwd, cmdline + strLen("pass:"));
	else if (strStartsWith(cmdline, "share:"))
		return cmdPwdReadShare(pwd, cmdline + strLen("share:"));
	return ERR_CMD_PARAMS;
}
