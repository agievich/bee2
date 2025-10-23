/*
*******************************************************************************
\file cmd_privkey.c
\brief Command-line interface to Bee2: managing private keys
\project bee2/cmd 
\created 2022.06.20
\version 2025.10.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bpki.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Запись личного ключа
*******************************************************************************
*/

err_t cmdPrivkeyWrite(const octet privkey[], size_t privkey_len,
	const char* name, const cmd_pwd_t pwd)
{
	err_t code;
	const size_t iter = 10000;
	size_t epki_len;
	void* state;
	octet* salt;			/* [8] */
	octet* epki;			/* [epki_len] */
	// pre
	ASSERT(privkey_len == 24 || privkey_len == 32 || privkey_len == 48 || 
		privkey_len == 64);
	ASSERT(memIsValid(privkey, privkey_len));
	ASSERT(strIsValid(name));
	ASSERT(cmdPwdIsValid(pwd));
	// определить длину контейнера
	code = bpkiPrivkeyWrap(0, &epki_len, 0, privkey_len, 0, 0, 0, iter);
	ERR_CALL_CHECK(code);
	// выделить и разметить память
	code = cmdBlobCreate2(state, 
		(size_t)8,
		epki_len, 
		SIZE_MAX,
		&salt, &epki);
	ERR_CALL_CHECK(code);
	// запустить ГСЧ
	code = cmdRngStart(TRUE);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// установить защиту
	rngStepR(salt, 8, 0);
	code = bpkiPrivkeyWrap(epki, 0, privkey, privkey_len, (const octet*)pwd,
		cmdPwdLen(pwd), salt, iter);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// записать в файл
	code = cmdFileWrite(name, epki, epki_len);
	// завершить
	cmdBlobClose(state);
	return code;
}

/*
*******************************************************************************
Чтение личного ключа
*******************************************************************************
*/

err_t cmdPrivkeyRead(octet privkey[], size_t* privkey_len, const char* name,
	const cmd_pwd_t pwd)
{
	err_t code;
	size_t len;
	size_t epki_len;
	size_t epki_len_min;
	size_t epki_len_max;
	void* state;
	octet* epki;			/* [epki_len_max + 1] */
	// pre
	ASSERT(memIsNullOrValid(privkey_len, sizeof(size_t)));
	ASSERT(!privkey_len || *privkey_len == 0 || *privkey_len == 24 ||
		*privkey_len == 32 || *privkey_len == 48 || *privkey_len == 64);
	ASSERT(strIsValid(name));
	ASSERT(cmdPwdIsValid(pwd));
	// определить длину личного ключа по размеру контейнера
	if (!privkey_len || *privkey_len == 0)
	{
		// определить размер контейнера
		if ((epki_len = cmdFileSize(name)) == SIZE_MAX)
			return ERR_FILE_READ;
		// найти подходящую длину
		for (len = 24; len <= 64; len = len == 24 ? len + 8 : len + 16)
		{
			code = bpkiPrivkeyWrap(0, &epki_len_min, 0, len, 0, 0, 0, 10000);
			ERR_CALL_CHECK(code);
			code = bpkiPrivkeyWrap(0, &epki_len_max, 0, len, 0, 0, 0, SIZE_MAX);
			ERR_CALL_CHECK(code);
			if (epki_len_min <= epki_len && epki_len <= epki_len_max)
				break;
		}
		if (len > 64)
			return ERR_BAD_FORMAT;
		if (privkey_len)
			*privkey_len = len;
	}
	// обработать переданную длину личного ключа
	else
	{
		len = *privkey_len;
		code = bpkiPrivkeyWrap(0, &epki_len_min, 0, len, 0, 0, 0, 10000);
		ERR_CALL_CHECK(code);
		code = bpkiPrivkeyWrap(0, &epki_len_max, 0, len, 0, 0, 0, SIZE_MAX);
		ERR_CALL_CHECK(code);
	}
	// ключ определять не нужно?
	if (!privkey)
		return ERR_OK;
	ASSERT(len == 24 || len == 32 || len == 48 || len == 64);
	ASSERT(memIsValid(privkey, len));
	// выделить и разметить память
	code = cmdBlobCreate2(state, 
		epki_len_max + 1,
		SIZE_MAX,
		&epki);
	ERR_CALL_CHECK(code);
	// определить длину контейнера
	code = cmdFileReadAll(0, &epki_len, name);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// проверить длину
	code = (epki_len_min <= epki_len && epki_len <= epki_len_max) ?
		ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// читать
	code = cmdFileReadAll(epki, &epki_len, name);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// снять защиту
	code = bpkiPrivkeyUnwrap(privkey, &epki_len_min, epki, epki_len,
		(const octet*)pwd, cmdPwdLen(pwd));
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	ASSERT(epki_len_min == len);
	cmdBlobClose(state);
	return code;
}
