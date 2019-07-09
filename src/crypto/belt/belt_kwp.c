/*
*******************************************************************************
\file belt_kwp.c
\brief STB 34.101.31 (belt): KWP (keywrap = key encryption + authentication)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2019.06.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Шифрование и имитозащита ключей (KWP)
*******************************************************************************
*/

err_t beltKWPWrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		header && !memIsDisjoint2(src, count, header, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count + 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// установить защиту
	beltKWPStart(state, key, len);
	memMove(dest, src, count);
	if (header)
		memJoin(dest, src, count, header, 16);
	else
		memSetZero(dest + count, 16);
	beltKWPStepE(dest, count + 16, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltKWPUnwrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet key[], size_t len)
{
	void* state;
	octet* header2;
	// проверить входные данные
	if (count < 32 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count - 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep() + 16);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	header2 = (octet*)state + beltKWP_keep();
	// снять защиту
	beltKWPStart(state, key, len);
	memCopy(header2, src + count - 16, 16);
	memMove(dest, src, count - 16);
	beltKWPStepD2(dest, header2, count, state);
	if (header && !memEq(header, header2, 16) ||
		header == 0 && !memIsZero(header2, 16))
	{
		memSetZero(dest, count - 16);
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
