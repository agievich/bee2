/*
*******************************************************************************
\file belt_ecb.c
\brief STB 34.101.31 (belt): ECB encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2020.03.24
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"

/*
*******************************************************************************
Шифрование в режиме ECB
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
} belt_ecb_st;

size_t beltECB_keep()
{
	return sizeof(belt_ecb_st);
}

void beltECBStart(void* state, const octet key[], size_t len)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(memIsValid(state, beltECB_keep()));
	beltKeyExpand2(st->key, key, len);
}

void beltECBStepE(void* buf, size_t count, void* state)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockEncr(buf, st->key);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		beltBlockEncr((octet*)buf - 16, st->key);
	}
}

void beltECBStepD(void* buf, size_t count, void* state)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockDecr(buf, st->key);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		beltBlockDecr((octet*)buf - 16, st->key);
	}
}

err_t beltECBEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltECBStart(state, key, len);
	memMove(dest, src, count);
	beltECBStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltECBDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltECBStart(state, key, len);
	memMove(dest, src, count);
	beltECBStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

