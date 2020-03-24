/*
*******************************************************************************
\file belt_cbc.c
\brief STB 34.101.31 (belt): CBC encryption
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
#include "belt_lcl.h"

/*
*******************************************************************************
Шифрование в режиме CBС
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];	/*< вспомогательный блок */
	octet block2[16];	/*< еще один вспомогательный блок */
} belt_cbc_st;

size_t beltCBC_keep()
{
	return sizeof(belt_cbc_st);
}

void beltCBCStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_cbc_st* st = (belt_cbc_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCBC_keep()));
	beltKeyExpand2(st->key, key, len);
	beltBlockCopy(st->block, iv);
}

void beltCBCStepE(void* buf, size_t count, void* state)
{
	belt_cbc_st* st = (belt_cbc_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltCBC_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockXor2(st->block, buf);
		beltBlockEncr(st->block, st->key);
		beltBlockCopy(buf, st->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		memXor2((octet*)buf - 16, st->block, count);
		beltBlockEncr((octet*)buf - 16, st->key);
	}
}

void beltCBCStepD(void* buf, size_t count, void* state)
{
	belt_cbc_st* st = (belt_cbc_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltCBC_keep()));
	// цикл по полным блокам
	while(count >= 32 || count == 16)
	{
		beltBlockCopy(st->block2, buf);
		beltBlockDecr(buf, st->key);
		beltBlockXor2(buf, st->block);
		beltBlockCopy(st->block, st->block2);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		ASSERT(16 < count && count < 32);
		beltBlockDecr(buf, st->key);
		memSwap(buf, (octet*)buf + 16, count - 16);
		memXor2((octet*)buf + 16, buf, count - 16);
		beltBlockDecr(buf, st->key);
		beltBlockXor2(buf, st->block);
	}
}

err_t beltCBCEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCBC_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltCBCStart(state, key, len, iv);
	memMove(dest, src, count);
	beltCBCStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltCBCDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCBC_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltCBCStart(state, key, len, iv);
	memMove(dest, src, count);
	beltCBCStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
