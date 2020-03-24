/*
*******************************************************************************
\file belt_cfb.c
\brief STB 34.101.31 (belt): CFB encryption
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
Шифрование в режиме CFB
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];	/*< блок гаммы */
	size_t reserved;	/*< резерв октетов гаммы */
} belt_cfb_st;

size_t beltCFB_keep()
{
	return sizeof(belt_cfb_st);
}

void beltCFBStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_cfb_st* st = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCFB_keep()));
	beltKeyExpand2(st->key, key, len);
	beltBlockCopy(st->block, iv);
	st->reserved = 0;
}

void beltCFBStepE(void* buf, size_t count, void* state)
{
	belt_cfb_st* st = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (st->reserved)
	{
		if (st->reserved >= count)
		{
			memXor2(st->block + 16 - st->reserved, buf, count);
			memCopy(buf, st->block + 16 - st->reserved, count);
			st->reserved -= count;
			return;
		}
		memXor2(st->block + 16 - st->reserved, buf, st->reserved);
		memCopy(buf, st->block + 16 - st->reserved, st->reserved);
		count -= st->reserved;
		buf = (octet*)buf + st->reserved;
		st->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(st->block, st->key);
		beltBlockXor2(st->block, buf);
		beltBlockCopy(buf, st->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(st->block, st->key);
		memXor2(st->block, buf, count);
		memCopy(buf, st->block, count);
		st->reserved = 16 - count;
	}
}

void beltCFBStepD(void* buf, size_t count, void* state)
{
	belt_cfb_st* st = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (st->reserved)
	{
		if (st->reserved >= count)
		{
			memXor2(buf, st->block + 16 - st->reserved, count);
			memXor2(st->block + 16 - st->reserved, buf, count);
			st->reserved -= count;
			return;
		}
		memXor2(buf, st->block + 16 - st->reserved, st->reserved);
		memXor2(st->block + 16 - st->reserved, buf, st->reserved);
		count -= st->reserved;
		buf = (octet*)buf + st->reserved;
		st->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(st->block, st->key);
		beltBlockXor2(buf, st->block);
		beltBlockXor2(st->block, buf);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(st->block, st->key);
		memXor2(buf, st->block, count);
		memXor2(st->block, buf, count);
		st->reserved = 16 - count;
	}
}

err_t beltCFBEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCFB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltCFBStart(state, key, len, iv);
	memMove(dest, src, count);
	beltCFBStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltCFBDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCFB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltCFBStart(state, key, len, iv);
	memMove(dest, src, count);
	beltCFBStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

