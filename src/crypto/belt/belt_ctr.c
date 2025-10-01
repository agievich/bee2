/*
*******************************************************************************
\file belt_ctr.c
\brief STB 34.101.31 (belt): CTR encryption
\project bee2 [cryptographic library]
\created 2012.12.18
\version 2025.10.01
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Инкремент
*******************************************************************************
*/

static void beltBlockInc(u32 block[4])
{
	register u32 carry = 1;
	block[0] += carry, carry = wordLess(block[0], carry);
	block[1] += carry, carry = wordLess(block[1], carry);
	block[2] += carry, carry = wordLess(block[2], carry);
	block[3] += carry, carry = wordLess(block[3], carry);
	CLEAN(carry);
}


/*
*******************************************************************************
Шифрование в режиме CTR

Для ускорения работы счетчик ctr хранится в виде [4]u32. Это позволяет
зашифровывать счетчик с помощью функции beltBlockEncr2(), в которой
не используется реверс октетов  даже на платформах BIG_ENDIAN.
Реверс применяется только перед использованием зашифрованного счетчика
в качестве гаммы.
*******************************************************************************
*/

size_t beltCTR_keep()
{
	return sizeof(belt_ctr_st);
}

void beltCTRStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_ctr_st* st = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCTR_keep()));
	beltKeyExpand2(st->key, key, len);
	u32From(st->ctr, iv, 16);
	beltBlockEncr2(st->ctr, st->key);
	st->reserved = 0;
}

void beltCTRStepE(void* buf, size_t count, void* state)
{
	belt_ctr_st* st = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCTR_keep()));
	// есть резерв гаммы?
	if (st->reserved)
	{
		if (st->reserved >= count)
		{
			memXor2(buf, st->block + 16 - st->reserved, count);
			st->reserved -= count;
			return;
		}
		memXor2(buf, st->block + 16 - st->reserved, st->reserved);
		count -= st->reserved;
		buf = (octet*)buf + st->reserved;
		st->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockInc(st->ctr);
		beltBlockCopy(st->block, st->ctr);
		ASSERT(memIsAligned(st->block, 4));
		beltBlockEncr2((u32*)st->block, st->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		beltBlockXor2(buf, st->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockInc(st->ctr);
		beltBlockCopy(st->block, st->ctr);
		ASSERT(memIsAligned(st->block, 4));
		beltBlockEncr2((u32*)st->block, st->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		memXor2(buf, st->block, count);
		st->reserved = 16 - count;
	}
}

err_t beltCTR(void* dest, const void* src, size_t count,
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
	state = blobCreate(beltCTR_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltCTRStart(state, key, len, iv);
	memMove(dest, src, count);
	beltCTRStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
