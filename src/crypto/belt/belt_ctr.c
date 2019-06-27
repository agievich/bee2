/*
*******************************************************************************
\file belt_ctr.c
\brief STB 34.101.31 (belt): CTR encryption
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
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

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
	belt_ctr_st* s = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCTR_keep()));
	beltKeyExpand2(s->key, key, len);
	u32From(s->ctr, iv, 16);
	beltBlockEncr2(s->ctr, s->key);
	s->reserved = 0;
}

void beltCTRStepE(void* buf, size_t count, void* state)
{
	belt_ctr_st* s = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCTR_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(buf, s->block + 16 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memXor2(buf, s->block + 16 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockIncU32(s->ctr);
		beltBlockCopy(s->block, s->ctr);
		beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockIncU32(s->ctr);
		beltBlockCopy(s->block, s->ctr);
		beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		memXor2(buf, s->block, count);
		s->reserved = 16 - count;
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

