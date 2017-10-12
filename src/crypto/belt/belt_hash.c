/*
*******************************************************************************
\file belt_hash.c
\brief STB 34.101.31 (belt): hashing
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2017.09.28
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
#include "belt_int.h"

/*
*******************************************************************************
Хэширование

\remark Копии переменных хранятся для организации инкрементального хэширования.
*******************************************************************************
*/
typedef struct {
	u32 ls[8];				/*< блок [4]len || [4]s */
	u32 s1[4];				/*< копия переменной s */
	u32 h[8];				/*< переменная h */
	u32 h1[8];				/*< копия переменной h */
	octet block[32];		/*< блок данных */
	size_t filled;			/*< накоплено октетов в блоке */
	octet stack[];			/*< [beltSigma_deep()] стек beltSigma */
} belt_hash_st;

size_t beltHash_keep()
{
	return sizeof(belt_hash_st) + beltSigma_deep();
}

void beltHashStart(void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(s, beltHash_keep()));
	// len || s <- 0
	beltBlockSetZero(s->ls);
	beltBlockSetZero(s->ls + 4);
	// h <- B194...0D
	u32From(s->h, beltH(), 32);
	// нет накопленнных данных
	s->filled = 0;
}

void beltHashStepH(const void* buf, size_t count, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, beltHash_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(s->ls, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 32 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 32 - s->filled);
		count -= 32 - s->filled;
		buf = (const octet*)buf + 32 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h, (u32*)s->block, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(s->block, buf);
		beltBlockCopy(s->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h, (u32*)s->block, s->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

static void beltHashStepG_internal(void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	// pre
	ASSERT(memIsValid(s, beltHash_keep()));
	// создать копии второй части s->ls и s->h
	beltBlockCopy(s->s1, s->ls + 4);
	beltBlockCopy(s->h1, s->h);
	beltBlockCopy(s->h1 + 4, s->h + 4);
	// есть необработанные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 32 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h1, (u32*)s->block, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block + 16);
		beltBlockRevU32(s->block);
#endif
	}
	// последний блок
	beltSigma2(s->h1, s->ls, s->stack);
	// восстановить сохраненную часть s->ls
	beltBlockCopy(s->ls + 4, s->s1);
}

void beltHashStepG(octet hash[32], void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
	u32To(hash, 32, s->h1);
}

void beltHashStepG2(octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
	u32To(hash, hash_len, s->h1);
}

bool_t beltHashStepV(const octet hash[32], void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1);
	beltBlockRevU32(s->h1 + 4);
#endif
	return memEq(hash, s->h1, 32);
}

bool_t beltHashStepV2(const octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1);
	beltBlockRevU32(s->h1 + 4);
#endif
	return memEq(hash, s->h1, hash_len);
}

err_t beltHash(octet hash[32], const void* src, size_t count)
{
	void* state;
	// проверить входные данные
	if (!memIsValid(src, count) || !memIsValid(hash, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHash_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// вычислить хэш-значение
	beltHashStart(state);
	beltHashStepH(src, count, state);
	beltHashStepG(hash, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
