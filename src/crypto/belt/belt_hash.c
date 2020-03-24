/*
*******************************************************************************
\file belt_hash.c
\brief STB 34.101.31 (belt): hashing
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
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

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
	octet stack[];			/*< [beltCompr_deep()] стек beltCompr */
} belt_hash_st;

size_t beltHash_keep()
{
	return sizeof(belt_hash_st) + beltCompr_deep();
}

void beltHashStart(void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(memIsValid(state, beltHash_keep()));
	// len || s <- 0
	beltBlockSetZero(st->ls);
	beltBlockSetZero(st->ls + 4);
	// h <- B194...0D
	u32From(st->h, beltH(), 32);
	// нет накопленнных данных
	st->filled = 0;
}

void beltHashStepH(const void* buf, size_t count, void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltHash_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(st->ls, count);
	// есть накопленные данные?
	if (st->filled)
	{
		if (count < 32 - st->filled)
		{
			memCopy(st->block + st->filled, buf, count);
			st->filled += count;
			return;
		}
		memCopy(st->block + st->filled, buf, 32 - st->filled);
		count -= 32 - st->filled;
		buf = (const octet*)buf + 32 - st->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls + 4, st->h, (u32*)st->block, st->stack);
		st->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(st->block, buf);
		beltBlockCopy(st->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls + 4, st->h, (u32*)st->block, st->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(st->block, buf, st->filled = count);
}

static void beltHashStepG_internal(void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	// pre
	ASSERT(memIsValid(state, beltHash_keep()));
	// создать копии второй части st->ls и st->h
	beltBlockCopy(st->s1, st->ls + 4);
	beltBlockCopy(st->h1, st->h);
	beltBlockCopy(st->h1 + 4, st->h + 4);
	// есть необработанные данные?
	if (st->filled)
	{
		memSetZero(st->block + st->filled, 32 - st->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls + 4, st->h1, (u32*)st->block, st->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block + 16);
		beltBlockRevU32(st->block);
#endif
	}
	// последний блок
	beltCompr(st->h1, st->ls, st->stack);
	// восстановить сохраненную часть st->ls
	beltBlockCopy(st->ls + 4, st->s1);
}

void beltHashStepG(octet hash[32], void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
	u32To(hash, 32, st->h1);
}

void beltHashStepG2(octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
	u32To(hash, hash_len, st->h1);
}

bool_t beltHashStepV(const octet hash[32], void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(st->h1);
	beltBlockRevU32(st->h1 + 4);
#endif
	return memEq(hash, st->h1, 32);
}

bool_t beltHashStepV2(const octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* st = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(st->h1);
	beltBlockRevU32(st->h1 + 4);
#endif
	return memEq(hash, st->h1, hash_len);
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
