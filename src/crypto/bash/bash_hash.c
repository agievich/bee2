/*
*******************************************************************************
\file bash_hash.c
\brief STB 34.101.77 (bash): hashing algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2014.07.15
\version 2018.10.30
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"
#include "bash_int.h"

/*
*******************************************************************************
Хэширование
*******************************************************************************
*/

typedef struct {
	u64 s[24];			/*< состояние */
	u64 s1[24];			/*< копия s */
	size_t block_len;	/*< длина блока */
	size_t filled;		/*< накоплено октетов в блоке */
} bash_hash_st;

size_t bashHash_keep()
{
	return sizeof(bash_hash_st);
}

void bashHashStart(void* state, size_t l)
{
	bash_hash_st* s = (bash_hash_st*)state;
	ASSERT(l > 0 && l % 16 == 0 && l <= 256);
	ASSERT(memIsValid(s, bashHash_keep()));
	// s <- 0^{1536 - 64} || <l / 4>_{64}
	memSetZero(s->s, sizeof(s->s) - 8);
	s->s[23] = (u64)(l / 4);
	// длина блока
	s->block_len = 192 - l / 2;
	// нет накопленнных данных
	s->filled = 0;
}

void bashHashStepH(const void* buf, size_t count, void* state)
{
	bash_hash_st* s = (bash_hash_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, sizeof(bash_hash_st)));
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < s->block_len - s->filled)
		{
			memCopy((octet*)s->s + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy((octet*)s->s + s->filled, buf, s->block_len - s->filled);
		count -= s->block_len - s->filled;
		buf = (const octet*)buf + s->block_len - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		u64Rev2(s->s, s->block_len / 8);
#endif
		bashF0(s->s);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= s->block_len)
	{
		memCopy(s->s, buf, s->block_len);
#if (OCTET_ORDER == BIG_ENDIAN)
		u64Rev2(s->s, s->block_len / 8);
#endif
		bashF0(s->s);
		buf = (const octet*)buf + s->block_len;
		count -= s->block_len;
	}
	// неполный блок?
	if (count)
		memCopy(s->s, buf, s->filled = count);
}

static void bashHashStepG_internal(size_t hash_len, void* state)
{
	bash_hash_st* s = (bash_hash_st*)state;
	// pre
	ASSERT(memIsValid(s, sizeof(bash_hash_st)));
	ASSERT(s->block_len + hash_len * 2 <= 192);
	// создать копию s->s
	memCopy(s->s1, s->s, sizeof(s->s));
	// есть необработанные данные?
	if (s->filled)
	{
		memSetZero((octet*)s->s1 + s->filled, s->block_len - s->filled);
		((octet*)s->s1)[s->filled] = 0x40;
	}
	// дополнительный блок
	else
	{
		memSetZero(s->s1, s->block_len);
		((octet*)s->s1)[0] = 0x40;
	}
	// последний шаг
	bashF0(s->s1);
#if (OCTET_ORDER == BIG_ENDIAN)
	u64Rev2(s->s1, (hash_len + 7) / 8);
#endif
}

void bashHashStepG(octet hash[], size_t hash_len, void* state)
{
	bash_hash_st* s = (bash_hash_st*)state;
	bashHashStepG_internal(hash_len, state);
	memMove(hash, s->s1, hash_len);
}

bool_t bashHashStepV(const octet hash[], size_t hash_len, void* state)
{
	bash_hash_st* s = (bash_hash_st*)state;
	bashHashStepG_internal(hash_len, state);
	return memEq(hash, s->s1, hash_len);
}

err_t bashHash(octet hash[], size_t l, const void* src, size_t count)
{
	void* state;
	// проверить входные данные
	if (l == 0 || l % 16 != 0 || l > 256)
		return ERR_BAD_PARAMS;
	if (!memIsValid(src, count) || !memIsValid(hash, l / 4))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bashHash_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// вычислить хэш-значение
	bashHashStart(state, l);
	bashHashStepH(src, count, state);
	bashHashStepG(hash, l / 4, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
