/*
*******************************************************************************
\file bash_hash.c
\brief STB 34.101.77 (bash): hashing algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2014.07.15
\version 2020.06.23
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

/*
*******************************************************************************
Хэширование
*******************************************************************************
*/

typedef struct {
	octet s[192];		/*< состояние */
	octet s1[192];		/*< копия s */
	size_t buf_len;		/*< длина буфера */
	size_t pos;		/*< позиция в буфере (накоплено октетов) */
	octet stack[];		/*< [bashF_deep()] стек bashF */
} bash_hash_st;

size_t bashHash_keep()
{
	return sizeof(bash_hash_st) + bashF_deep();
}

void bashHashStart(void* state, size_t l)
{
	bash_hash_st* st = (bash_hash_st*)state;
	ASSERT(l > 0 && l % 16 == 0 && l <= 256);
	ASSERT(memIsValid(st, bashHash_keep()));
	// s <- 0^{1536 - 64} || <l / 4>_{64}
	memSetZero(st->s, sizeof(st->s));
	st->s[192 - 8] = (octet)(l / 4);
	// длина блока
	st->buf_len = 192 - l / 2;
	// нет накопленнных октетов
	st->pos = 0;
}

void bashHashStepH(const void* buf, size_t count, void* state)
{
	bash_hash_st* st = (bash_hash_st*)state;
	ASSERT(memIsDisjoint2(st, bashHash_keep(), buf, count));
	// не накопился полный буфер?
	if (count < st->buf_len - st->pos)
	{
		memCopy(st->s + st->pos, buf, count);
		st->pos += count;
		return;
	}
	// новый полный буфер
	memCopy(st->s + st->pos, buf, st->buf_len - st->pos);
	buf = (const octet*)buf + st->buf_len - st->pos;
	count -= st->buf_len - st->pos;
	bashF(st->s, st->stack);
	// цикл по полным блокам
	while (count >= st->buf_len)
	{
		memCopy(st->s, buf, st->buf_len);
		buf = (const octet*)buf + st->buf_len;
		count -= st->buf_len;
		bashF(st->s, st->stack);
	}
	// неполный блок?
	if (st->pos = count)
		memCopy(st->s, buf, count);
}

static void bashHashStepG_internal(size_t hash_len, void* state)
{
	bash_hash_st* st = (bash_hash_st*)state;
	ASSERT(memIsValid(st, bashHash_keep()));
	ASSERT(st->buf_len + hash_len * 2 <= 192);
	// создать копию s
	memCopy(st->s1, st->s, sizeof(st->s));
	// есть необработанные данные?
	if (st->pos)
	{
		memSetZero(st->s1 + st->pos, st->buf_len - st->pos);
		st->s1[st->pos] = 0x40;
	}
	// дополнительный блок
	else
	{
		memSetZero(st->s1, st->buf_len);
		st->s1[0] = 0x40;
	}
	// последний шаг
	bashF(st->s1, st->stack);
}

void bashHashStepG(octet hash[], size_t hash_len, void* state)
{
	bash_hash_st* st = (bash_hash_st*)state;
	bashHashStepG_internal(hash_len, state);
	memMove(hash, st->s1, hash_len);
}

bool_t bashHashStepV(const octet hash[], size_t hash_len, void* state)
{
	bash_hash_st* st = (bash_hash_st*)state;
	bashHashStepG_internal(hash_len, state);
	return memEq(hash, st->s1, hash_len);
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
