/*
*******************************************************************************
\file belt_cfb.c
\brief STB 34.101.31 (belt): CFB encryption
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
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_int.h"

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
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCFB_keep()));
	beltKeyExpand2(s->key, key, len);
	beltBlockCopy(s->block, iv);
	s->reserved = 0;
}

void beltCFBStepE(void* buf, size_t count, void* state)
{
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(s->block + 16 - s->reserved, buf, count);
			memCopy(buf, s->block + 16 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memXor2(s->block + 16 - s->reserved, buf, s->reserved);
		memCopy(buf, s->block + 16 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(s->block, s->key);
		beltBlockXor2(s->block, buf);
		beltBlockCopy(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(s->block, s->key);
		memXor2(s->block, buf, count);
		memCopy(buf, s->block, count);
		s->reserved = 16 - count;
	}
}

void beltCFBStepD(void* buf, size_t count, void* state)
{
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(buf, s->block + 16 - s->reserved, count);
			memXor2(s->block + 16 - s->reserved, buf, count);
			s->reserved -= count;
			return;
		}
		memXor2(buf, s->block + 16 - s->reserved, s->reserved);
		memXor2(s->block + 16 - s->reserved, buf, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(s->block, s->key);
		beltBlockXor2(buf, s->block);
		beltBlockXor2(s->block, buf);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(s->block, s->key);
		memXor2(buf, s->block, count);
		memXor2(s->block, buf, count);
		s->reserved = 16 - count;
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

