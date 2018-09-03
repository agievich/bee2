/*
*******************************************************************************
\file belt_bde.c
\brief STB 34.101.31 (belt): BDE (Blockwise Disk Encryption)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2018.06.28
\version 2018.09.01
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
Умножение на многочлен C(x) = x mod (x^128 + x^7 + x^2 + x + 1)

\remark t = (старший бит block ненулевой) ? x^7 + x^2 + x + 1 : 0 [регулярно].
*******************************************************************************
*/

void beltBlockMulC(u32 block[4])
{
	register u32 t = ~((block[3] >> 31) - U32_1) & 0x00000087;
	block[3] = (block[3] << 1) ^ (block[2] >> 31);
	block[2] = (block[2] << 1) ^ (block[1] >> 31);
	block[1] = (block[1] << 1) ^ (block[0] >> 31);
	block[0] = (block[0] << 1) ^ t;
	t = 0;
}

/*
*******************************************************************************
Шифрование в режиме BDE
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	u32 s[4];			/*< переменная s */
	octet block[16];	/*< вспомогательный блок */
} belt_bde_st;

size_t beltBDE_keep()
{
	return sizeof(belt_bde_st);
}

void beltBDEStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_bde_st* s = (belt_bde_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltBDE_keep()));
	beltKeyExpand2(s->key, key, len);
	u32From(s->s, iv, 16);
	beltBlockEncr2(s->s, s->key);
}

void beltBDEStepE(void* buf, size_t count, void* state)
{
	belt_bde_st* s = (belt_bde_st*)state;
	ASSERT(count % 16 == 0);
	ASSERT(memIsDisjoint2(buf, count, state, beltBDE_keep()));
	// цикл по блокам
	while(count >= 16)
	{
		beltBlockMulC(s->s);
		u32To(s->block, 16, s->s);
		beltBlockXor2(buf, s->block);
		beltBlockEncr(buf, s->key);
		beltBlockXor2(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
}

void beltBDEStepD(void* buf, size_t count, void* state)
{
	belt_bde_st* s = (belt_bde_st*)state;
	ASSERT(count % 16 == 0);
	ASSERT(memIsDisjoint2(buf, count, state, beltBDE_keep()));
	// цикл по блокам
	while(count >= 16)
	{
		beltBlockMulC(s->s);
		u32To(s->block, 16, s->s);
		beltBlockXor2(buf, s->block);
		beltBlockDecr(buf, s->key);
		beltBlockXor2(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
}

err_t beltBDEEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count % 16 != 0 || count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltBDE_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltBDEStart(state, key, len, iv);
	memMove(dest, src, count);
	beltBDEStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltBDEDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count % 16 != 0 || count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltBDE_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltBDEStart(state, key, len, iv);
	memMove(dest, src, count);
	beltBDEStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}