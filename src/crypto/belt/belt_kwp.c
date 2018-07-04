/*
*******************************************************************************
\file belt_kwp.c
\brief STB 34.101.31 (belt): KWP (keywrap = key encryption + authentication)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2017.11.20
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
Шифрование и имитозащита ключей (KWP)

Отдельная от WBL реализация: в состоянии можно не учитывать номер такта.

todo: Упростить, через обращение к функциям WBL.
*******************************************************************************
*/

typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];	/*< вспомогательный блок */
} belt_kwp_st;

size_t beltKWP_keep()
{
	return sizeof(belt_kwp_st);
}

void beltKWPStart(void* state, const octet key[], size_t len)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	ASSERT(memIsValid(state, beltWBL_keep()));
	beltKeyExpand2(s->key, key, len);
}

void beltKWPStepE(void* buf, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	word round;
	// pre
	ASSERT(count > 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	// итерации
	for (round = 1; round <= 2 * n; ++round)
	{
		size_t i;
		// block <- r1 + ... + r_{n-1}
		beltBlockCopy(s->block, buf);
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(s->block, (octet*)buf + i);
		// r <- ShLo^128(r)
		memMove(buf, (octet*)buf + 16, count - 16);
		// r* <- block
		beltBlockCopy((octet*)buf + count - 16, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &round, O_PER_W);
#else // BIG_ENDIAN
		round = wordRev(round);
		memXor2(s->block, &round, O_PER_W);
		round = wordRev(round);
#endif // OCTET_ORDER
		// r*_до_сдвига <- r*_до_сдвига + block
		beltBlockXor2((octet*)buf + count - 32, s->block);
	}
}

void beltKWPStepD(void* buf, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	word round;
	// pre
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	for (round = 2 * n; round; --round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(s->block, (octet*)buf + count - 16);
		// r <- ShHi^128(r)
		memMove((octet*)buf + 16, buf, count - 16);
		// r1 <- block
		beltBlockCopy(buf, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &round, O_PER_W);
#else // BIG_ENDIAN
		round = wordRev(round);
		memXor2(s->block, &round, O_PER_W);
		round = wordRev(round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + count - 16, s->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(buf, (octet*)buf + i);
	}
}

void beltKWPStepD2(void* buf1, void* buf2, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	word round;
	// pre
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint3(buf1, count - 16, buf2, 16, state, beltKWP_keep()));
	for (round = 2 * n; round; --round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(s->block, buf2);
		// r <- ShHi^128(r)
		memCopy(buf2, (octet*)buf1 + count - 32, 16);
		memMove((octet*)buf1 + 16, buf1, count - 32);
		// r1 <- block
		beltBlockCopy(buf1, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &round, O_PER_W);
#else // BIG_ENDIAN
		round = wordRev(round);
		memXor2(s->block, &round, O_PER_W);
		round = wordRev(round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2(buf2, s->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 32 < count; i += 16)
			beltBlockXor2(buf1, (octet*)buf1 + i);
		ASSERT(i + 16 <= count && i + 32 >= count);
		if (i + 16 < count)
		{
			memXor2(buf1, (octet*)buf1 + i, count - 16 - i);
			memXor2((octet*)buf1 + count - 16 - i, buf2, 32 + i - count);
		}
	}
}

err_t beltKWPWrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		header && !memIsDisjoint2(src, count, header, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count + 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// установить защиту
	beltKWPStart(state, key, len);
	memMove(dest, src, count);
	if (header)
		memJoin(dest, src, count, header, 16);
	else
		memMove(dest, src, count), // <- не нужная строчка, уже есть такая сверху!
		memSetZero(dest + count, 16);
	beltKWPStepE(dest, count + 16, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltKWPUnwrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet key[], size_t len)
{
	void* state;
	octet* header2;
	// проверить входные данные
	if (count < 32 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count - 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep() + 16);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	header2 = (octet*)state + beltKWP_keep();
	// снять защиту
	beltKWPStart(state, key, len);
	memCopy(header2, src + count - 16, 16);
	memMove(dest, src, count - 16);
	beltKWPStepD2(dest, header2, count, state);
	if (header && !memEq(header, header2, 16) ||
		header == 0 && !memIsZero(header2, 16))
	{
		memSetZero(dest, count - 16);
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
