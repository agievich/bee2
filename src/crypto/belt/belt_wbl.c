/*
*******************************************************************************
\file belt_wbl.c
\brief STB 34.101.31 (belt): wide block encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.11.03
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
Шифрование широкого блока (WBL)

\remark Внутренняя реализация представлена бвзовыми (Base) и оптимизированными 
(Opt) функциями. Оптимизация включается, когда обрабатываемый широкий блок 
состоит из целого числа 128-битовых блоков и число блоков n не меньше 4 при 
зашифровании и не меньше 5 при расшифровании.

\remark Суть оптимизации:
- в beltWBLStepEOpt() сумма sum = r1 + ... + r_{n-1} сохраняется и учитывается 
  при расчете такой же суммы на следующем такте (требуется 2 сложения 
  128-битовых блоков вместо n - 2);
- в beltWBLStepD2() сумма sum = r2 + ... + r_{n-1} сохраняется и учитывается 
  при расчете такой же суммы на следующем такте (требуется 2 сложения блоков 
  вместо n - 3).
*******************************************************************************
*/

size_t beltWBL_keep()
{
	return sizeof(belt_wbl_st);
}

void beltWBLStart(void* state, const octet key[], size_t len)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	ASSERT(memIsValid(state, beltWBL_keep()));
	beltKeyExpand2(st->key, key, len);
	st->round = 0;
}

void beltWBLStepEBase(void* buf, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	ASSERT(st->round % (2 * n) == 0);
	do
	{
		size_t i;
		// block <- r1 + ... + r_{n-1}
		beltBlockCopy(st->block, buf);
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(st->block, (octet*)buf + i);
		// r <- ShLo^128(r)
		memMove(buf, (octet*)buf + 16, count - 16);
		// r* <- block
		beltBlockCopy((octet*)buf + count - 16, st->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(st->block, st->key);
		st->round++;
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(st->block, &st->round, O_PER_W);
#else // BIG_ENDIAN
		st->round = wordRev(st->round);
		memXor2(st->block, &st->round, O_PER_W);
		st->round = wordRev(st->round);
#endif // OCTET_ORDER
		// r*_до_сдвига <- r*_до_сдвига + block
		beltBlockXor2((octet*)buf + count - 32, st->block);
	}
	while (st->round % (2 * n));
}

void beltWBLStepEOpt(void* buf, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	size_t i;
	ASSERT(count >= 32 && count % 16 == 0);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	// sum <- r1 + ... + r_{n-1}
	beltBlockCopy(st->sum, buf);
	for (i = 16; i + 16 < count; i += 16)
		beltBlockXor2(st->sum, (octet*)buf + i);
	// 2 * n итераций 
	ASSERT(st->round % (2 * n) == 0);
	// sum будет записываться по смещению i: 
	// это блок r1 в начале такта и блок r* в конце)
	i = 0; 
	do
	{
		// block <- beltBlockEncr(sum) + <round>
		beltBlockCopy(st->block, st->sum);
		beltBlockEncr(st->block, st->key);
		st->round++;
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(st->block, &st->round, O_PER_W);
#else // BIG_ENDIAN
		st->round = wordRev(st->round);
		memXor2(st->block, &st->round, O_PER_W);
		st->round = wordRev(st->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + (i + count - 16) % count, st->block);
		// запомнить sum
		beltBlockCopy(st->block, st->sum);
		// пересчитать sum: добавить новое слагаемое
		beltBlockXor2(st->sum, (octet*)buf + (i + count - 16) % count);
		// пересчитать sum: исключить старое слагаемое
		beltBlockXor2(st->sum, (octet*)buf + i);
		// сохранить sum
		beltBlockCopy((octet*)buf + i, st->block);
		// вперед
		i = (i + 16) % count;
	}
	while (st->round % (2 * n));
}

void beltWBLStepDBase(void* buf, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	for (st->round = 2 * n; st->round; --st->round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(st->block, (octet*)buf + count - 16);
		// r <- ShHi^128(r)
		memMove((octet*)buf + 16, buf, count - 16);
		// r1 <- block
		beltBlockCopy(buf, st->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(st->block, st->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(st->block, &st->round, O_PER_W);
#else // BIG_ENDIAN
		st->round = wordRev(st->round);
		memXor2(st->block, &st->round, O_PER_W);
		st->round = wordRev(st->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + count - 16, st->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(buf, (octet*)buf + i);
	}
}

void beltWBLStepDOpt(void* buf, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	size_t i;
	ASSERT(count >= 32 && count % 16 == 0);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	// sum <- r1 + ... + r_{n-2} (будущая сумма r2 + ... + r_{n-1})
	beltBlockCopy(st->sum, (octet*)buf);
	for (i = 16; i + 32 < count; i += 16)
		beltBlockXor2(st->sum, (octet*)buf + i);
	// 2 * n итераций (sum будет записываться по смещению i: 
	// это блок r* в начале такта и блок r1 в конце)
	for (st->round = 2 * n, i = count - 16; st->round; --st->round)
	{
		// block <- beltBlockEncr(r*) + <round>
		beltBlockCopy(st->block, (octet*)buf + i);
		beltBlockEncr(st->block, st->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(st->block, &st->round, O_PER_W);
#else // BIG_ENDIAN
		st->round = wordRev(st->round);
		memXor2(st->block, &st->round, O_PER_W);
		st->round = wordRev(st->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + (i + count - 16) % count, st->block);
		// r1 <- pre r* + sum
		beltBlockXor2((octet*)buf + i, st->sum);
		// пересчитать sum: исключить старое слагаемое
		beltBlockXor2(st->sum, (octet*)buf + (i + count - 32) % count);
		// пересчитать sum: добавить новое слагаемое
		beltBlockXor2(st->sum, (octet*)buf + i);
		// назад
		i = (i + count - 16) % count;
	}
}

void beltWBLStepE(void* buf, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	ASSERT(memIsValid(state, beltWBL_keep()));
	st->round = 0;
	(count % 16 || count < 64) ? 
		beltWBLStepEBase(buf, count, state) :
		beltWBLStepEOpt(buf, count, state);
}

void beltWBLStepD(void* buf, size_t count, void* state)
{
	(count % 16 || count < 80) ? 
		beltWBLStepDBase(buf, count, state) :
		beltWBLStepDOpt(buf, count, state);
}

void beltWBLStepD2(void* buf1, void* buf2, size_t count, void* state)
{
	belt_wbl_st* st = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	// pre
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint3(buf1, count - 16, buf2, 16, state, beltWBL_keep()));
	for (st->round = 2 * n; st->round; --st->round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(st->block, buf2);
		// r <- ShHi^128(r)
		memCopy(buf2, (octet*)buf1 + count - 32, 16);
		memMove((octet*)buf1 + 16, buf1, count - 32);
		// r1 <- block
		beltBlockCopy(buf1, st->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(st->block, st->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(st->block, &st->round, O_PER_W);
#else // BIG_ENDIAN
		st->round = wordRev(st->round);
		memXor2(st->block, &st->round, O_PER_W);
		st->round = wordRev(st->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2(buf2, st->block);
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

void beltWBLStepR(void* buf, size_t count, void* state)
{
	(count % 16 || count < 64) ? 
		beltWBLStepEBase(buf, count, state) :
		beltWBLStepEOpt(buf, count, state);
}
