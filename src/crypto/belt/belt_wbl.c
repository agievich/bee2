/*
*******************************************************************************
\file belt_wbl.c
\brief STB 34.101.31 (belt): wide block encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.11.03
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
Шифрование широкого блока (WBL)

todo: Сокращение числа сложений при count % 16 == 0 (только полные блоки):
сумма r1 + ... + r_{n-1} сохраняется и учитывается при расчете такой же суммы
на следующем такте.
*******************************************************************************
*/

size_t beltWBL_keep()
{
	return sizeof(belt_wbl_st);
}

void beltWBLStart(void* state, const octet key[], size_t len)
{
	belt_wbl_st* s = (belt_wbl_st*)state;
	ASSERT(memIsValid(state, beltWBL_keep()));
	beltKeyExpand2(s->key, key, len);
	s->round = 0;
}

void beltWBLStepR(void* buf, size_t count, void* state)
{
	belt_wbl_st* s = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	do
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
		s->round++;
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &s->round, O_PER_W);
#else // BIG_ENDIAN
		round = wordRev(round);
		memXor2(s->block, &round, O_PER_W);
		round = wordRev(round);
#endif // OCTET_ORDER
		// r*_до_сдвига <- r*_до_сдвига + block
		beltBlockXor2((octet*)buf + count - 32, s->block);
	}
	while (s->round % (2 * n));
}

void beltWBLStepE(void* buf, size_t count, void* state)
{
	belt_wbl_st* s = (belt_wbl_st*)state;
	ASSERT(memIsValid(state, beltWBL_keep()));
	s->round = 0;
	beltWBLStepR(buf, count, state);
}

void beltWBLStepD(void* buf, size_t count, void* state)
{
	belt_wbl_st* s = (belt_wbl_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltWBL_keep()));
	for (s->round = 2 * n; s->round; --s->round)
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
		memXor2(s->block, &s->round, O_PER_W);
#else // BIG_ENDIAN
		s->round = wordRev(s->round);
		memXor2(s->block, &s->round, O_PER_W);
		s->round = wordRev(s->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + count - 16, s->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(buf, (octet*)buf + i);
	}
}
