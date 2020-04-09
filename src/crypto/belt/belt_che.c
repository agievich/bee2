/*
*******************************************************************************
\file belt_che.c
\brief STB 34.101.31 (belt): CHE (Ctr-Hash-Encrypt) authenticated encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2020.03.20
\version 2020.04.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/ww.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Аутентифицированное шифрование данных (CHE)

\remark Режим get-then-continue реализован, но пока не рекомендован
(вплоть до завершения оценки надежности).
*******************************************************************************
*/

typedef struct
{
	u32 key[8];				/*< форматированный ключ */
	u32 s[4];				/*< переменная s */
	word r[W_OF_B(128)];	/*< переменная r */
	word t[W_OF_B(128)];	/*< переменная t */
	word t1[W_OF_B(128)];	/*< копия t/имитовставка */
	word len[W_OF_B(128)];	/*< обработано открытых || критических данных */
	octet block[16];		/*< блок аутентифицируемых данных */
	octet block1[16];		/*< блок гаммы */
	size_t filled;			/*< накоплено октетов в block */
	size_t reserved;		/*< резерв октетов гаммы */
	octet stack[];			/*< стек умножения */
} belt_che_st;

size_t beltCHE_keep()
{
	return sizeof(belt_che_st) + beltPolyMul_deep();
}

void beltCHEStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCHE_keep()));
	// разобрать key и iv
	beltKeyExpand2(st->key, key, len);
	beltBlockCopy(st->r, iv);
	beltBlockEncr((octet*)st->r, st->key);
	u32From(st->s, st->r, 16);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevW(st->r);
#endif
	// подготовить t
	wwFrom(st->t, beltH(), 16);
	// обнулить счетчики
	memSetZero(st->len, sizeof(st->len));
	st->reserved = 0;
	st->filled = 0;
}

void beltCHEStepE(void* buf, size_t count, void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
	// есть резерв гаммы?
	if (st->reserved)
	{
		if (st->reserved >= count)
		{
			memXor2(buf, st->block1 + 16 - st->reserved, count);
			st->reserved -= count;
			return;
		}
		memXor2(buf, st->block1 + 16 - st->reserved, st->reserved);
		count -= st->reserved;
		buf = (octet*)buf + st->reserved;
		st->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockMulC(st->s), st->s[0] ^= 0x00000001;
		beltBlockCopy(st->block1, st->s);
		beltBlockEncr2((u32*)st->block1, st->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block1);
#endif
		beltBlockXor2(buf, st->block1);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockMulC(st->s), st->s[0] ^= 0x00000001;
		beltBlockCopy(st->block1, st->s);
		beltBlockEncr2((u32*)st->block1, st->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block1);
#endif
		memXor2(buf, st->block1, count);
		st->reserved = 16 - count;
	}
}

void beltCHEStepI(const void* buf, size_t count, void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
	// критические данные не обрабатывались?
	ASSERT(count == 0 || beltHalfBlockIsZero(st->len + W_OF_B(64)));
	// обновить длину
	beltHalfBlockAddBitSizeW(st->len, count);
	// есть накопленные данные?
	if (st->filled)
	{
		if (count < 16 - st->filled)
		{
			memCopy(st->block + st->filled, buf, count);
			st->filled += count;
			return;
		}
		memCopy(st->block + st->filled, buf, 16 - st->filled);
		count -= 16 - st->filled;
		buf = (const octet*)buf + 16 - st->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(st->block);
#endif
		beltBlockXor2(st->t, st->block);
		beltPolyMul(st->t, st->t, st->r, st->stack);
		st->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(st->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(st->block);
#endif
		beltBlockXor2(st->t, st->block);
		beltPolyMul(st->t, st->t, st->r, st->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(st->block, buf, st->filled = count);
}

void beltCHEStepA(const void* buf, size_t count, void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
	// первый непустой фрагмент критических данных?
	// есть необработанные открытые данные?
	if (count && beltHalfBlockIsZero(st->len + W_OF_B(64)) && st->filled)
	{
		memSetZero(st->block + st->filled, 16 - st->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(st->block);
#endif
		beltBlockXor2(st->t, st->block);
		beltPolyMul(st->t, st->t, st->r, st->stack);
		st->filled = 0;
	}
	// обновить длину
	beltHalfBlockAddBitSizeW(st->len + W_OF_B(64), count);
	// есть накопленные данные?
	if (st->filled)
	{
		if (count < 16 - st->filled)
		{
			memCopy(st->block + st->filled, buf, count);
			st->filled += count;
			return;
		}
		memCopy(st->block + st->filled, buf, 16 - st->filled);
		count -= 16 - st->filled;
		buf = (const octet*)buf + 16 - st->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(st->block);
#endif
		beltBlockXor2(st->t, st->block);
		beltPolyMul(st->t, st->t, st->r, st->stack);
		st->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(st->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(st->block);
#endif
		beltBlockXor2(st->t, st->block);
		beltPolyMul(st->t, st->t, st->r, st->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(st->block, buf, st->filled = count);
}

void beltCHEStepD(void* buf, size_t count, void* state)
{
	beltCHEStepE(buf, count, state);
}

static void beltCHEStepG_internal(void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsValid(state, beltCHE_keep()));
	// создать копию t и завершить обработку данных
	if (st->filled)
	{
		memSetZero(st->block + st->filled, 16 - st->filled);
		wwFrom(st->t1, st->block, 16);
		beltBlockXor2(st->t1, st->t);
		beltPolyMul(st->t1, st->t1, st->r, st->stack);
	}
	else
		memCopy(st->t1, st->t, 16);
	// обработать блок длины
	beltBlockXor2(st->t1, st->len);
	beltPolyMul(st->t1, st->t1, st->r, st->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevW(st->t1);
#endif
	beltBlockEncr((octet*)st->t1, st->key);
}

void beltCHEStepG(octet mac[8], void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltCHEStepG_internal(state);
	memCopy(mac, st->t1, 8);
}

bool_t beltCHEStepV(const octet mac[8], void* state)
{
	belt_che_st* st = (belt_che_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltCHEStepG_internal(state);
	return memEq(mac, st->t1, 8);
}

err_t beltCHEWrap(void* dest, octet mac[8], const void* src1, size_t count1,
	const void* src2, size_t count2, const octet key[], size_t len,
	const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src1, count1) ||
		!memIsValid(src2, count2) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count1) ||
		!memIsValid(mac, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCHE_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// установить защиту (I перед E из-за разрешенного пересечения src2 и dest)
	beltCHEStart(state, key, len, iv);
	beltCHEStepI(src2, count2, state);
	memMove(dest, src1, count1);
	beltCHEStepE(dest, count1, state);
	beltCHEStepA(dest, count1, state);
	beltCHEStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltCHEUnwrap(void* dest, const void* src1, size_t count1,
	const void* src2, size_t count2, const octet mac[8], const octet key[],
	size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src1, count1) ||
		!memIsValid(src2, count2) ||
		!memIsValid(mac, 8) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count1))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltDWP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// снять защиту
	beltCHEStart(state, key, len, iv);
	beltCHEStepI(src2, count2, state);
	beltCHEStepA(src1, count1, state);
	if (!beltCHEStepV(mac, state))
	{
		blobClose(state);
		return ERR_BAD_MAC;
	}
	memMove(dest, src1, count1);
	beltCHEStepD(dest, count1, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
