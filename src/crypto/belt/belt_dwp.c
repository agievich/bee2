/*
*******************************************************************************
\file belt_dwp.c
\brief STB 34.101.31 (belt): DWP (datawrap = data encryption + authentication)
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
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/ww.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Шифрование и имитозащита данных (DWP)

\remark Режим get-then-continue реализован, но пока не рекомендован
(вплоть до завершения оценки надежности).
*******************************************************************************
*/

typedef struct
{
	belt_ctr_st ctr[1];		/*< состояние функций CTR */
	word r[W_OF_B(128)];	/*< переменная r */
	word t[W_OF_B(128)];	/*< переменная t */
	word t1[W_OF_B(128)];	/*< копия t/имитовставка */
	word len[W_OF_B(128)];	/*< обработано открытых || критических данных */
	octet block[16];		/*< блок данных */
	size_t filled;			/*< накоплено октетов в блоке */
	octet stack[];			/*< стек умножения */
} belt_dwp_st;

size_t beltDWP_keep()
{
	return sizeof(belt_dwp_st) + beltPolyMul_deep();
}

void beltDWPStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltDWP_keep()));
	// настроить CTR
	beltCTRStart(st->ctr, key, len, iv);
	// установить r, s
	beltBlockCopy(st->r, st->ctr->ctr);
	beltBlockEncr2((u32*)st->r, st->ctr->key);
#if (OCTET_ORDER == BIG_ENDIAN && B_PER_W != 32)
	beltBlockRevU32(st->r);
	beltBlockRevW(st->r);
#endif
	wwFrom(st->t, beltH(), 16);
	// обнулить счетчики
	memSetZero(st->len, sizeof(st->len));
	st->filled = 0;
}

void beltDWPStepE(void* buf, size_t count, void* state)
{
	beltCTRStepE(buf, count, state);
}

void beltDWPStepI(const void* buf, size_t count, void* state)
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltDWP_keep()));
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

void beltDWPStepA(const void* buf, size_t count, void* state)
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltDWP_keep()));
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

void beltDWPStepD(void* buf, size_t count, void* state)
{
	beltCTRStepD(buf, count, state);
}

static void beltDWPStepG_internal(void* state)
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsValid(state, beltDWP_keep()));
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
	beltBlockEncr((octet*)st->t1, st->ctr->key);
}

void beltDWPStepG(octet mac[8], void* state)
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltDWPStepG_internal(state);
	memCopy(mac, st->t1, 8);
}

bool_t beltDWPStepV(const octet mac[8], void* state)
{
	belt_dwp_st* st = (belt_dwp_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltDWPStepG_internal(state);
	return memEq(mac, st->t1, 8);
}

err_t beltDWPWrap(void* dest, octet mac[8], const void* src1, size_t count1,
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
	state = blobCreate(beltDWP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// установить защиту (I перед E из-за разрешенного пересечения src2 и dest)
	beltDWPStart(state, key, len, iv);
	beltDWPStepI(src2, count2, state);
	memMove(dest, src1, count1);
	beltDWPStepE(dest, count1, state);
	beltDWPStepA(dest, count1, state);
	beltDWPStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltDWPUnwrap(void* dest, const void* src1, size_t count1,
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
	beltDWPStart(state, key, len, iv);
	beltDWPStepI(src2, count2, state);
	beltDWPStepA(src1, count1, state);
	if (!beltDWPStepV(mac, state))
	{
		blobClose(state);
		return ERR_BAD_MAC;
	}
	memMove(dest, src1, count1);
	beltDWPStepD(dest, count1, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
