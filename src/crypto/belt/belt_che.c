/*
*******************************************************************************
\file belt_che.c
\brief STB 34.101.31 (belt): CHE (Ctr-Hash-Encrypt) authenticated encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2020.03.20
\version 2020.03.20
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
*******************************************************************************
*/

typedef struct
{
    u32 key[8];			    /*< форматированный ключ */
    word s[W_OF_B(128)];	/*< переменная s */
    word t[W_OF_B(128)];	/*< переменная t */
    word len[W_OF_B(128)];	/*< обработано открытых || критических данных */
    u32 ctr[4];	            /*< счетчик */
    octet block[16];	    /*< блок данных/гаммы */
    size_t reserved;	    /*< резерв октетов гаммы */
	size_t filled;			/*< накоплено октетов в блоке */
	octet mac[8];			/*< имитовставка для StepV */
	octet stack[];			/*< стек умножения */
} belt_che_st;

size_t beltCHE_keep()
{
	return sizeof(belt_che_st) + beltPolyMul_deep();
}

void beltCHEStart(void* state, const octet key[], size_t len, 
	const octet iv[16])
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCHE_keep()));
    // разобрать key и iv
    beltKeyExpand2(s->key, key, len);
    beltBlockCopy(s->s, iv);
    beltBlockEncr((octet*)s->s, s->key);
    u32From(s->ctr, s->s, 16);
#if (OCTET_ORDER == BIG_ENDIAN)
    beltBlockRevW(s->s);
#endif
    // подготовить t
    wwFrom(s->t, beltH(), 16);
    // обнулить счетчики
    memSetZero(s->len, sizeof(s->len));
    s->reserved = 0;
    s->filled = 0;
}

void beltCHEStepE(void* buf, size_t count, void* state)
{
    belt_che_st* s = (belt_che_st*)state;
    ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
    // есть резерв гаммы?
    if (s->reserved)
    {
        if (s->reserved >= count)
        {
            memXor2(buf, s->block + 16 - s->reserved, count);
            s->reserved -= count;
            return;
        }
        memXor2(buf, s->block + 16 - s->reserved, s->reserved);
        count -= s->reserved;
        buf = (octet*)buf + s->reserved;
        s->reserved = 0;
    }
    // цикл по полным блокам
    while (count >= 16)
    {
        beltBlockMulC(s->ctr), s->ctr[0] ^= 0x00000001;
        beltBlockCopy(s->block, s->ctr);
        beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
        beltBlockRevU32(s->block);
#endif
        beltBlockXor2(buf, s->block);
        buf = (octet*)buf + 16;
        count -= 16;
    }
    // неполный блок?
    if (count)
    {
        beltBlockMulC(s->ctr), s->ctr[0] ^= 0x00000001;
        beltBlockCopy(s->block, s->ctr);
        beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
        beltBlockRevU32(s->block);
#endif
        memXor2(buf, s->block, count);
        s->reserved = 16 - count;
    }
}

void beltCHEStepI(const void* buf, size_t count, void* state)
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
	// критические данные не обрабатывались?
	ASSERT(count == 0 || beltHalfBlockIsZero(s->len + W_OF_B(64)));
	// обновить длину
	beltHalfBlockAddBitSizeW(s->len, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(s->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

void beltCHEStepA(const void* buf, size_t count, void* state)
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCHE_keep()));
	// первый непустой фрагмент критических данных?
	// есть необработанные открытые данные?
	if (count && beltHalfBlockIsZero(s->len + W_OF_B(64)) && s->filled)
	{
		memSetZero(s->block + s->filled, 16 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		s->filled = 0;
	}
	// обновить длину
	beltHalfBlockAddBitSizeW(s->len + W_OF_B(64), count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(s->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

void beltCHEStepD(void* buf, size_t count, void* state)
{
	beltCTRStepD(buf, count, state);
}

static void beltCHEStepG_internal(void* state)
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsValid(state, beltCHE_keep()));
	// есть накопленные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 16 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->t, s->block);
		beltPolyMul(s->t, s->t, s->s, s->stack);
		s->filled = 0;
	}
	// обработать блок длины
	beltBlockXor2(s->t, s->len);
	beltPolyMul(s->t, s->t, s->s, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN && B_PER_W != 32)
	beltBlockRevW(s->t);
	beltBlockRevU32(s->t);
#endif
	beltBlockEncr2((u32*)s->t, s->key);
}

void beltCHEStepG(octet mac[8], void* state)
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltCHEStepG_internal(state);
	u32To(mac, 8, (u32*)s->t);
}

bool_t beltCHEStepV(const octet mac[8], void* state)
{
	belt_che_st* s = (belt_che_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltCHEStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->t[0] = u32Rev(s->t[0]);
	s->t[1] = u32Rev(s->t[1]);
#endif
	return memEq(mac, s->s, 8);
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
