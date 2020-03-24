/*
*******************************************************************************
\file belt_hmac.c
\brief STB 34.101.31 (belt): HMAC message authentication
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
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Ключезависимое хэширование (HMAC)
*******************************************************************************
*/
typedef struct
{
	u32 ls_in[8];		/*< блок [4]len || [4]s внутреннего хэширования */
	u32 h_in[8];		/*< переменная h внутреннего хэширования */
	u32 h1_in[8];		/*< копия переменной h внутреннего хэширования */
	u32 ls_out[8];		/*< блок [4]len || [4]s внешнего хэширования */
	u32 h_out[8];		/*< переменная h внешнего хэширования */
	u32 h1_out[8];		/*< копия переменной h внешнего хэширования */
	u32 s1[4];			/*< копия переменной s */
	octet block[32];	/*< блок данных */
	size_t filled;		/*< накоплено октетов в блоке */
	octet stack[];		/*< [beltCompr_deep()] стек beltCompr */
} belt_hmac_st;

size_t beltHMAC_keep()
{
	return sizeof(belt_hmac_st) + beltCompr_deep();
}

void beltHMACStart(void* state, const octet key[], size_t len)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(key, len, state, beltHMAC_keep()));
	// key <- key || 0
	if (len <= 32)
	{
		memCopy(st->block, key, len);
		memSetZero(st->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
	}
	// key <- beltHash(key)
	else
	{
		beltBlockSetZero(st->ls_in);
		beltBlockAddBitSizeU32(st->ls_in, len);
		beltBlockSetZero(st->ls_in + 4);
		u32From(st->h_in, beltH(), 32);
		while (len >= 32)
		{
			beltBlockCopy(st->block, key);
			beltBlockCopy(st->block + 16, key + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(st->block);
			beltBlockRevU32(st->block + 16);
#endif
			beltCompr2(st->ls_in + 4, st->h_in, (u32*)st->block, st->stack);
			key += 32;
			len -= 32;
		}
		if (len)
		{
			memCopy(st->block, key, len);
			memSetZero(st->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(st->block);
			beltBlockRevU32(st->block + 16);
#endif
			beltCompr2(st->ls_in + 4, st->h_in, (u32*)st->block, st->stack);
		}
		beltCompr(st->h_in, st->ls_in, st->stack);
		beltBlockCopy(st->block, st->h_in);
		beltBlockCopy(st->block + 16, st->h_in + 4);
	}
	// сформировать key ^ ipad
	for (len = 0; len < 32; ++len)
		st->block[len] ^= 0x36;
	// начать внутреннее хэширование
	beltBlockSetZero(st->ls_in);
	beltBlockAddBitSizeU32(st->ls_in, 32);
	beltBlockSetZero(st->ls_in + 4);
	u32From(st->h_in, beltH(), 32);
	beltCompr2(st->ls_in + 4, st->h_in, (u32*)st->block, st->stack);
	st->filled = 0;
	// сформировать key ^ opad [0x36 ^ 0x5C == 0x6A]
	for (; len--; )
		st->block[len] ^= 0x6A;
	// начать внешнее хэширование [будет хэшироваться ровно два блока]
	beltBlockSetZero(st->ls_out);
	beltBlockAddBitSizeU32(st->ls_out, 32 * 2);
	beltBlockSetZero(st->ls_out + 4);
	u32From(st->h_out, beltH(), 32);
	beltCompr2(st->ls_out + 4, st->h_out, (u32*)st->block, st->stack);
}

void beltHMACStepA(const void* buf, size_t count, void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltHMAC_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(st->ls_in, count);
	// есть накопленные данные?
	if (st->filled)
	{
		if (count < 32 - st->filled)
		{
			memCopy(st->block + st->filled, buf, count);
			st->filled += count;
			return;
		}
		memCopy(st->block + st->filled, buf, 32 - st->filled);
		count -= 32 - st->filled;
		buf = (const octet*)buf + 32 - st->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls_in + 4, st->h_in, (u32*)st->block, st->stack);
		st->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(st->block, buf);
		beltBlockCopy(st->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls_in + 4, st->h_in, (u32*)st->block, st->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(st->block, buf, st->filled = count);
}

static void beltHMACStepG_internal(void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	// pre
	ASSERT(memIsValid(state, beltHash_keep()));
	// создать копии второй части st->ls_in и st->h_in
	beltBlockCopy(st->s1, st->ls_in + 4);
	beltBlockCopy(st->h1_in, st->h_in);
	beltBlockCopy(st->h1_in + 4, st->h_in + 4);
	// есть необработанные данные?
	if (st->filled)
	{
		memSetZero(st->block + st->filled, 32 - st->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
		beltBlockRevU32(st->block + 16);
#endif
		beltCompr2(st->ls_in + 4, st->h1_in, (u32*)st->block, st->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block + 16);
		beltBlockRevU32(st->block);
#endif
	}
	// последний блок внутреннего хэширования
	beltCompr(st->h1_in, st->ls_in, st->stack);
	// восстановить сохраненную часть st->ls_in
	beltBlockCopy(st->ls_in + 4, st->s1);
	// создать копии второй части st->ls_out и st->h_out
	beltBlockCopy(st->s1, st->ls_out + 4);
	beltBlockCopy(st->h1_out, st->h_out);
	beltBlockCopy(st->h1_out + 4, st->h_out + 4);
	// обработать блок st->h1_in
	beltCompr2(st->ls_out + 4, st->h1_out, st->h1_in, st->stack);
	// последний блок внешнего хэширования
	beltCompr(st->h1_out, st->ls_out, st->stack);
	// восстановить сохраненную часть st->ls_out
	beltBlockCopy(st->ls_out + 4, st->s1);
}

void beltHMACStepG(octet mac[32], void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
	u32To(mac, 32, st->h1_out);
}

void beltHMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
	u32To(mac, mac_len, st->h1_out);
}

bool_t beltHMACStepV(const octet mac[32], void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(st->h1_out);
	beltBlockRevU32(st->h1_out + 4);
#endif
	return memEq(mac, st->h1_out, 32);
}

bool_t beltHMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* st = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(st->h1_out);
	beltBlockRevU32(st->h1_out + 4);
#endif
	return memEq(mac, st->h1_out, mac_len);
}

err_t beltHMAC(octet mac[32], const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(mac, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHMAC_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// выработать имитовставку
	beltHMACStart(state, key, len);
	beltHMACStepA(src, count, state);
	beltHMACStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
