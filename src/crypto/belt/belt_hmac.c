/*
*******************************************************************************
\file belt_hmac.c
\brief STB 34.101.31 (belt): HMAC message authentication
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2019.06.26
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
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(key, len, s, beltHMAC_keep()));
	// key <- key || 0
	if (len <= 32)
	{
		memCopy(s->block, key, len);
		memSetZero(s->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
	}
	// key <- beltHash(key)
	else
	{
		beltBlockSetZero(s->ls_in);
		beltBlockAddBitSizeU32(s->ls_in, len);
		beltBlockSetZero(s->ls_in + 4);
		u32From(s->h_in, beltH(), 32);
		while (len >= 32)
		{
			beltBlockCopy(s->block, key);
			beltBlockCopy(s->block + 16, key + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(s->block);
			beltBlockRevU32(s->block + 16);
#endif
			beltCompr2(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
			key += 32;
			len -= 32;
		}
		if (len)
		{
			memCopy(s->block, key, len);
			memSetZero(s->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(s->block);
			beltBlockRevU32(s->block + 16);
#endif
			beltCompr2(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		}
		beltCompr(s->h_in, s->ls_in, s->stack);
		beltBlockCopy(s->block, s->h_in);
		beltBlockCopy(s->block + 16, s->h_in + 4);
	}
	// сформировать key ^ ipad
	for (len = 0; len < 32; ++len)
		s->block[len] ^= 0x36;
	// начать внутреннее хэширование
	beltBlockSetZero(s->ls_in);
	beltBlockAddBitSizeU32(s->ls_in, 32);
	beltBlockSetZero(s->ls_in + 4);
	u32From(s->h_in, beltH(), 32);
	beltCompr2(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
	s->filled = 0;
	// сформировать key ^ opad [0x36 ^ 0x5C == 0x6A]
	for (; len--; )
		s->block[len] ^= 0x6A;
	// начать внешнее хэширование [будет хэшироваться ровно два блока]
	beltBlockSetZero(s->ls_out);
	beltBlockAddBitSizeU32(s->ls_out, 32 * 2);
	beltBlockSetZero(s->ls_out + 4);
	u32From(s->h_out, beltH(), 32);
	beltCompr2(s->ls_out + 4, s->h_out, (u32*)s->block, s->stack);
}

void beltHMACStepA(const void* buf, size_t count, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, beltHMAC_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(s->ls_in, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 32 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 32 - s->filled);
		count -= 32 - s->filled;
		buf = (const octet*)buf + 32 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltCompr2(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(s->block, buf);
		beltBlockCopy(s->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltCompr2(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

static void beltHMACStepG_internal(void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	// pre
	ASSERT(memIsValid(s, beltHash_keep()));
	// создать копии второй части s->ls_in и s->h_in
	beltBlockCopy(s->s1, s->ls_in + 4);
	beltBlockCopy(s->h1_in, s->h_in);
	beltBlockCopy(s->h1_in + 4, s->h_in + 4);
	// есть необработанные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 32 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltCompr2(s->ls_in + 4, s->h1_in, (u32*)s->block, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block + 16);
		beltBlockRevU32(s->block);
#endif
	}
	// последний блок внутреннего хэширования
	beltCompr(s->h1_in, s->ls_in, s->stack);
	// восстановить сохраненную часть s->ls_in
	beltBlockCopy(s->ls_in + 4, s->s1);
	// создать копии второй части s->ls_out и s->h_out
	beltBlockCopy(s->s1, s->ls_out + 4);
	beltBlockCopy(s->h1_out, s->h_out);
	beltBlockCopy(s->h1_out + 4, s->h_out + 4);
	// обработать блок s->h1_in
	beltCompr2(s->ls_out + 4, s->h1_out, s->h1_in, s->stack);
	// последний блок внешнего хэширования
	beltCompr(s->h1_out, s->ls_out, s->stack);
	// восстановить сохраненную часть s->ls_out
	beltBlockCopy(s->ls_out + 4, s->s1);
}

void beltHMACStepG(octet mac[32], void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
	u32To(mac, 32, s->h1_out);
}

void beltHMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
	u32To(mac, mac_len, s->h1_out);
}

bool_t beltHMACStepV(const octet mac[32], void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1_out);
	beltBlockRevU32(s->h1_out + 4);
#endif
	return memEq(mac, s->h1_out, 32);
}

bool_t beltHMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1_out);
	beltBlockRevU32(s->h1_out + 4);
#endif
	return memEq(mac, s->h1_out, mac_len);
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
